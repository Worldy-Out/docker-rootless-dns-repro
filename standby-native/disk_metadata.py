"""Exact private Docker disk snapshots and one version-pinned audit exception.

This does not change metadata or normalize a stored baseline. Callers retain the
full before/after snapshots privately; only fingerprints and the explicit delta
belong in public evidence. A raw FAIL remains a raw FAIL.
"""
import copy
import hashlib
import json
import re
import stat
from pathlib import Path

DNS_FIELDS = ('Dns', 'DnsOptions', 'DnsSearch')
SOURCE = 'https://github.com/moby/moby/blob/docker-v29.1.3/daemon/container/container.go#L619-L633'


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(value):
    # Preserve the existing read-host.py specSha256 serialization exactly.
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def snapshot(config, hostconfig, mountpoints):
    require(all(isinstance(v, dict) for v in [config, hostconfig, mountpoints]), 'Full Config/HostConfig/MountPoints required')
    require(bool(config) and bool(hostconfig), 'Empty Config/HostConfig is not full evidence')
    spec = copy.deepcopy({'config': config, 'hostconfig': hostconfig, 'mountpoints': mountpoints})
    return {'schema': 1, 'kind': 'PRIVATE_FULL_DOCKER_DISK_SPEC', 'spec': spec,
            'specSha256': digest(spec), 'componentSha256': {k: digest(v) for k, v in spec.items()}}


def checked(value):
    require(isinstance(value, dict) and set(value) == {'schema', 'kind', 'spec', 'specSha256', 'componentSha256'}, 'Full private snapshot required')
    require(value['schema'] == 1 and value['kind'] == 'PRIVATE_FULL_DOCKER_DISK_SPEC', 'Unknown disk snapshot schema')
    spec = value['spec']
    require(isinstance(spec, dict) and set(spec) == {'config', 'hostconfig', 'mountpoints'}, 'Incomplete raw disk components')
    expected = snapshot(spec['config'], spec['hostconfig'], spec['mountpoints'])
    require(value == expected, 'Disk snapshot fingerprints do not match full evidence')
    return spec


def fingerprints(value):
    checked(value)
    return {'specSha256': value['specSha256'], 'componentSha256': copy.deepcopy(value['componentSha256'])}


def read_snapshot(directory, uid):
    directory = Path(directory)
    require(directory.is_dir() and all(not p.is_symlink() for p in [directory, *directory.parents]), 'Unsafe container metadata path')
    values = []
    for name in ['config.v2.json', 'hostconfig.json']:
        path = directory / name
        meta = path.lstat()
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == uid and meta.st_nlink == 1 and stat.S_IMODE(meta.st_mode) == 0o600, 'Unsafe private Docker metadata file')
        values.append(json.loads(path.read_text()))
    config, hostconfig = values
    require(config['ID'] == directory.name and not any(config['State'].get(k) for k in ['Running', 'Paused', 'Restarting', 'Pid']), 'Disk snapshot requires this stopped container')
    return snapshot(config['Config'], hostconfig, config['MountPoints'])


def audit(before, after, engine_version):
    old, new = checked(before), checked(after)
    require(engine_version == '29.1.3', 'DNS transition is proved only for Docker 29.1.3')
    receipt = {'schema': 1, 'engineVersion': engine_version, 'fullPrivateBeforeAndAfterVerified': True,
               'before': fingerprints(before), 'after': fingerprints(after), 'rawEqual': old == new,
               'diskMutatedByAudit': False, 'baselineRewritten': False, 'changedPaths': [],
               'hostConfigBefore': copy.deepcopy(old['hostconfig']), 'hostConfigAfter': copy.deepcopy(new['hostconfig'])}
    if old == new:
        return receipt | {'status': 'PASS_EXACT_DISK_SPEC'}
    require(old['config'] == new['config'], 'Docker Config changed')
    require(old['mountpoints'] == new['mountpoints'], 'Docker MountPoints changed')
    require(all(k in old['hostconfig'] and old['hostconfig'][k] is None for k in DNS_FIELDS), 'Before must contain all three explicit null DNS fields')
    require(all(k in new['hostconfig'] and type(new['hostconfig'][k]) is list and new['hostconfig'][k] == [] for k in DNS_FIELDS), 'After must contain all three empty DNS lists')
    target = copy.deepcopy(old['hostconfig'])
    for key in DNS_FIELDS:
        target[key] = []
    require(target == new['hostconfig'], 'Other HostConfig fields changed; DNS exception forbidden')
    return receipt | {'status': 'PASS_CONFIRMED_DOCKER_29_1_3_DNS_DEFAULTS',
                      'changedPaths': ['HostConfig/' + k for k in DNS_FIELDS],
                      'priorValue': None, 'currentValue': [], 'source': SOURCE}


def capture_inventory(rows, data_root, uid):
    """Capture private full specs before Engine starts, linked to fresh read-host."""
    require(isinstance(rows, list) and all(isinstance(r, dict) and re.fullmatch(r'[a-f0-9]{64}', r.get('id', '')) for r in rows), 'Invalid disk inventory identities')
    ids = [r['id'] for r in rows]
    require(len(set(ids)) == len(ids), 'Duplicate disk container identity')
    directory = Path(data_root) / 'containers'
    require(directory.is_dir() and not directory.is_symlink(), 'Missing private Docker container directory')
    present = {p.parent.name for p in directory.glob('*/config.v2.json')}
    require(present == set(ids), 'Full disk container inventory differs')
    captured = {}
    for row in rows:
        value = read_snapshot(directory / row['id'], uid)
        require(value['specSha256'] == row['specSha256'], 'Captured disk spec differs from fresh host receipt')
        captured[row['id']] = value
    return {'schema': 1, 'containers': captured}


def audit_inventory(before, after, engine_version):
    for value in [before, after]:
        require(isinstance(value, dict) and set(value) == {'schema', 'containers'} and value['schema'] == 1 and isinstance(value['containers'], dict), 'Full private inventory snapshots required')
    require(set(before['containers']) == set(after['containers']), 'Private disk container IDs changed')
    return {'schema': 1, 'engineVersion': engine_version, 'containers': {
        cid: audit(old, after['containers'][cid], engine_version) for cid, old in before['containers'].items()}}


def validate_receipt(receipt, before_hash, after_hash):
    """Check a fresh final-read audit; never accept an unlinked boolean waiver."""
    base = {'schema', 'engineVersion', 'fullPrivateBeforeAndAfterVerified', 'before', 'after', 'rawEqual',
            'diskMutatedByAudit', 'baselineRewritten', 'changedPaths', 'hostConfigBefore', 'hostConfigAfter', 'status'}
    require(isinstance(receipt, dict), 'Disk audit receipt missing')
    exact = receipt.get('status') == 'PASS_EXACT_DISK_SPEC'
    require(set(receipt) == base if exact else set(receipt) == base | {'priorValue', 'currentValue', 'source'}, 'Incomplete/unknown disk audit receipt fields')
    require(receipt['schema'] == 1 and receipt['engineVersion'] == '29.1.3' and receipt['fullPrivateBeforeAndAfterVerified'] is True, 'Unproved disk audit provenance')
    require(receipt['diskMutatedByAudit'] is False and receipt['baselineRewritten'] is False, 'Audit changed or replaced original evidence')
    for side, expected_hash in [('before', before_hash), ('after', after_hash)]:
        value = receipt[side]
        require(set(value) == {'specSha256', 'componentSha256'} and value['specSha256'] == expected_hash and re.fullmatch(r'[a-f0-9]{64}', expected_hash), 'Disk audit raw hash not linked to host inventory')
        require(set(value['componentSha256']) == {'config', 'hostconfig', 'mountpoints'} and all(re.fullmatch(r'[a-f0-9]{64}', h) for h in value['componentSha256'].values()), 'Missing component hashes')
        host = receipt['hostConfigBefore' if side == 'before' else 'hostConfigAfter']
        require(isinstance(host, dict) and digest(host) == value['componentSha256']['hostconfig'], 'HostConfig proof/hash mismatch')
    old, new = receipt['hostConfigBefore'], receipt['hostConfigAfter']
    if exact:
        require(receipt['rawEqual'] is True and before_hash == after_hash and receipt['before'] == receipt['after'] and old == new and receipt['changedPaths'] == [], 'Exact disk audit has a delta')
        return
    require(receipt['status'] == 'PASS_CONFIRMED_DOCKER_29_1_3_DNS_DEFAULTS' and receipt['rawEqual'] is False and before_hash != after_hash, 'Unknown metadata transition')
    require(receipt['changedPaths'] == ['HostConfig/' + k for k in DNS_FIELDS] and receipt['priorValue'] is None and receipt['currentValue'] == [] and receipt['source'] == SOURCE, 'Unknown metadata exception')
    require(all(k in old and old[k] is None and k in new and type(new[k]) is list and new[k] == [] for k in DNS_FIELDS), 'DNS transition proof differs')
    target = copy.deepcopy(old)
    for key in DNS_FIELDS: target[key] = []
    require(target == new, 'Additional HostConfig drift')
    require(all(receipt['before']['componentSha256'][k] == receipt['after']['componentSha256'][k] for k in ['config', 'mountpoints']), 'Config/MountPoints component drift')


def verify_inventory_rows(before, after, receipt):
    require(isinstance(receipt, dict) and set(receipt) == {'schema', 'engineVersion', 'containers'} and receipt['schema'] == 1 and receipt['engineVersion'] == '29.1.3', 'Full final disk audit required')
    require(isinstance(before, list) and isinstance(after, list) and all(isinstance(r, dict) and isinstance(r.get('id'), str) and isinstance(r.get('specSha256'), str) for r in before + after), 'Incomplete final container metadata')
    require(len({r['id'] for r in before}) == len(before) and len({r['id'] for r in after}) == len(after), 'Duplicate final container ID')
    require(len(before) == len(after) and [r['id'] for r in before] == [r['id'] for r in after], 'Container inventory identity/order drift')
    require(set(receipt['containers']) == {r['id'] for r in before}, 'Disk audit does not cover exactly the original containers')
    deltas = []
    for old, new in zip(before, after):
        cid = old['id']
        require(set(old) == set(new), 'Container metadata fields changed')
        require({k: v for k, v in old.items() if k != 'specSha256'} == {k: v for k, v in new.items() if k != 'specSha256'}, 'Container metadata/attachments drift outside disk fingerprint')
        item = receipt['containers'][cid]
        validate_receipt(item, old['specSha256'], new['specSha256'])
        if not item['rawEqual']: deltas.append({'containerId': cid, 'rawEqual': False, 'changedPaths': item['changedPaths'], 'beforeSpecSha256': old['specSha256'], 'afterSpecSha256': new['specSha256']})
    return {'rawEqual': not deltas, 'confirmedDnsDefaultTransitions': deltas, 'allOtherInventoryAndAttachmentsExact': True}
