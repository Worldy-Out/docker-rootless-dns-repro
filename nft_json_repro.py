#!/usr/bin/env python3
"""Independent synthetic nft JSON shape probe; never uses a host ruleset."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

TABLE = 'synthetic_json_probe'
MARKER = 'synthetic named and anonymous JSON sets'
LEASE = '192.0.2.55'
TIMEOUT = 2
PORTS = [18880, 18881, 18882]
RULES = f'''table inet {TABLE} {{
 comment "{MARKER}"
 set lease_sources {{ type ipv4_addr; flags timeout; timeout {TIMEOUT}s; }}
 chain observations {{
  ip saddr @lease_sources tcp dport {{ 18880, 18881, 18882 }} counter accept
  udp dport {{ 18880, 18881 }} drop
  limit rate 1 mbytes/second counter accept
 }}
}}
'''


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def run(argv, *, data=None, timeout=10):
    # nft is a fixed native leaf, without shell/includes/exec helpers. Keep it
    # in the namespace controller's group so the outer deadline kills all of
    # that group's processes, not merely the Python parent.
    grouped = argv[0] == '/usr/bin/unshare'
    process = subprocess.Popen(argv, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=grouped,
                               env={**os.environ, 'LC_ALL': 'C', 'LANG': 'C'})
    try:
        out, err = process.communicate(data, timeout=timeout)
    except BaseException:
        try:
            if grouped:
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass
        process.communicate(timeout=5)
        raise
    require(len(out) <= 262144 and len(err) <= 4096, 'Synthetic command output exceeded bound')
    require(process.returncode == 0, 'Fixed command failed: ' + Path(argv[0]).name + '; exit=' +
            str(process.returncode) + '; stderr=' + err.decode('utf-8', errors='replace')[:1024])
    return out


def namespace_identity(pid='self'):
    value = Path('/proc', str(pid), 'ns/net').stat()
    return [value.st_dev, value.st_ino]


def require_runner():
    require(os.geteuid() == 0 and os.environ.get('CI') == 'true' and
            os.environ.get('GITHUB_ACTIONS') == 'true' and
            os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted' and
            os.environ.get('RUN_NFT_JSON_REPRO') == 'yes', 'Only an explicitly enabled disposable hosted runner')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(release.get('ID') == 'ubuntu' and release.get('VERSION_ID', '').strip('"') == '26.04' and
            Path('/proc/1/comm').read_text().strip() == 'systemd', 'Ubuntu 26.04 hosted systemd runner required')
    version = run(['/usr/sbin/nft', '--version']).decode().strip()
    require(version.startswith('nftables v1.1.6 '), 'This experiment is pinned to nftables 1.1.6')
    return {'nft': version, 'kernel': os.uname().release, 'python': sys.version.split()[0], 'ubuntu': '26.04'}


def json_ruleset():
    raw = run(['/usr/sbin/nft', '-j', 'list', 'ruleset'])
    return raw, json.loads(raw)


def validate_snapshot(value):
    """Named declarations occur only as rows; nested set expressions stay intact."""
    require(isinstance(value, dict) and set(value) == {'nftables'} and
            isinstance(value['nftables'], list), 'Incomplete ruleset')
    objects = value['nftables']
    require(all(isinstance(row, dict) and len(row) == 1 and
                next(iter(row)) in ('metainfo', 'table', 'set', 'chain', 'rule') for row in objects),
            'Unexpected top-level ruleset object')
    tables = [row['table'] for row in objects if 'table' in row]
    sets = [row['set'] for row in objects if 'set' in row]
    chains = [row['chain'] for row in objects if 'chain' in row]
    rules = [row['rule'] for row in objects if 'rule' in row]
    require(len(tables) == len(sets) == len(chains) == 1 and len(rules) == 3,
            'Synthetic declaration count changed')
    table, named, chain = tables[0], sets[0], chains[0]
    require(isinstance(table, dict) and table.get('family') == 'inet' and
            table.get('name') == TABLE and table.get('comment') == MARKER and
            type(table.get('handle')) is int and table['handle'] > 0, 'Foreign table or invalid handle')
    require(isinstance(named, dict) and named.get('family') == 'inet' and named.get('table') == TABLE and
            named.get('name') == 'lease_sources' and named.get('type') == 'ipv4_addr' and
            named.get('flags') == ['timeout'] and type(named.get('timeout')) is int and
            named['timeout'] == TIMEOUT, 'Named set identity/seconds/timeout flag differ')
    require(chain.get('family') == 'inet' and chain.get('table') == TABLE and
            chain.get('name') == 'observations' and 'hook' not in chain and 'policy' not in chain,
            'No packet-path hooks are permitted')
    require(all(row.get('family') == 'inet' and row.get('table') == TABLE and
                row.get('chain') == 'observations' for row in rules), 'Foreign rule')
    elements = named.get('elem', [])
    require(isinstance(elements, list) and len(elements) <= 1, 'Unexpected element count')
    for item in elements:
        require(isinstance(item, dict) and set(item) == {'elem'} and isinstance(item['elem'], dict),
                'Unexpected named element wrapper')
        element = item['elem']
        require(set(element) <= {'val', 'timeout', 'expires'} and element.get('val') == LEASE and
                type(element.get('timeout', TIMEOUT)) is int and element.get('timeout', TIMEOUT) == TIMEOUT and
                type(element.get('expires')) is int and 0 <= element['expires'] <= TIMEOUT,
                'Unexpected source or unbounded element lifetime')
    anonymous = []
    def expressions(item):
        if isinstance(item, list):
            for child in item:
                expressions(child)
        elif isinstance(item, dict):
            if 'set' in item:
                require(set(item) == {'set'} and isinstance(item['set'], list), 'Anonymous set must be an array')
                anonymous.append(copy.deepcopy(item['set']))
            for child in item.values():
                expressions(child)
    for row in rules:
        expressions(row['expr'])
    require(anonymous == [PORTS, PORTS[:2]], 'Anonymous port expressions changed')
    return {'namedSetObject': True, 'anonymousSetArrays': anonymous, 'leaseElements': len(elements),
            'everySetValueIsObject': False}


def stable_snapshot(value):
    validate_snapshot(value)
    result = copy.deepcopy(value)
    result['nftables'] = [row for row in result['nftables'] if 'metainfo' not in row]
    for row in result['nftables']:
        if 'set' in row:
            row['set'].pop('elem', None)  # Only the validated named declaration.
    def counters(item):
        if isinstance(item, list):
            return [counters(child) for child in item]
        if not isinstance(item, dict):
            return item
        if set(item) == {'counter'}:
            c = item['counter']
            require(isinstance(c, dict) and set(c) == {'packets', 'bytes'} and
                    all(type(n) is int and n >= 0 for n in c.values()), 'Unexpected counter')
            return {'counter': {'packets': 0, 'bytes': 0}}
        return {key: counters(child) for key, child in item.items()}
    return counters(result)


def delete_owned_table(value, baseline):
    require(baseline is not None, 'No accepted full snapshot for deletion')
    require(stable_snapshot(value) == stable_snapshot(baseline), 'Full table drift blocks deletion')
    table = next(row['table'] for row in value['nftables'] if 'table' in row)
    handle = table['handle']
    # One exact object, with no retry or name-based fallback on an unknown ACK.
    run(['/usr/sbin/nft', 'delete', 'table', 'inet', 'handle', str(handle)])
    return handle


def child(request):
    versions = require_runner()
    parent = request['parentPid'];parent_namespace = request['parentNamespace']
    require(type(parent) is int and parent > 1 and namespace_identity(parent) == parent_namespace and
            namespace_identity() != parent_namespace, 'An independent ephemeral network namespace is mandatory')
    initial_raw, initial = json_ruleset()
    require(all(set(row) == {'metainfo'} for row in initial['nftables']), 'New namespace must have no tables')
    result = {'scope': 'SYNTHETIC_NFT_JSON_DECLARATION_VS_EXPRESSION', 'versions': versions,
              'status': 'FAIL', 'hostNamespaceUsed': False, 'packetHooks': 0, 'trafficGenerated': 0,
              'dockerActions': 0, 'snapshots': {}, 'cleanup': {'status': 'UNCONFIRMED'}}
    applied = False
    accepted_empty = None
    def capture(label):
        raw, value = json_ruleset()
        result['snapshots'][label] = {'sha256': digest(raw), 'bytes': len(raw), 'rawUtf8': raw.decode(), 'value': value}
        return value
    try:
        run(['/usr/sbin/nft', '--check', '-f', '-'], data=RULES.encode())
        applied = True
        run(['/usr/sbin/nft', '-f', '-'], data=RULES.encode())
        empty = capture('empty')
        result['shape'] = validate_snapshot(empty)
        accepted_empty = copy.deepcopy(empty)
        text = run(['/usr/sbin/nft', 'list', 'ruleset'])
        result['textReadback'] = {'sha256': digest(text), 'bytes': len(text), 'rawUtf8': text.decode(),
                                 'explicitTimeoutFlagPrinted': b'flags timeout' in text}
        require(b'timeout 2s' in text and b'flags timeout' not in text, 'Expected 1.1.6 text-only flag elision not observed')
        run(['/usr/sbin/nft', '-f', '-'], data=(f'add element inet {TABLE} lease_sources {{ {LEASE} timeout 2s }}\n').encode())
        live = capture('active')
        require(validate_snapshot(live)['leaseElements'] == 1, 'Active finite element not observed')
        require(stable_snapshot(live) == stable_snapshot(empty), 'Non-lease snapshot drift')
        deadline = time.monotonic() + 8
        while True:
            raw, value = json_ruleset()
            require(time.monotonic() < deadline, 'Kernel element did not expire within bound')
            if validate_snapshot(value)['leaseElements'] == 0:
                result['snapshots']['expired'] = {'sha256': digest(raw), 'bytes': len(raw), 'rawUtf8': raw.decode(), 'value': value}
                require(stable_snapshot(value) == stable_snapshot(empty), 'Expired snapshot changed static fields')
                break
            time.sleep(.15)
        result['status'] = 'PASS'
    except BaseException as error:
        result['failure'] = {'type': type(error).__name__, 'reason': str(error)[:1600]}
    finally:
        try:
            deleted_handle = None
            if applied:
                _, current = json_ruleset()
                if any('table' in row for row in current['nftables']):
                    deleted_handle = delete_owned_table(current, accepted_empty)
            final_raw, final = json_ruleset()
            require(all(set(row) == {'metainfo'} for row in final['nftables']), 'Namespace table cleanup unconfirmed')
            result['cleanup'] = {'status': 'PASS', 'emptyRulesetSha256': digest(final_raw),
                                 'deletedTableHandle': deleted_handle, 'deleteMethod': 'VERIFIED_TABLE_HANDLE', 'deleteRetries': 0}
        except BaseException as error:
            result['status'] = 'FAIL'
            result['cleanup'] = {'status': 'UNCONFIRMED', 'type': type(error).__name__, 'reason': str(error)[:1600]}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--child', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.child:
        require(args.output is None, 'Child has no filesystem output')
        print(json.dumps(child(json.load(sys.stdin)), sort_keys=True))
        return
    require_runner()
    require(args.output is not None and args.output.is_absolute() is False and
            len(args.output.parts) == 1 and args.output.name not in ('.', '..') and
            not os.path.lexists(args.output), 'Exclusive local result directory required')
    args.output.mkdir(mode=0o755)
    directory = os.open(args.output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        held = os.fstat(directory)
        def check_directory():
            current = args.output.lstat()
            require(stat.S_ISDIR(current.st_mode) and not args.output.is_symlink() and
                    current.st_uid == current.st_gid == 0 and
                    (current.st_dev, current.st_ino) == (held.st_dev, held.st_ino), 'Output directory replaced')
        check_directory();os.fchmod(directory, 0o755)
        before = namespace_identity()
        try:
            raw = run(['/usr/bin/unshare', '--net', '--fork', '--kill-child=KILL', sys.executable, '-I', '-B',
                       str(Path(__file__).resolve()), '--child'], data=encoded({'parentPid': os.getpid(), 'parentNamespace': before}), timeout=45)
            value = json.loads(raw)
            require(namespace_identity() == before, 'Outer namespace changed')
            value['namespaceChildExited'] = True
        except BaseException as error:
            value = {'status': 'FAIL', 'failure': {'type': type(error).__name__, 'reason': str(error)[:1600]},
                     'cleanup': {'status': 'UNCONFIRMED'}, 'outerNamespaceUnchanged': namespace_identity() == before}
        data = encoded(value);check_directory()
        fd = os.open('result.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=directory)
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), 0o644);output.write(data);output.flush();os.fsync(output.fileno())
        check_directory();os.fsync(directory)
    finally:
        os.close(directory)
    print(json.dumps({'status': value['status'], 'resultSha256': digest(data), 'bytes': len(data)}))
    require(value['status'] == 'PASS' and value['cleanup']['status'] == 'PASS', 'Native synthetic JSON probe did not pass')


if __name__ == '__main__':
    main()
