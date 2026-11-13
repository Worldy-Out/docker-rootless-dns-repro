import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

PATH = Path(__file__).resolve().parent / 'disk_metadata.py'
spec = importlib.util.spec_from_file_location('disk_metadata', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class DiskMetadataTests(unittest.TestCase):
    def setUp(self):
        self.config = {'Env': ['SECRET_KEY=fixture-never-public'], 'Image': 'pinned-fixture'}
        self.host = {'Dns': None, 'DnsOptions': None, 'DnsSearch': None, 'NetworkMode': 'original', 'RestartPolicy': {'Name': 'no'}}
        self.mounts = {'/run/tls': {'Source': '/fixture/tls', 'RW': False, 'Spec': {'ReadOnly': True}}}
        self.before = m.snapshot(self.config, self.host, self.mounts)
        self.after_host = copy.deepcopy(self.host)
        self.after_host.update({k: [] for k in m.DNS_FIELDS})
        self.after = m.snapshot(self.config, self.after_host, self.mounts)

    def test_exact_snapshot_keeps_raw_hash(self):
        r = m.audit(self.before, self.before, '29.1.3')
        self.assertTrue(r['rawEqual'])
        self.assertEqual(r['before']['specSha256'], m.digest(self.before['spec']))

    def test_only_proved_three_field_transition(self):
        saved = copy.deepcopy(self.before)
        r = m.audit(self.before, self.after, '29.1.3')
        self.assertEqual(r['status'], 'PASS_CONFIRMED_DOCKER_29_1_3_DNS_DEFAULTS')
        self.assertFalse(r['rawEqual'])
        self.assertEqual(self.before, saved)
        self.assertNotEqual(r['before']['specSha256'], r['after']['specSha256'])
        self.assertEqual(r['before']['componentSha256']['config'], r['after']['componentSha256']['config'])
        self.assertNotIn('fixture-never-public', json.dumps(r))

    def test_hash_only_before_forbidden(self):
        with self.assertRaises(RuntimeError): m.audit(m.fingerprints(self.before), self.after, '29.1.3')

    def test_missing_component_forbidden(self):
        old = copy.deepcopy(self.before); del old['spec']['mountpoints']
        with self.assertRaises(RuntimeError): m.audit(old, self.after, '29.1.3')

    def test_tampered_hash_forbidden(self):
        old = copy.deepcopy(self.before); old['specSha256'] = '0' * 64
        with self.assertRaises(RuntimeError): m.audit(old, self.after, '29.1.3')

    def test_other_versions_forbidden(self):
        for version in ['29.1.2', '29.1.3-unknown', '29.2.0', None]:
            with self.subTest(version=version), self.assertRaises(RuntimeError): m.audit(self.before, self.after, version)

    def test_reverse_transition_forbidden(self):
        with self.assertRaises(RuntimeError): m.audit(self.after, self.before, '29.1.3')

    def test_partial_dns_transition_forbidden(self):
        h = copy.deepcopy(self.host); h['Dns'] = []
        with self.assertRaises(RuntimeError): m.audit(self.before, m.snapshot(self.config, h, self.mounts), '29.1.3')

    def test_missing_dns_not_equivalent_to_null(self):
        h = copy.deepcopy(self.host); del h['Dns']
        with self.assertRaises(RuntimeError): m.audit(m.snapshot(self.config, h, self.mounts), self.after, '29.1.3')

    def test_unknown_host_field_change_forbidden(self):
        for key, value in [('Runtime', 'unknown'), ('NetworkMode', 'other'), ('FutureField', None)]:
            h = copy.deepcopy(self.after_host); h[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError): m.audit(self.before, m.snapshot(self.config, h, self.mounts), '29.1.3')

    def test_real_dns_change_forbidden(self):
        h = copy.deepcopy(self.after_host); h['Dns'] = ['8.8.8.8']
        with self.assertRaises(RuntimeError): m.audit(self.before, m.snapshot(self.config, h, self.mounts), '29.1.3')

    def test_credentials_and_mount_policy_drift_forbidden(self):
        c = copy.deepcopy(self.config); c['Env'] = ['SECRET_KEY=changed']
        mount = copy.deepcopy(self.mounts); mount['/run/tls']['RW'] = True
        for a in [m.snapshot(c, self.after_host, self.mounts), m.snapshot(self.config, self.after_host, mount)]:
            with self.assertRaises(RuntimeError): m.audit(self.before, a, '29.1.3')

    def test_full_stopped_disk_capture_and_permissions(self):
        with tempfile.TemporaryDirectory() as t:
            path = Path(t).resolve() / ('a' * 64); path.mkdir(mode=0o700)
            config = {'ID': path.name, 'State': {'Running': False, 'Paused': False, 'Restarting': False, 'Pid': 0}, 'Config': self.config, 'MountPoints': self.mounts}
            for name, value in [('config.v2.json', config), ('hostconfig.json', self.host)]:
                file = path / name; file.write_text(json.dumps(value)); file.chmod(0o600)
            self.assertEqual(m.read_snapshot(path, os.getuid()), self.before)
            (path / 'hostconfig.json').chmod(0o644)
            with self.assertRaises(RuntimeError): m.read_snapshot(path, os.getuid())

    def test_running_disk_snapshot_forbidden(self):
        with tempfile.TemporaryDirectory() as t:
            path = Path(t).resolve() / ('b' * 64); path.mkdir(mode=0o700)
            for name, value in [('config.v2.json', {'ID': path.name, 'State': {'Running': True}, 'Config': self.config, 'MountPoints': self.mounts}), ('hostconfig.json', self.host)]:
                file = path / name; file.write_text(json.dumps(value)); file.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, 'stopped'): m.read_snapshot(path, os.getuid())

    def inventory(self):
        cid = 'a' * 64
        fields = {'id': cid, 'running': False, 'restart': 'no', 'networkAttachments': {'original': {'NetworkID': 'b' * 64, 'Aliases': ['node'], 'DNSNames': ['node'], 'IPAMConfig': None}}, 'networks': {'original': 'b' * 64}, 'ports': {}}
        old = [fields | {'specSha256': self.before['specSha256']}]
        new = [copy.deepcopy(fields) | {'specSha256': self.after['specSha256']}]
        receipt = m.audit_inventory({'schema': 1, 'containers': {cid: self.before}}, {'schema': 1, 'containers': {cid: self.after}}, '29.1.3')
        return old, new, receipt

    def test_inventory_exception_keeps_raw_delta_explicit(self):
        old, new, receipt = self.inventory()
        r = m.verify_inventory_rows(old, new, receipt)
        self.assertFalse(r['rawEqual'])
        self.assertTrue(r['allOtherInventoryAndAttachmentsExact'])
        self.assertEqual(len(r['confirmedDnsDefaultTransitions']), 1)

    def test_no_receipt_or_hash_unlinked_fallback(self):
        old, new, receipt = self.inventory()
        for mutate in [lambda r: r['containers'].clear(),
                       lambda r: r['containers']['a' * 64]['before'].update(specSha256='0' * 64),
                       lambda r: r['containers']['a' * 64].update(fullPrivateBeforeAndAfterVerified=False),
                       lambda r: r['containers']['a' * 64]['after']['componentSha256'].update(config='0' * 64),
                       lambda r: r['containers']['a' * 64]['hostConfigAfter'].update(Foreign=True),
                       lambda r: r['containers']['a' * 64].update(rawEqual=True),
                       lambda r: r.update(engineVersion='29.2.0')]:
            bad = copy.deepcopy(receipt); mutate(bad)
            with self.assertRaises(RuntimeError): m.verify_inventory_rows(old, new, bad)
        with self.assertRaises(RuntimeError): m.verify_inventory_rows(old, new, None)

    def test_all_other_fields_and_extra_attachments_stay_exact(self):
        old, new, receipt = self.inventory()
        for mutate in [lambda row: row['networkAttachments'].update(extra={'NetworkID': 'c' * 64}),
                       lambda row: row['networkAttachments']['original'].update(Aliases=['other']),
                       lambda row: row['networkAttachments']['original'].update(DNSNames=['other']),
                       lambda row: row['networkAttachments']['original'].update(IPAMConfig={}),
                       lambda row: row.update(running=True), lambda row: row.update(restart='always'),
                       lambda row: row.update(FutureMetadata=None), lambda row: row.update(ports={'443/tcp': []})]:
            bad = copy.deepcopy(new); mutate(bad[0])
            with self.assertRaises(RuntimeError): m.verify_inventory_rows(old, bad, receipt)
        with self.assertRaises(RuntimeError): m.verify_inventory_rows(old, new + new, receipt)

    def test_capture_inventory_requires_fresh_hash_and_all_containers(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t).resolve(); parent = root / 'containers'; parent.mkdir(); directory = parent / ('a' * 64); directory.mkdir()
            c = {'ID': directory.name, 'State': {'Running': False, 'Pid': 0}, 'Config': self.config, 'MountPoints': self.mounts}
            for name, value in [('config.v2.json', c), ('hostconfig.json', self.host)]:
                file = directory / name; file.write_text(json.dumps(value)); file.chmod(0o600)
            rows = [{'id': directory.name, 'specSha256': self.before['specSha256']}]
            self.assertEqual(m.capture_inventory(rows, root, os.getuid())['containers'][directory.name], self.before)
            with self.assertRaises(RuntimeError): m.capture_inventory([], root, os.getuid())
            rows[0]['specSha256'] = '0' * 64
            with self.assertRaises(RuntimeError): m.capture_inventory(rows, root, os.getuid())


if __name__ == '__main__': unittest.main()
