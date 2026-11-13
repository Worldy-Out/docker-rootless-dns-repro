import copy
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import native_repro as native


class NativeHarnessTests(unittest.TestCase):
    def test_explicit_receipt_permissions_survive_umask077(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'receipt.json'
            old = os.umask(0o077)
            try:
                native.write(file, {'synthetic': True}, 0o644)
            finally:
                os.umask(old)
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o644)

    def test_existing_evidence_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'receipt.json'
            native.write(file, {'before': True})
            before = file.read_bytes()
            with self.assertRaises(RuntimeError):
                native.write(file, {'before': False})
            self.assertEqual(file.read_bytes(), before)

    def test_preflight_rejects_non_hosted_without_creating_paths(self):
        with patch.object(native.os, 'geteuid', return_value=0), \
             patch.object(native.os, 'uname', return_value=type('Uname', (), {'machine': 'x86_64'})()), \
             patch.dict(os.environ, {}, clear=True), \
             patch.object(Path, 'mkdir') as mkdir:
            with self.assertRaisesRegex(RuntimeError, 'GitHub-hosted'):
                native.preflight()
            mkdir.assert_not_called()

    def test_protected_preserves_full_attachment_map_and_deep_copies(self):
        row = {'Id': 'synthetic', 'Name': 'fixture', 'Image': 'pinned', 'Config': {'Env': []},
               'HostConfig': {'Dns': None}, 'Mounts': [{'Destination': '/fixture', 'RW': False}],
               'NetworkSettings': {'Networks': {'fixture-net': {'NetworkID': 'fixture-network',
                  'Aliases': ['fixture'], 'DNSNames': ['fixture', 'synthetic'], 'IPAMConfig': None,
                  'EndpointID': '', 'FutureField': {'proof': True}}}}}
        old = copy.deepcopy(row)
        protected = native.protected(row)
        self.assertEqual(protected['NetworkSettings'], row['NetworkSettings']['Networks'])
        protected['NetworkSettings']['fixture-net']['Aliases'].append('changed')
        self.assertEqual(row, old)
        row['Mounts'].append(copy.deepcopy(row['Mounts'][0]))
        with self.assertRaisesRegex(RuntimeError, 'Duplicate'):
            native.protected(row)


    def engine_baseline(self):
        return {'control': {'Id': 'control-id', 'Config': {'Env': ['SYNTHETIC=1']},
                            'HostConfig': {'Dns': None, 'DnsOptions': [], 'DnsSearch': [], 'ReadonlyRootfs': True},
                            'NetworkSettings': {'net': {'NetworkID': 'network-id', 'Aliases': ['control'], 'DNSNames': ['control']}}},
                'fixture': {'Id': 'fixture-id', 'Config': {'Env': []},
                            'HostConfig': {'Dns': None, 'DnsOptions': None, 'DnsSearch': None, 'ReadonlyRootfs': True},
                            'NetworkSettings': {'net': {'NetworkID': 'network-id', 'Aliases': ['fixture'], 'IPAMConfig': None}}}}

    def test_cold_projection_is_explicit_versioned_and_never_mutates_baseline(self):
        before = self.engine_baseline()
        saved = copy.deepcopy(before)
        expected, receipt = native.expected_cold_engine(before, '29.1.3')
        self.assertEqual(before, saved)
        self.assertEqual(receipt['projectedPaths'], ['/engine/control/HostConfig/Dns',
            '/engine/fixture/HostConfig/Dns', '/engine/fixture/HostConfig/DnsOptions', '/engine/fixture/HostConfig/DnsSearch'])
        self.assertFalse(receipt['rawBaselineRewritten'])
        self.assertFalse(receipt['diskMutatedByProjection'])
        self.assertEqual(receipt['kind'], 'DERIVED_COLD_ENGINE_EXPECTATION')
        for row in expected.values():
            for field in native.DNS_FIELDS:
                self.assertEqual(row['HostConfig'][field], [])
        expected['fixture']['NetworkSettings']['net']['Aliases'].append('changed')
        self.assertEqual(before, saved)

    def test_cold_projection_rejects_unknown_version_missing_or_invalid_dns(self):
        for version in ['29.1.2', '29.1.3-custom', None]:
            with self.subTest(version=version), self.assertRaises(RuntimeError):
                native.expected_cold_engine(self.engine_baseline(), version)
        for field in native.DNS_FIELDS:
            before = self.engine_baseline()
            del before['fixture']['HostConfig'][field]
            with self.subTest(missing=field), self.assertRaises(RuntimeError):
                native.expected_cold_engine(before, '29.1.3')
            for value in [False, 0, '', {}, (), ['nonempty']]:
                before = self.engine_baseline()
                before['fixture']['HostConfig'][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(RuntimeError):
                    native.expected_cold_engine(before, '29.1.3')

    def test_cold_projection_preserves_every_other_field_and_full_attachments(self):
        before = self.engine_baseline()
        expected, _ = native.expected_cold_engine(before, '29.1.3')
        inverse = copy.deepcopy(expected)
        for name in inverse:
            for field in native.DNS_FIELDS:
                inverse[name]['HostConfig'][field] = before[name]['HostConfig'][field]
        self.assertEqual(inverse, before)
        for key, value in [('NetworkID', 'other-network'), ('Aliases', ['other']),
                           ('DNSNames', ['other']), ('IPAMConfig', {'IPv4Address': 'synthetic'})]:
            changed = copy.deepcopy(expected)
            changed['fixture']['NetworkSettings']['net'][key] = value
            self.assertNotEqual(changed, expected)
        changed = copy.deepcopy(expected)
        changed['fixture']['HostConfig']['ReadonlyRootfs'] = False
        self.assertNotEqual(changed, expected)
        changed = copy.deepcopy(expected)
        changed['fixture']['Config']['Env'] = ['CHANGED=1']
        self.assertNotEqual(changed, expected)


    def test_control_initialization_changes_only_dns_before_accepted_baseline(self):
        host = {'Dns': None, 'DnsOptions': [], 'DnsSearch': [], 'ReadonlyRootfs': True,
                'FutureField': {'keep': True}}
        original = native.snapshot({'Env': ['SYNTHETIC=1']}, host,
                                   {'/fixture': {'Destination': '/fixture', 'RW': False}})
        saved = copy.deepcopy(original)
        target, receipt = native.control_setup_snapshot(original)
        self.assertEqual(original, saved)
        self.assertEqual(receipt['initializedPaths'], ['/HostConfig/Dns'])
        self.assertTrue(receipt['originalSnapshotPreserved'])
        self.assertFalse(receipt['historicalRollbackClaim'])
        self.assertEqual(receipt['kind'], 'SYNTHETIC_CONTROL_INITIALIZATION_BEFORE_BASELINE')
        self.assertEqual(target['spec']['config'], original['spec']['config'])
        self.assertEqual(target['spec']['mountpoints'], original['spec']['mountpoints'])
        inverse = copy.deepcopy(target['spec']['hostconfig'])
        for field in native.DNS_FIELDS:
            self.assertEqual(target['spec']['hostconfig'][field], [])
            inverse[field] = original['spec']['hostconfig'][field]
        self.assertEqual(inverse, original['spec']['hostconfig'])
        self.assertEqual(native.audit(target, copy.deepcopy(target), '29.1.3')['status'], 'PASS_EXACT_DISK_SPEC')
        target['spec']['hostconfig']['FutureField']['keep'] = False
        self.assertEqual(original, saved)

    def test_control_initialization_rejects_incomplete_tampered_and_nonempty_dns(self):
        for field in native.DNS_FIELDS:
            for bad in [False, 0, '', {}, ['nonempty']]:
                host = {'Dns': None, 'DnsOptions': [], 'DnsSearch': []}
                host[field] = bad
                with self.subTest(field=field, bad=bad), self.assertRaises(RuntimeError):
                    native.control_setup_snapshot(native.snapshot({'Env': []}, host, {}))
            host = {'Dns': None, 'DnsOptions': [], 'DnsSearch': []}
            del host[field]
            with self.subTest(missing=field), self.assertRaises(RuntimeError):
                native.control_setup_snapshot(native.snapshot({'Env': []}, host, {}))
        original = native.snapshot({'Env': []}, {'Dns': None, 'DnsOptions': [], 'DnsSearch': []}, {})
        original['specSha256'] = '0' * 64
        with self.assertRaises(RuntimeError):
            native.control_setup_snapshot(original)


if __name__ == '__main__':
    unittest.main()
