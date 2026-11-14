"""Local adversarial verdict/cleanup tests; these do not run a network fixture."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('fixture', Path(__file__).with_name('nft_lease_repro.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def samples():
    first = {'atMonotonic': 100.0, 'streams': {
        'gated': {'bytes': 100, 'lastByteMonotonic': 98.0, 'closed': False},
        'control': {'bytes': 100, 'lastByteMonotonic': 99.9, 'closed': False}}}
    second = copy.deepcopy(first)
    second['atMonotonic'] = 102.01
    second['streams']['control'].update(bytes=200, lastByteMonotonic=102.0)
    return first, second


class MeasurementTests(unittest.TestCase):
    def evaluate(self, case='gate-first', change=None):
        first, second = samples()
        denied = {'newGatedConnectionConnected': False}
        counters = {'input': {'packets': 1}, 'output': {'packets': 1}}
        if change: change(first, second, denied, counters)
        return fixture.measure(case, first, second, denied, counters)

    def test_fixed_gate_accepts_continuing_control_and_quiet_open_target(self):
        self.assertEqual(self.evaluate()[1], 0)

    def test_unsafe_control_must_demonstrate_bypass(self):
        with self.assertRaises(RuntimeError): self.evaluate('unsafe-order')
        result = self.evaluate('unsafe-order', lambda a, b, d, c: b['streams']['gated'].update(bytes=120))
        self.assertEqual(result[1], 20)
        self.assertTrue(result[0].startswith('EXPECTED_UNSAFE'))

    def test_late_target_bytes_are_failure(self):
        with self.assertRaisesRegex(RuntimeError, 'continued'):
            self.evaluate(change=lambda a, b, d, c: b['streams']['gated'].update(bytes=101))

    def test_target_remote_close_is_not_kernel_lease_proof(self):
        with self.assertRaisesRegex(RuntimeError, 'terminated'):
            self.evaluate(change=lambda a, b, d, c: b['streams']['gated'].update(closed=True))

    def test_dead_or_stalled_control_never_passes(self):
        for fields in ({'closed': True}, {'bytes': 100}, {'lastByteMonotonic': 100}):
            with self.subTest(fields=fields), self.assertRaises(RuntimeError):
                self.evaluate(change=lambda a, b, d, c: b['streams']['control'].update(fields))

    def test_short_window_and_new_connection_and_missing_counters_fail(self):
        changes = [lambda a, b, d, c: b.update(atMonotonic=101),
                   lambda a, b, d, c: d.update(newGatedConnectionConnected=True),
                   lambda a, b, d, c: c['input'].update(packets=0),
                   lambda a, b, d, c: c['output'].update(packets=0)]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(RuntimeError): self.evaluate(change=change)


class KernelContractTests(unittest.TestCase):
    def test_timed_element_parser_is_exact(self):
        item = {'family': 'inet', 'name': 'allowed', 'table': fixture.TABLE,
                'flags': ['timeout'], 'type': 'ipv4_addr', 'timeout': 4,
                'elem': [{'elem': {'val': fixture.CLIENT, 'timeout': 4, 'expires': 3}}]}
        row = {'nftables': [{'set': item}]}
        self.assertTrue(fixture.lease_present(row))
        item['elem'] = []
        self.assertFalse(fixture.lease_present(row))

    def test_exact_native_109_omitted_default_element_timeout(self):
        # Exact synthetic set/metainfo captured from the initial native attempt.
        row = {'nftables': [{'metainfo': {'json_schema_version': 1,
                'release_name': 'Old Doc Yak #3', 'version': '1.0.9'}},
                {'set': {'elem': [{'elem': {'expires': 3, 'val': '192.0.2.1'}}],
                'family': 'inet', 'flags': ['timeout'], 'handle': 3, 'name': 'allowed',
                'table': 'timed_gate', 'timeout': 4, 'type': 'ipv4_addr'}}]}
        self.assertTrue(fixture.lease_present(row))
        row['nftables'][1]['set']['elem'][0]['elem']['expires'] = 0
        # Rounded remaining time zero is not proof of absence; wait until the
        # kernel omits the element, then measure actual denied traffic.
        self.assertTrue(fixture.lease_present(row))

    def test_wrong_default_and_ambiguous_units_never_accepted(self):
        item = {'family': 'inet', 'name': 'allowed', 'table': fixture.TABLE,
                'flags': ['timeout'], 'type': 'ipv4_addr', 'timeout': 4,
                'elem': [{'elem': {'val': fixture.CLIENT, 'expires': 3}}]}
        for changes in ({'timeout': 4000}, {'timeout': True}, {'flags': []}, {'type': 'ipv6_addr'}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                fixture.lease_present({'nftables': [{'set': {**item, **changes}}]})

    def test_timed_element_drift_unknown_source_and_permanent_entry_fail(self):
        for fields in [{'val': '192.0.2.3', 'timeout': 4, 'expires': 3},
                       {'val': fixture.CLIENT}, {'val': fixture.CLIENT, 'timeout': 4000, 'expires': 3},
                       {'val': fixture.CLIENT, 'timeout': 4, 'expires': 5},
                       {'val': fixture.CLIENT, 'timeout': True, 'expires': 0}]:
            row = {'nftables': [{'set': {'family': 'inet', 'name': 'allowed', 'table': fixture.TABLE,
                                        'flags': ['timeout'], 'type': 'ipv4_addr', 'timeout': 4,
                                        'elem': [{'elem': fields}]}}]}
            with self.subTest(fields=fields), self.assertRaises(RuntimeError): fixture.lease_present(row)

    def test_both_directions_put_denial_before_conntrack(self):
        good, bad = fixture.rules(False), fixture.rules(True)
        for direction in ('input', 'output'):
            good_chain = good.split('chain '+direction+' {', 1)[1].split('}', 1)[0]
            bad_chain = bad.split('chain '+direction+' {', 1)[1].split('}', 1)[0]
            self.assertLess(good_chain.index('counter drop'), good_chain.index('ct state'))
            self.assertGreater(bad_chain.index('counter drop'), bad_chain.index('ct state'))
        renewal = fixture.renew_rules()
        self.assertEqual(renewal.count('delete element'), 1)
        self.assertEqual(renewal.count('add element'), 1)
        self.assertNotIn('flush', renewal)

    def test_unknown_namespace_identity_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = fixture.Lab('gate-first', Path(directory))
            lab.namespaces['server'] = (123, 456)
            fake = type('Info', (), {'st_uid': 0, 'st_dev': 123, 'st_ino': 999})()
            calls = []
            lab.run = lambda *a, **kw: calls.append((a, kw))
            with patch.object(Path, 'lstat', return_value=fake), patch.object(Path, 'is_symlink', return_value=False):
                self.assertFalse(lab.close())
            self.assertEqual(calls, [])
            record = json.loads((Path(directory)/'cleanup.json').read_text())
            self.assertEqual(record['status'], 'CLEANUP_UNCONFIRMED')

    def test_foreign_namespace_occupant_prevents_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = fixture.Lab('gate-first', Path(directory))
            lab.namespaces['server'] = (123, 456)
            fake = type('Info', (), {'st_uid': 0, 'st_dev': 123, 'st_ino': 456})()
            calls = []
            def command(args, **_):
                calls.append(args)
                return type('Result', (), {'stdout': '999\n'})()
            lab.run = command
            with patch.object(Path, 'lstat', return_value=fake), patch.object(Path, 'is_symlink', return_value=False):
                self.assertFalse(lab.close())
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][1:3], ['netns', 'pids'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
