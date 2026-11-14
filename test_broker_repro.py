"""Offline adversarial contracts; this file never installs or starts systemd units."""
import importlib.util
import json
from pathlib import Path
import socket
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('fixture', Path(__file__).with_name('broker_repro.py'))
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class FramingTests(unittest.TestCase):
    def test_exact_operation_only(self):
        self.assertEqual(fixture.decode_request(b'{"op":"probe"}\n'), {'op': 'probe'})
        for data in [b'', b'{}\n', b'{"op":"start"}\n', b'{"op":"probe","args":[]}\n',
                     b'[]\n', b'null\n', b'{"op":"probe"}', b'{"op":"probe"}\n\n',
                     b'{"op":"probe"}\n{"op":"probe"}\n', b'X' * 257, b'\xff\n']:
            with self.subTest(data=data), self.assertRaises(RuntimeError):
                fixture.decode_request(data)

    def test_fragmentation_and_eof(self):
        a, b = socket.socketpair()
        try:
            def send():
                for chunk in [b'{"op":', b'"probe"}', b'\n']:
                    a.sendall(chunk)
                a.shutdown(socket.SHUT_WR)
            thread = threading.Thread(target=send); thread.start()
            self.assertEqual(fixture.read_frame(b), {'op': 'probe'})
            thread.join(timeout=1); self.assertFalse(thread.is_alive())
        finally:
            a.close(); b.close()

    def test_trailing_second_frame_rejected_even_after_first_newline(self):
        a, b = socket.socketpair()
        try:
            a.sendall(b'{"op":"probe"}\n{"op":"probe"}\n'); a.shutdown(socket.SHUT_WR)
            with self.assertRaises(RuntimeError):fixture.read_frame(b)
        finally:
            a.close(); b.close()

    def test_timeout_never_yields_valid_request(self):
        peer = unittest.mock.Mock()
        peer.recv.side_effect = socket.timeout()
        with patch.object(fixture.time, 'monotonic', side_effect=[10, 10]), self.assertRaises(socket.timeout):fixture.read_frame(peer)
        peer.settimeout.assert_called_once_with(3)

    def test_slow_drip_does_not_extend_total_receive_deadline(self):
        peer = unittest.mock.Mock(); peer.recv.side_effect = [b'{', b'"']
        with patch.object(fixture.time, 'monotonic', side_effect=[10, 10, 12, 13.01]), self.assertRaises(RuntimeError):
            fixture.read_frame(peer)
        self.assertEqual(peer.recv.call_count, 2)
        self.assertEqual(peer.settimeout.call_args_list, [unittest.mock.call(3), unittest.mock.call(1)])


class SandboxContractTests(unittest.TestCase):
    def test_probe_failure_retains_fixed_stage_and_bounded_diagnostic(self):
        with patch.object(fixture.os, 'getuid', return_value=0), \
                patch.object(fixture, 'proc_security', side_effect=RuntimeError('fixed capability diagnostic')), \
                patch.object(fixture, 'capability_diagnostic', return_value={'before': {'CapEff': 'missing'}}):
            with self.assertRaises(fixture.ProbeFailure) as caught:fixture.harmless_probe()
        self.assertEqual(caught.exception.stage, 'process-security')
        self.assertEqual(caught.exception.error_type, 'RuntimeError')
        self.assertEqual(str(caught.exception), 'fixed capability diagnostic')
        self.assertEqual(caught.exception.diagnostic, {'before': {'CapEff': 'missing'}})
        self.assertEqual(len(str(fixture.ProbeFailure('fixed-root-command', RuntimeError('x'*900)))), 800)

    def test_units_keep_exact_bounded_privilege_pattern(self):
        rows = fixture.unit_files()
        service = rows['broker-fixture@.service']
        for line in ['NoNewPrivileges=yes', 'ProtectSystem=strict', 'ProtectHome=yes',
                     'PrivateTmp=yes', 'ProtectControlGroups=yes', 'Restart=no',
                     'RuntimeMaxSec=150', 'KillMode=control-group', 'TasksMax=32',
                     'MemoryMax=128M', 'StandardInput=socket', 'StandardOutput=socket']:
            self.assertIn(line + '\n', service)
        self.assertNotIn('sudo', service)
        self.assertNotIn('ExecStartPre=', service)
        self.assertNotIn('Restart=always', ''.join(rows.values()))
        for line in ['Accept=yes', 'SocketMode=0660', 'SocketGroup=broker-fixture',
                     'MaxConnections=4', 'RemoveOnStop=yes']:
            self.assertIn(line + '\n', rows['broker-fixture.socket'])

    def test_effective_capabilities_need_exact_bits_and_no_new_privileges(self):
        good = 'NoNewPrivs:\t1\nCapEff:\t%016x\nCapBnd:\t%016x\nCapAmb:\t0\nCapPrm:\t%016x\nCapInh:\t0\n' % (fixture.CAP_MASK, fixture.CAP_MASK, fixture.CAP_MASK)
        with patch.object(Path, 'read_text', return_value=good):
            self.assertEqual(fixture.proc_security()['NoNewPrivs'], '1')
        for text in [good.replace('NoNewPrivs:\t1', 'NoNewPrivs:\t0'),
                     good.replace('CapAmb:\t0', 'CapAmb:\t1'),
                     good.replace('%016x' % fixture.CAP_MASK, '%016x' % (fixture.CAP_MASK | 1)),
                     good.replace('CapBnd:', 'Foreign:')]:
            with self.subTest(text=text), patch.object(Path, 'read_text', return_value=text), self.assertRaises(RuntimeError):
                fixture.proc_security()

    def test_watchdog_never_launches_commands_and_writes_only_once(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); (root / 'heartbeat.json').write_text(json.dumps({'at': 10}))
            with patch.object(fixture, 'STATE', root), patch.object(fixture, 'proc_security', return_value={}), \
                    patch.object(fixture.time, 'monotonic', return_value=20), patch.object(fixture, 'run') as command:
                fixture.watchdog(); first = (root / 'watchdog.json').read_bytes()
                fixture.watchdog()
                self.assertEqual((root / 'watchdog.json').read_bytes(), first)
                self.assertEqual(json.loads(first)['startsExecuted'], 0)
                command.assert_not_called()


class CleanupTests(unittest.TestCase):
    def empty(self):
        return {'users': [], 'group': False, 'dirs': [], 'files': {}, 'reloaded': False, 'enabled': []}

    def test_unknown_stop_cannot_report_cleanup_pass(self):
        created = self.empty(); created['reloaded'] = True
        with patch.object(fixture, 'names_present', return_value=['broker-fixture@1.service']), \
                patch.object(fixture, 'run', side_effect=RuntimeError('stop unavailable')):
            self.assertEqual(fixture.cleanup(created)['status'], 'FAIL')

    def test_unknown_account_creation_never_claims_clean(self):
        created = self.empty(); created['pendingAccount'] = 'broker-other'
        with patch.object(fixture, 'run') as command:
            self.assertEqual(fixture.cleanup(created)['status'], 'FAIL')
            command.assert_not_called()

    def test_userdel_removed_owned_group_only_when_name_and_gid_absent(self):
        created = self.empty();created['group'] = True
        with patch.object(fixture.grp, 'getgrnam', side_effect=KeyError()), \
                patch.object(fixture.grp, 'getgrgid', side_effect=KeyError()), patch.object(fixture, 'run') as command:
            self.assertEqual(fixture.cleanup(created)['status'], 'PASS')
            command.assert_not_called()

    def test_missing_group_name_with_reused_gid_is_not_safe_absence(self):
        created = self.empty();created['group'] = True
        with patch.object(fixture.grp, 'getgrnam', side_effect=KeyError()), \
                patch.object(fixture.grp, 'getgrgid', return_value=object()), patch.object(fixture, 'run') as command:
            self.assertEqual(fixture.cleanup(created)['status'], 'FAIL')
            command.assert_not_called()

    def test_groupdel_success_requires_independent_absence_readback(self):
        created = self.empty();created['group'] = True
        group = unittest.mock.Mock(gr_gid=fixture.UID)
        with patch.object(fixture.grp, 'getgrnam', return_value=group), \
                patch.object(fixture.grp, 'getgrgid', return_value=group), patch.object(fixture, 'run') as command:
            self.assertEqual(fixture.cleanup(created)['status'], 'FAIL')
            command.assert_called_once_with(['groupdel', fixture.NAME])

    def test_changed_file_never_removed(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'data'; receipt = fixture.write_new(path, b'first')
            path.write_bytes(b'changed')
            with patch.object(fixture, 'owned_stat', return_value=path.stat()), self.assertRaises(RuntimeError):
                fixture.unlink_owned(path, receipt)
            self.assertTrue(path.exists())

    def test_symlink_does_not_pass_owned_stat(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); (root / 'a').write_text('a'); (root / 'b').symlink_to(root / 'a')
            with self.assertRaises(RuntimeError):fixture.owned_stat(root / 'b', 0o600)

    def test_safe_writer_exclusive_and_exact_mode(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'data'
            fixture.write_new(path, b'first')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):fixture.write_new(path, b'overwrite')
            self.assertEqual(path.read_bytes(), b'first')

    def test_non_ci_host_rejected_before_commands(self):
        with patch.object(fixture.sys, 'platform', 'linux'), patch.object(fixture.os, 'getuid', return_value=0), \
                patch.dict(fixture.os.environ, {}, clear=True), patch.object(fixture, 'run') as command:
            with self.assertRaises(RuntimeError):fixture.native(Path('/not-created'))
            command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
