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


if __name__ == '__main__':
    unittest.main()
