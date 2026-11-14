"""Offline failure contracts. Native systemd evidence is a separate workflow."""
import copy
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import Mock,patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('fixture',HERE/'broker_bus_repro.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def manager(pid='42',inv='a'*32,active=True):
    return {'LoadState':'loaded','ActiveState':'active'if active else'inactive','SubState':'running'if active else'dead',
            'MainPID':pid if active else'0','InvocationID':inv if active else'',
            'ExecMainStartTimestampMonotonic':'100'if active else'0'}


def row(case):
    value={'case':case,'homeHidden':True,'rootMarkerHidden':True,'otherRuntimeHidden':True,
           'socketMountReadOnly':case!='original','onlySocketVisible':case=='bound'}
    if case=='original':value.update(status='QUERY_REJECTED',queryExecuted=True,queryExit=1,bus={'available':False,'reason':'MISSING'})
    elif case=='bound':value.update(status='STOPPED_QUERY_CONFIRMED',queryExecuted=True,bus={'available':True})
    else:value.update(status='REJECTED_BEFORE_USER_QUERY',queryExecuted=False,reason='MISSING'if case=='missing'else'FOREIGN_SOCKET')
    return value


class SandboxTests(unittest.TestCase):
    def test_candidate_changes_only_home_mode_and_fixed_readonly_socket(self):
        old=m.sandbox('original');new=m.sandbox('bound')
        self.assertEqual({k for k in old.keys()|new.keys()if old.get(k)!=new.get(k)}, {'ProtectHome','BindReadOnlyPaths'})
        self.assertEqual(new['ProtectHome'],'tmpfs');self.assertEqual(new['BindReadOnlyPaths'],str(m.RUNTIME/'bus'))
        self.assertNotIn('BindPaths',new);self.assertNotIn('User',new)
        self.assertEqual(old['NoNewPrivileges'],'yes');self.assertEqual(old['Group'],'root')
        self.assertEqual(old['ProtectSystem'],'strict');self.assertEqual(old['RuntimeMaxSec'],'25')
    def test_no_unbounded_or_caller_chosen_sandbox_case(self):
        for case in ('','../../escape','arbitrary','root'):
            with self.subTest(case=case),self.assertRaises(RuntimeError):m.sandbox(case)
    def test_fixed_query_has_no_start_or_shell_and_pins_the_bus(self):
        argv=m.user_query();self.assertEqual(argv[:4],['runuser','-u',m.NAME,'--'])
        self.assertIn('DBUS_SESSION_BUS_ADDRESS=unix:path='+str(m.RUNTIME/'bus'),argv)
        self.assertEqual(argv[argv.index('systemctl'):argv.index('systemctl')+4],['systemctl','--user','show','docker.service'])
        self.assertFalse(any(x in argv for x in ('start','restart','enable','bash','sh')))
    def test_stopped_query_rejects_unknown_status_extra_fields_or_running_pid(self):
        good={'exit':0,'stdout':'LoadState=loaded\nActiveState=inactive\nMainPID=0\nUnitFileState=disabled\nExecMainStartTimestampMonotonic=0\n','stderr':''}
        self.assertTrue(m.stopped_response(good))
        for change in ({'exit':1},{'stdout':good['stdout']+'Extra=1\n'},
                       {'stdout':good['stdout'].replace('MainPID=0','MainPID=7')},
                       {'stdout':good['stdout'].replace('disabled','enabled')},
                       {'stdout':good['stdout'].replace('inactive','active')},
                       {'stdout':good['stdout'].replace('ExecMainStartTimestampMonotonic=0','ExecMainStartTimestampMonotonic=77')}):
            with self.subTest(change=change):self.assertFalse(m.stopped_response({**good,**change}))
    def test_exact_assertions_reject_fake_positive_negative_or_lost_isolation(self):
        for case in m.CASES:m.check_case(case,row(case))
        changes={'original':[{'queryExit':0},{'bus':{'available':True,'reason':'OBSERVED'}}],
                 'bound':[{'socketMountReadOnly':False},{'onlySocketVisible':False},{'bus':{'available':False}}],
                 'missing':[{'queryExecuted':True},{'reason':'FOREIGN_SOCKET'}],
                 'foreign':[{'queryExecuted':True},{'reason':'MISSING'}]}
        for case,changeset in changes.items():
            for change in changeset+[{'homeHidden':False},{'rootMarkerHidden':False},{'otherRuntimeHidden':False}]:
                with self.subTest(case=case,change=change),self.assertRaises(RuntimeError):m.check_case(case,{**row(case),**change})


class FilesTests(unittest.TestCase):
    def test_exclusive_write_permissions_hash_and_replacement_detection(self):
        with tempfile.TemporaryDirectory()as td:
            path=Path(td)/'owned';pin=m.write_new(path,b'fixture\n');m.file_owned(path,pin)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            with self.assertRaises(FileExistsError):m.write_new(path,b'overwritten')
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError,'permissions'):m.file_owned(path,pin)
            path.chmod(0o600);path.write_bytes(b'changed')
            with self.assertRaisesRegex(RuntimeError,'changed'):m.file_owned(path,pin)
    def test_missing_or_symlink_or_regular_file_cannot_become_bus(self):
        with tempfile.TemporaryDirectory()as td:
            p=Path(td);self.assertEqual(m.bus_metadata(p),{'available':False,'reason':'MISSING'})
            (p/'target').write_text('inert');(p/'bus').symlink_to(p/'target')
            self.assertEqual(m.bus_metadata(p)['reason'],'SYMLINK')
            (p/'bus').unlink();(p/'bus').write_text('not a socket')
            self.assertFalse(m.bus_metadata(p)['available'])


class CleanupTests(unittest.TestCase):
    def state(self):return {'setupComplete':True,'managerGeneration':m.identity(manager()),
                            'stopAttempted':False,'files':{},'directories':{},'probeUnits':[]}
    def test_partial_setup_unknown_start_and_unknown_stop_preserve_without_commands(self):
        for data in ({'setupComplete':False},{'setupComplete':True,'managerGeneration':None},
                     {**self.state(),'stopAttempted':True,'stopConfirmed':False}):
            with self.subTest(data=data),patch.object(m,'run')as command,patch.object(m,'properties')as read:
                result=m.cleanup(data);self.assertEqual(result['status'],'FAIL');self.assertTrue(result['preserved'])
                command.assert_not_called();read.assert_not_called()
    def test_foreign_manager_generation_never_gets_stop(self):
        with patch.object(m,'properties',return_value=manager(inv='b'*32)),patch.object(m,'run')as command:
            result=m.cleanup(self.state());self.assertEqual(result['status'],'FAIL');command.assert_not_called()
    def test_lost_stop_ack_is_latched_and_cannot_repeat_after_later_inactivity(self):
        state=self.state()
        with patch.object(m,'properties',return_value=manager()),patch.object(m,'run',side_effect=TimeoutError('unknown'))as command:
            result=m.cleanup(state);self.assertEqual(result['status'],'FAIL');self.assertTrue(state['stopAttempted'])
            self.assertEqual(command.call_args.args[0],['systemctl','stop',m.MANAGER])
        with patch.object(m,'properties',return_value=manager(active=False)),patch.object(m,'run')as command:
            result=m.cleanup(state);self.assertEqual(result['status'],'FAIL');command.assert_not_called()
    def test_runtime_directory_teardown_is_required_before_cleanup_success(self):
        with patch.object(m,'properties',return_value=manager(active=False)),patch.object(m,'run',return_value={'exit':1}) as command, \
             patch.object(m.os.path,'lexists',return_value=True),patch.object(m.time,'monotonic',side_effect=[0,0,2]),patch.object(m.time,'sleep'):
            with self.assertRaisesRegex(RuntimeError,'not fully confirmed'):m.wait_closed(timeout=1)
        self.assertEqual(command.call_args.args[0],['pgrep','-u',str(m.UID)])
    def test_manager_stopped_does_not_claim_ready(self):
        self.assertFalse(m.active(manager(active=False)))
        with self.assertRaises(RuntimeError):m.identity(manager(active=False))


class HostGuardTests(unittest.TestCase):
    def test_hosted_runner_optin_is_mandatory(self):
        env={'GITHUB_ACTIONS':'true','CI':'true','RUNNER_ENVIRONMENT':'github-hosted','RUN_BROKER_BUS_REPRO':'yes'}
        for key in env:
            bad={**env,key:'wrong'}
            with self.subTest(key=key),patch.dict(m.os.environ,bad,clear=True),patch.object(m.os,'geteuid',return_value=0):
                with self.assertRaisesRegex(RuntimeError,'GitHub-hosted'):m.hosted_guard()
    def test_readiness_rejects_generation_change_during_bus_observation(self):
        with patch.object(m,'properties',side_effect=[manager(),manager(inv='b'*32)]), \
             patch.object(m,'bus_metadata',return_value={'available':True}), \
             patch.object(m.time,'monotonic',side_effect=[0,0,2]),patch.object(m.time,'sleep'):
            with self.assertRaisesRegex(RuntimeError,'deadline'):m.wait_ready(timeout=1)
    def test_unfiltered_inventory_failure_is_not_absence(self):
        with patch.object(m,'run',side_effect=RuntimeError('read failed')):
            with self.assertRaisesRegex(RuntimeError,'read failed'):m.service_inventory()
        for text in ('','bad','x.service loaded active running a\nx.service loaded active running b\n'):
            with self.subTest(text=text),patch.object(m,'run',return_value={'stdout':text}):
                with self.assertRaises(RuntimeError):m.service_inventory()


if __name__=='__main__':unittest.main()
