#!/usr/bin/env python3
"""Local contract tests only; no systemd, accounts, or network calls."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('fixture',Path(__file__).with_name('user_manager_repro.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def unit(active=False, generation='a'*32, runtime=False):
    return {'LoadState':'loaded','ActiveState':'active' if active else 'inactive',
            'SubState':('exited' if runtime else 'running') if active else 'dead',
            'MainPID':'201' if active and not runtime else '0','InvocationID':generation if active else ''}


class Host:
    def __init__(self,warm=False):
        self.state={'bootId':'synthetic-boot','manager':unit(warm),'runtime':unit(warm,runtime=True),
          'busPresent':warm,'busInode':44 if warm else None,'busDevice':1 if warm else None,
          'sessions':[],'processes':[201] if warm else []}
        self.calls=[];self.stale_source=False;self.canary_running=False;self.leave_runtime=False;self.unknown_start=False;self.foreign_scope=False
    def snapshot(self):return copy.deepcopy(self.state)
    def offline(self):
        self.calls.append('offline');m.require(not self.stale_source,'static proof changed')
    def online(self):
        self.calls.append('online');m.require(not self.canary_running,'canary ran');m.require(not self.foreign_scope,'Unexpected user scope')
    def start(self):
        self.calls.append('start');self.state.update(manager=unit(True),runtime=unit(True,runtime=True),busPresent=True,busInode=44,busDevice=1,processes=[201])
        if self.unknown_start:raise RuntimeError('UNKNOWN_ACK')
    def wait_online(self):return self.snapshot()
    def stop_manager(self):
        self.calls.append('stop');self.state['manager']=unit();self.state['processes']=[]
        if not self.leave_runtime:self.stop_runtime()
    def stop_runtime(self):
        self.calls.append('runtime-stop');self.state.update(runtime=unit(),busPresent=False,busInode=None,busDevice=None)
    def wait_stopped(self,runtime=False):return self.snapshot()


class Cases(unittest.TestCase):
    def test_cold_start_and_owned_cleanup(self):
        host=Host();lease=m.Lease(host)
        self.assertEqual(lease.acquire(),'COLD_STARTED');self.assertEqual(host.calls[:2],['offline','start'])
        self.assertEqual(lease.release(),'OWNED_MANAGER_STOPPED');self.assertEqual(host.calls.count('start'),1)
        self.assertEqual(host.calls.count('stop'),1);self.assertFalse(host.state['busPresent'])
    def test_warm_never_starts_or_stops(self):
        host=Host(True);before=host.snapshot();lease=m.Lease(host)
        self.assertEqual(lease.acquire(),'WARM_REUSED');self.assertEqual(lease.release(),'PREEXISTING_MANAGER_PRESERVED')
        self.assertEqual(before,host.state);self.assertNotIn('start',host.calls);self.assertNotIn('stop',host.calls)
    def test_static_failure_precedes_start(self):
        host=Host();host.stale_source=True
        with self.assertRaises(RuntimeError):m.Lease(host).acquire()
        self.assertNotIn('start',host.calls)
    def test_missing_bus_warm_is_not_cold_start(self):
        host=Host(True);host.state['busPresent']=False
        # Online adapter must reject an inaccessible bus; never fallback start.
        host.online=lambda:(_ for _ in ()).throw(RuntimeError('missing bus'))
        with self.assertRaises(RuntimeError):m.Lease(host).acquire()
        self.assertNotIn('start',host.calls)
    def test_stale_bus_in_cold_state_rejected(self):
        host=Host();host.state['busPresent']=True
        with self.assertRaises(RuntimeError):m.Lease(host).acquire()
        self.assertNotIn('start',host.calls)
    def test_unknown_start_no_repeat_or_guessed_stop(self):
        host=Host();host.unknown_start=True;lease=m.Lease(host)
        with self.assertRaisesRegex(RuntimeError,'UNKNOWN_ACK'):lease.acquire()
        with self.assertRaisesRegex(RuntimeError,'UNKNOWN_START'):lease.release()
        self.assertEqual(host.calls.count('start'),1);self.assertNotIn('stop',host.calls)
    def test_unknown_precommit_ack_cannot_retry_same_lease(self):
        host=Host();lease=m.Lease(host)
        def missing_ack():host.calls.append('start');raise RuntimeError('UNKNOWN_ACK')
        host.start=missing_ack
        with self.assertRaisesRegex(RuntimeError,'UNKNOWN_ACK'):lease.acquire()
        self.assertTrue(m.cold(host.state['manager']))
        with self.assertRaisesRegex(RuntimeError,'single-attempt'):lease.acquire()
        self.assertEqual(host.calls.count('start'),1)
    def test_warm_lease_cannot_be_reacquired(self):
        host=Host(True);lease=m.Lease(host);lease.acquire()
        with self.assertRaisesRegex(RuntimeError,'single-attempt'):lease.acquire()
        self.assertNotIn('start',host.calls)
    def test_real_online_proof_failure_has_cleanup_ownership(self):
        host=Host();host.canary_running=True;lease=m.Lease(host)
        with self.assertRaisesRegex(RuntimeError,'canary ran'):lease.acquire()
        self.assertTrue(lease.owned)
        # A running unexpected workload blocks stop, not simply hidden by cleanup.
        with self.assertRaises(RuntimeError):lease.release()
        self.assertNotIn('stop',host.calls)
    def test_failure_after_successful_proof_cleans_once(self):
        host=Host();lease=m.Lease(host);lease.acquire()
        try:raise RuntimeError('injected')
        except RuntimeError:lease.release()
        self.assertEqual(host.calls.count('stop'),1)
    def test_unknown_stop_ack_cannot_retry_stop(self):
        host=Host();lease=m.Lease(host);lease.acquire()
        def missing_ack():host.calls.append('stop');raise RuntimeError('UNKNOWN_STOP_ACK')
        host.stop_manager=missing_ack
        with self.assertRaisesRegex(RuntimeError,'UNKNOWN_STOP_ACK'):lease.release()
        with self.assertRaisesRegex(RuntimeError,'single-attempt'):lease.release()
        self.assertEqual(host.calls.count('stop'),1)
    def test_foreign_session_blocks_stop(self):
        host=Host();lease=m.Lease(host);lease.acquire();host.state['sessions']=['foreign']
        with self.assertRaisesRegex(RuntimeError,'Foreign session'):lease.release()
        self.assertNotIn('stop',host.calls)
    def test_foreign_user_scope_blocks_stop_without_login_session(self):
        host=Host();lease=m.Lease(host);lease.acquire();host.foreign_scope=True
        self.assertEqual(host.state['sessions'],[])
        with self.assertRaisesRegex(RuntimeError,'Unexpected user scope'):lease.release()
        self.assertNotIn('stop',host.calls)
    def test_changed_manager_generation_blocks_stop(self):
        for key in ('bootId','busInode','manager'):
            host=Host();lease=m.Lease(host);lease.acquire()
            host.state[key]={'bootId':'new','busInode':99,'manager':unit(True,'b'*32)}[key]
            with self.assertRaises(RuntimeError):lease.release()
            self.assertNotIn('stop',host.calls)
    def test_leftover_own_runtime_is_stopped_exactly(self):
        host=Host();host.leave_runtime=True;lease=m.Lease(host);lease.acquire();lease.release()
        self.assertEqual(host.calls.count('runtime-stop'),1)
    def test_foreign_runtime_generation_not_stopped(self):
        host=Host();host.leave_runtime=True;lease=m.Lease(host);lease.acquire()
        old=host.stop_manager
        def stop():old();host.state['runtime']['InvocationID']='b'*32
        host.stop_manager=stop
        with self.assertRaisesRegex(RuntimeError,'Runtime directory ownership'):lease.release()
        self.assertNotIn('runtime-stop',host.calls)
    def test_foreign_session_during_online_check_blocks_stop(self):
        host=Host();lease=m.Lease(host);lease.acquire()
        host.online=lambda:host.state.update(sessions=['late-session'])
        with self.assertRaisesRegex(RuntimeError,'session drift'):lease.release()
        self.assertNotIn('stop',host.calls)
    def test_failed_manager_is_not_cold(self):
        host=Host();host.state['manager']['ActiveState']='failed'
        with self.assertRaisesRegex(RuntimeError,'proven cold'):m.Lease(host).acquire()
        self.assertNotIn('start',host.calls)
    def test_read_failure_not_absence(self):
        host=Host();host.snapshot=lambda:(_ for _ in ()).throw(RuntimeError('read failure'))
        with self.assertRaises(RuntimeError):m.Lease(host).acquire()
        self.assertNotIn('start',host.calls)
    def test_unknown_start_cold_snapshot_preserves_account(self):
        host=Host();lease=m.Lease(host)
        def unknown():host.calls.append('start');raise RuntimeError('UNKNOWN_ACK')
        host.start=unknown
        with self.assertRaises(RuntimeError):lease.acquire()
        with patch.object(m,'remove_account') as remove:
            result=m.cleanup_owned(host,[lease],True,True)
            self.assertEqual(result['status'],'FAIL');remove.assert_not_called()
    def test_unknown_stop_then_cold_snapshot_preserves_account(self):
        host=Host();lease=m.Lease(host);lease.acquire();original=host.stop_manager
        def unknown():original();raise RuntimeError('UNKNOWN_STOP_ACK')
        host.stop_manager=unknown
        with self.assertRaises(RuntimeError):lease.release()
        self.assertTrue(m.cold(host.state['manager']))
        with patch.object(m,'remove_account') as remove:
            self.assertEqual(m.cleanup_owned(host,[lease],True,True)['status'],'FAIL');remove.assert_not_called()
    def test_confirmed_cleanup_removes_only_known_account(self):
        host=Host();lease=m.Lease(host);lease.acquire()
        with patch.object(m,'remove_account') as remove:
            self.assertEqual(m.cleanup_owned(host,[lease],True,True)['status'],'PASS');remove.assert_called_once_with(host)
    def test_partial_setup_is_not_cleanup_pass(self):
        with patch.object(m,'remove_account') as remove:
            self.assertEqual(m.cleanup_owned(Host(),[],False,True)['status'],'FAIL');remove.assert_not_called()
    def test_unknown_pam_start_cold_snapshot_preserves_account(self):
        host=Host();host.unit=lambda _:dict(unit(),LoadState='not-found')
        pam=m.PamCase(host)
        with patch.object(m,'run',side_effect=RuntimeError('UNKNOWN_PAM_ACK')):
            with self.assertRaisesRegex(RuntimeError,'UNKNOWN_PAM_ACK'):pam.start()
        with patch.object(m,'remove_account') as remove:
            result=m.cleanup_owned(host,[],True,True,pam)
            self.assertEqual(result['status'],'FAIL');self.assertIn('UNKNOWN_PAM_START',str(result));remove.assert_not_called()
    def test_pam_start_requires_complete_cold_snapshot(self):
        for field,value in [('runtime',unit(True,runtime=True)),('busPresent',True),('sessions',['new']),('processes',[99])]:
            host=Host();host.unit=lambda _:dict(unit(),LoadState='not-found');host.state[field]=value
            with patch.object(m,'run') as call:
                with self.assertRaisesRegex(RuntimeError,'proven cold account'):m.PamCase(host).start()
                call.assert_not_called()
    def test_duplicate_and_missing_systemd_properties_rejected(self):
        for raw in ('LoadState=loaded\nLoadState=loaded','LoadState=loaded','not-a-property'):
            with self.assertRaises(RuntimeError):m.properties(raw,m.FIELDS)

if __name__=='__main__':unittest.main()
