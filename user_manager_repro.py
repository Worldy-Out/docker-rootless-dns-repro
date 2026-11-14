#!/usr/bin/env python3
"""Disposable, synthetic GitHub-hosted Linux user-manager experiment only."""
import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import signal
import stat
import subprocess
import time

NAME = 'manager-fixture'
UID = 16067
FIXTURE_HOME = Path('/var/lib/manager-fixture')
CANARY = FIXTURE_HOME / '.config/systemd/user/disabled-canary.service'
MARKER = FIXTURE_HOME / 'UNEXPECTED_START'
MANAGER = 'user@16067.service'
RUNTIME = 'user-runtime-dir@16067.service'
SESSION = 'manager-fixture-pam.service'
FIELDS = ['LoadState', 'ActiveState', 'SubState', 'MainPID', 'InvocationID']
PAM_FIELDS = FIELDS + ['Type','Result','ExecMainPID','ControlPID','ExecMainCode','ExecMainStatus',
    'ExecMainStartTimestampMonotonic','ExecMainExitTimestampMonotonic','ActiveEnterTimestampMonotonic',
    'StateChangeTimestampMonotonic','TimeoutStartUSec','RuntimeMaxUSec','Job','Names']
CANARY_TEXT = '''[Unit]
Description=Disabled synthetic canary must never run
[Service]
Type=oneshot
ExecStart=/usr/bin/touch /var/lib/manager-fixture/UNEXPECTED_START
Restart=no
[Install]
WantedBy=default.target
'''


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def run(argv, timeout=10, accepted=(0,)):
    p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, start_new_session=True)
    try:
        out, err = p.communicate(timeout=timeout)
    except BaseException:
        try: os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        p.communicate(timeout=3)
        raise
    require(p.returncode in accepted, 'Fixed command failed: ' + argv[0] + ': ' + err.decode(errors='replace')[-500:])
    return p.returncode, out.decode().strip(), err.decode().strip()


def properties(text, fields):
    result = {}
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        require(sep and key not in result, 'Malformed or duplicate systemd property')
        result[key] = value
    require(set(result) == set(fields), 'Missing systemd properties')
    return result


def active(row):
    return row['LoadState'] == 'loaded' and row['ActiveState'] == 'active' and row['SubState'] == 'running' and int(row['MainPID']) > 0 and len(row['InvocationID']) == 32


def cold(row):
    return row['LoadState'] in ('loaded', 'not-found') and row['ActiveState'] == 'inactive' and row['SubState'] == 'dead' and row['MainPID'] == '0'


def stable_identity(row):
    return {k: row[k] for k in ('bootId', 'manager', 'runtime', 'busInode', 'busDevice', 'runtimeDirectoryInode', 'runtimeDirectoryDevice')}


def closed_snapshot(row):
    return row['coherent'] and cold(row['manager']) and cold(row['runtime']) and not row['busPresent'] and not row['runtimeDirectoryPresent'] and not row['processes'] and not row['sessions']


def stop_ready(row, runtime=False):
    if closed_snapshot(row):return True
    # Return a still-active owned runtime-dir to the caller for its ONE optional
    # stop. Cold units with a lingering bus/directory are intermediate teardown,
    # not completion, and must only be polled within the existing deadline.
    return (not runtime and row['coherent'] and cold(row['manager']) and not row['processes'] and not row['sessions']
            and row['runtime']['ActiveState']=='active' and row['runtime']['SubState']=='exited')


class Lease:
    """Generic reviewed mechanism. Unknown start does not authorize a stop."""
    def __init__(self, host):
        self.host, self.owned, self.generation = host, False, None
        self.start_attempted = False
        self.acquire_attempted = False
        self.stop_attempted = False

    def acquire(self):
        require(not self.acquire_attempted, 'Lease acquisition is single-attempt')
        self.acquire_attempted = True
        before = self.host.snapshot()
        require(before['coherent'], 'Initial observation changed during read')
        self.host.offline()
        if active(before['manager']):
            self.host.online()
            current=self.host.snapshot()
            require(current['coherent'] and stable_identity(current) == stable_identity(before), 'Warm generation changed')
            self.generation = before
            return 'WARM_REUSED'
        require(cold(before['manager']) and not before['busPresent'] and not before['runtimeDirectoryPresent'] and cold(before['runtime']), 'Not a proven cold manager')
        require(not before['sessions'] and not before['processes'], 'Cold account unexpectedly active')
        self.start_attempted = True
        self.host.start()
        after = self.host.wait_online()
        # Ownership requires a successful start result plus this exact observed
        # generation. An interrupted/unknown start is never blindly repeated.
        require(after['bootId'] == before['bootId'] and active(after['manager']), 'Manager generation unavailable')
        self.generation, self.owned = after, True
        self.host.online()
        return 'COLD_STARTED'

    def release(self):
        if not self.owned:
            require(not self.start_attempted, 'UNKNOWN_START_REQUIRES_DISPOSABLE_RUNNER_CONTAINMENT')
            current=self.host.snapshot()
            require(current['coherent'] and stable_identity(current) == stable_identity(self.generation), 'Warm manager changed')
            self.host.online()
            return 'PREEXISTING_MANAGER_PRESERVED'
        require(not self.stop_attempted, 'Manager stop is single-attempt; unknown cleanup preserved')
        now = self.host.snapshot()
        require(now['coherent'] and stable_identity(now) == stable_identity(self.generation), 'Owned manager identity changed')
        require(not now['sessions'], 'Foreign session forbids manager stop')
        self.host.online()
        immediate = self.host.snapshot()
        require(immediate['coherent'] and stable_identity(immediate) == stable_identity(self.generation) and not immediate['sessions'], 'Manager/session drift before stop')
        self.stop_attempted = True
        self.host.stop_manager()
        state = self.host.wait_stopped()
        # Some distributions leave the runtime-dir unit. Never rm /run/user.
        if not cold(state['runtime']):
            require(state['runtime'] == self.generation['runtime'] and not state['sessions'], 'Runtime directory ownership changed')
            self.host.stop_runtime()
            state = self.host.wait_stopped(runtime=True)
        require(closed_snapshot(state), 'Incomplete manager cleanup')
        self.owned = self.start_attempted = False
        return 'OWNED_MANAGER_STOPPED'


class Host:
    def __init__(self):
        self.calls, self.started_at = [], time.monotonic()
        self.cleaning = False
        self.stop_observations = []
        self.stop_observations_omitted = 0

    def deadline(self):
        require(time.monotonic() - self.started_at < (240 if self.cleaning else 180), 'Native experiment deadline')

    def unit(self, name):
        text = run(['/usr/bin/systemctl', 'show', name, '--no-pager', *['--property='+x for x in FIELDS]])[1]
        return properties(text, FIELDS)

    def pam_diagnostic(self):
        text=run(['/usr/bin/systemctl','show',SESSION,'--no-pager',*['--property='+x for x in PAM_FIELDS]])[1]
        return properties(text,PAM_FIELDS)

    def user(self, *args):
        self.deadline()
        return run(['/usr/sbin/runuser', '-u', NAME, '--', '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin',
                    'HOME='+str(FIXTURE_HOME), 'XDG_RUNTIME_DIR=/run/user/'+str(UID),
                    'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/'+str(UID)+'/bus', '/usr/bin/systemctl', '--user', *args])

    def resources(self):
        directory=Path('/run/user') / str(UID)
        try:
            ds=directory.lstat()
            require(stat.S_ISDIR(ds.st_mode) and ds.st_uid==UID and ds.st_gid==UID and stat.S_IMODE(ds.st_mode)==0o700, 'Unsafe runtime directory')
        except FileNotFoundError:ds=None
        try:
            bs=(directory/'bus').lstat()
            require(stat.S_ISSOCK(bs.st_mode) and bs.st_uid==UID, 'Unsafe user bus')
        except FileNotFoundError:bs=None
        return {'busPresent':bs is not None,'busInode':bs.st_ino if bs else None,'busDevice':bs.st_dev if bs else None,
                'runtimeDirectoryPresent':ds is not None,'runtimeDirectoryInode':ds.st_ino if ds else None,
                'runtimeDirectoryDevice':ds.st_dev if ds else None}

    def boundaries(self):
        return {'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'manager':self.unit(MANAGER),'runtime':self.unit(RUNTIME)}

    def snapshot(self):
        self.deadline()
        begin=self.boundaries();resources_before=self.resources()
        sessions=[]
        for line in run(['/usr/bin/loginctl','list-sessions','--no-legend','--no-pager'])[1].splitlines():
            parts=line.split();require(len(parts)>=3,'Session listing malformed')
            if parts[1]==str(UID):sessions.append(parts[0])
        code,procs,_=run(['/usr/bin/pgrep','-u',str(UID)],accepted=(0,1))
        resources_after=self.resources();end=self.boundaries()
        row={**end,**resources_after,'sessions':sessions,'processes':[int(x) for x in procs.split()] if code==0 else [],
             'coherent':begin==end and resources_before==resources_after}
        if not row['coherent']:
            row['readBoundary']={'before':begin,'resourcesBefore':resources_before}
        return row

    def stop_observation(self, row, runtime):
        value={'runtimeStopPhase':runtime,'state':row}
        at=round(time.monotonic()-self.started_at,3)
        if self.stop_observations and self.stop_observations[-1]['observation']==value:
            self.stop_observations[-1]['lastObservedSeconds']=at
        else:
            self.stop_observations.append({'firstObservedSeconds':at,'lastObservedSeconds':at,'observation':value})
            if len(self.stop_observations)>32:
                self.stop_observations.pop(0);self.stop_observations_omitted+=1

    def offline(self):
        require(not MARKER.exists() and not MARKER.is_symlink(), 'Canary ran')
        data = CANARY.read_bytes()
        s = CANARY.lstat()
        require(stat.S_ISREG(s.st_mode) and s.st_uid == UID and s.st_gid == UID and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600 and data == CANARY_TEXT.encode(), 'Canary source changed')
        # The synthetic account has exactly this single source and no enablement
        # links, environment, generators, aliases, or drop-ins in its home.
        root = FIXTURE_HOME / '.config/systemd/user'
        require(list(root.iterdir()) == [CANARY], 'Unexpected user startup files')
        for path in (FIXTURE_HOME, FIXTURE_HOME/'.config', FIXTURE_HOME/'.config/systemd', root):
            st = path.lstat()
            require(stat.S_ISDIR(st.st_mode) and st.st_uid == UID and st.st_gid == UID and stat.S_IMODE(st.st_mode) == 0o700, 'Unsafe synthetic ancestry')
        require(not (Path('/var/lib/systemd/linger')/NAME).exists(), 'Linger changed')
        return hashlib.sha256(data).hexdigest()

    def online(self):
        self.offline()
        fields = ['ActiveState','SubState','MainPID','UnitFileState','FragmentPath','DropInPaths','NeedDaemonReload']
        row = properties(self.user('show', 'disabled-canary.service', *['--property='+x for x in fields])[1], fields)
        require(row == {'ActiveState':'inactive','SubState':'dead','MainPID':'0','UnitFileState':'disabled',
                        'FragmentPath':str(CANARY),'DropInPaths':'','NeedDaemonReload':'no'}, 'Disabled canary changed or ran')
        units = json.loads(self.user('list-units','--type=service','--state=active,activating,deactivating','--all','--no-legend','--no-pager','--output=json')[1])
        require(all(x.get('unit') in ('dbus.service','dbus-broker.service') for x in units), 'Unexpected active user service')
        scopes = json.loads(self.user('list-units','--type=scope','--state=active,activating,deactivating','--all','--no-legend','--no-pager','--output=json')[1])
        require(all(x.get('unit') == 'init.scope' for x in scopes), 'Unexpected user scope')
        return row

    def start(self):
        self.calls.append('manager_start')
        run(['/usr/bin/systemctl','start','--no-block',MANAGER])

    def stop_manager(self):
        self.calls.append('manager_stop')
        run(['/usr/bin/systemctl','stop','--no-block',MANAGER])

    def stop_runtime(self):
        self.calls.append('runtime_stop')
        run(['/usr/bin/systemctl','stop','--no-block',RUNTIME])

    def wait_online(self):
        end = time.monotonic() + 30
        while time.monotonic() < end:
            row = self.snapshot()
            if row['coherent'] and active(row['manager']) and row['busPresent'] and row['runtimeDirectoryPresent']: return row
            time.sleep(.1)
        raise RuntimeError('User manager online deadline')

    def wait_stopped(self, runtime=False):
        end = time.monotonic() + 30
        while time.monotonic() < end:
            row = self.snapshot()
            self.stop_observation(row,runtime)
            if stop_ready(row,runtime): return row
            time.sleep(.1)
        raise RuntimeError('User manager stop deadline')


class PamCase:
    """Separate observation; never interprets session loss as a manager hold."""
    def __init__(self, host):
        self.host, self.generation, self.owned_manager = host, None, None
        self.attempted = False
        self.cleanup_attempted = False
        self.observations=[]
        self.observations_omitted=0

    def record(self,service,state):
        diagnostic=self.host.pam_diagnostic()
        value={'service':service,'serviceDetailed':diagnostic,'state':state,
               'readiness':{'ownServiceActive':active(service),'managerActive':active(state['manager']),
                            'busPresent':state['busPresent'],'hasSession':bool(state['sessions'])}}
        at=round(time.monotonic()-self.host.started_at,3)
        if self.observations and self.observations[-1]['observation']==value:
            self.observations[-1]['lastObservedSeconds']=at
        else:
            self.observations.append({'firstObservedSeconds':at,'lastObservedSeconds':at,'observation':value})
            if len(self.observations)>24:self.observations.pop(0);self.observations_omitted+=1

    def start(self):
        require(not self.attempted and self.host.unit(SESSION)['LoadState'] == 'not-found', 'Synthetic PAM service already exists')
        before=self.host.snapshot()
        require(closed_snapshot(before), 'PAM observation needs proven cold account')
        self.attempted = True
        run(['/usr/bin/systemd-run','--unit='+SESSION,'--no-block','--collect',
             '--property=Type=exec','--property=User='+NAME,'--property=Group='+NAME,
             '--property=PAMName=login','--property=Restart=no','--property=RuntimeMaxSec=25',
             '--property=TimeoutStopSec=5','/usr/bin/sleep','15'])
        end=time.monotonic()+10
        while time.monotonic()<end:
            service=self.host.unit(SESSION);state=self.host.snapshot()
            self.record(service,state)
            if active(service) and active(state['manager']) and state['busPresent'] and state['sessions']:
                self.generation=service
                # Only the outer disposable harness owns this newly created
                # manager; the inner warm consumer does not acquire ownership.
                self.owned_manager=m=Lease(self.host)
                m.generation=state;m.owned=True;m.start_attempted=True
                return state
            time.sleep(.1)
        raise RuntimeError('PAM online deadline')

    def observe(self):
        before=self.start();calls=list(self.host.calls)
        warm=Lease(self.host);require(warm.acquire()=='WARM_REUSED','PAM manager not warm')
        require(warm.release()=='PREEXISTING_MANAGER_PRESERVED' and self.host.calls==calls,'PAM warm consumer mutated manager')
        end=time.monotonic()+25
        while time.monotonic()<end:
            state=self.host.snapshot()
            if cold(self.host.unit(SESSION)) and not state['sessions']:break
            time.sleep(.1)
        else:raise RuntimeError('PAM natural session end deadline')
        ended=time.monotonic();observations=[]
        for offset in (0,5,10,20,30):
            while time.monotonic()-ended<offset:
                self.host.deadline();time.sleep(.1)
            self.host.offline();state=self.host.snapshot()
            require(not state['sessions'],'Unexpected new PAM session')
            if active(state['manager']):
                require(stable_identity(state)==stable_identity(before),'PAM manager generation changed')
                self.host.online()
            else:require(cold(state['manager']),'PAM manager entered unknown state')
            observations.append({'afterSessionEndSeconds':round(time.monotonic()-ended,3),'state':state})
        return {'case':'pam-session-loss-observation','warmConsumerStartStopCalls':0,
                'initial':before,'observations':observations,
                'survived30Seconds':active(observations[-1]['state']['manager']),
                'managerHoldProven':False,'lingerChanged':False}

    def cleanup(self):
        require(not self.cleanup_attempted, 'PAM cleanup is single-attempt')
        self.cleanup_attempted = True
        require(not self.attempted or self.generation is not None, 'UNKNOWN_PAM_START_PRESERVED')
        current=self.host.unit(SESSION)
        if not cold(current):
            require(self.generation is not None and current==self.generation,'PAM service ownership unknown')
            run(['/usr/bin/systemctl','stop','--no-block',SESSION])
            end=time.monotonic()+10
            while time.monotonic()<end:
                if cold(self.host.unit(SESSION)) and not self.host.snapshot()['sessions']:break
                time.sleep(.1)
            else:raise RuntimeError('PAM cleanup deadline')
        if self.owned_manager is not None:
            state=self.host.snapshot()
            if cold(state['manager']):
                state=self.host.wait_stopped()
                require(state['coherent'] and state['bootId']==self.owned_manager.generation['bootId'] and not state['sessions'] and not state['processes'],'PAM manager disappeared with unexpected work')
                if not cold(state['runtime']):
                    require(state['runtime']==self.owned_manager.generation['runtime'],'PAM runtime-dir ownership changed')
                    self.host.stop_runtime();state=self.host.wait_stopped(runtime=True)
                require(closed_snapshot(state),'PAM runtime cleanup incomplete')
                self.owned_manager.owned=self.owned_manager.start_attempted=False
            else:self.owned_manager.release()


def create_account():
    require(not FIXTURE_HOME.exists() and not FIXTURE_HOME.is_symlink() and not Path('/run/user/16067').exists() and not Path('/run/user/16067').is_symlink(), 'Synthetic paths already exist')
    for database, key in ((pwd.getpwnam,NAME),(pwd.getpwuid,UID),(grp.getgrnam,NAME),(grp.getgrgid,UID)):
        try: database(key)
        except KeyError: continue
        raise RuntimeError('Synthetic account identifier already exists')
    require(cold(Host().unit(MANAGER)) and cold(Host().unit(RUNTIME)), 'Preexisting manager/runtime unit')
    run(['/usr/sbin/groupadd','--gid',str(UID),NAME])
    run(['/usr/sbin/useradd','--uid',str(UID),'--gid',str(UID),'--no-create-home','--home-dir',str(FIXTURE_HOME),'--shell','/usr/sbin/nologin',NAME])
    for path in (FIXTURE_HOME,FIXTURE_HOME/'.config',FIXTURE_HOME/'.config/systemd',CANARY.parent):
        path.mkdir(mode=0o700);os.chown(path,UID,UID)
    fd = os.open(CANARY,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:out.write(CANARY_TEXT.encode());out.flush();os.fsync(out.fileno());os.fchown(out.fileno(),UID,UID)


def remove_account(host):
    state = host.snapshot()
    require(closed_snapshot(state), 'Account cleanup requires confirmed cold state')
    host.offline()
    account = pwd.getpwnam(NAME)
    require((account.pw_uid,account.pw_gid,account.pw_dir)==(UID,UID,str(FIXTURE_HOME)), 'Account ownership changed')
    CANARY.unlink()
    for path in (CANARY.parent,FIXTURE_HOME/'.config/systemd',FIXTURE_HOME/'.config',FIXTURE_HOME):path.rmdir()
    run(['/usr/sbin/userdel',NAME])
    try: group = grp.getgrnam(NAME)
    except KeyError:group = None
    if group is not None:
        require(group.gr_gid == UID and not group.gr_mem, 'Group ownership changed')
        run(['/usr/sbin/groupdel',NAME])
    for database, key in ((pwd.getpwnam,NAME),(pwd.getpwuid,UID),(grp.getgrnam,NAME),(grp.getgrgid,UID)):
        try: database(key)
        except KeyError: continue
        raise RuntimeError('Synthetic account/group cleanup not confirmed')


def cleanup_owned(host, leases, created, creation_attempted, pam=None):
    errors=[]
    if creation_attempted and not created:errors.append('PARTIAL_OR_UNPROVED_SETUP_PRESERVED')
    if pam is not None:
        try:pam.cleanup()
        except BaseException as error:errors.append(str(error)[:500])
    for lease in reversed(leases):
        if lease.owned or lease.start_attempted:
            try:lease.release()
            except BaseException as error:errors.append(str(error)[:500])
    # A cold snapshot does not cancel an unacknowledged queued start/stop.
    # Preserve account and files after ANY unknown or rejected lease cleanup.
    if created and not errors:
        try:remove_account(host)
        except BaseException as error:errors.append(str(error)[:500])
    return {'status':'PASS' if not errors else 'FAIL','errors':errors}


def direct_cases(host,leases,result,source_hash):
    first=Lease(host);leases.append(first);require(first.acquire()=='COLD_STARTED','First cold branch')
    result['firstOnline']=first.generation;result['onlineCanary']=host.online()
    hold_start=time.monotonic()
    while time.monotonic()-hold_start<12:
        require(stable_identity(host.snapshot())==stable_identity(first.generation),'Direct manager did not survive no-session observation')
        host.offline();time.sleep(.2)
    result['directNoSessionObservedSeconds']=round(time.monotonic()-hold_start,3)
    result['indefiniteManagerHoldProven']=False
    # Deliberate local failure after the real online proof, not an invented
    # lost-ACK success. Cleanup must still own exactly this generation.
    try:raise RuntimeError('INJECTED_AFTER_ONLINE_PROOF')
    except RuntimeError:result['cases'].append({'case':'post-online-failure','cleanup':first.release()})
    result['firstStopped']=host.snapshot()
    second=Lease(host);leases.append(second);require(second.acquire()=='COLD_STARTED','Second cold branch')
    require(first.generation['manager']['InvocationID']!=second.generation['manager']['InvocationID'],'Manager restart did not change invocation')
    require(source_hash==host.offline(),'Static canary seal changed')
    result['secondOnline']=second.generation
    calls=list(host.calls);warm=Lease(host);require(warm.acquire()=='WARM_REUSED','Warm branch')
    require(warm.release()=='PREEXISTING_MANAGER_PRESERVED' and host.calls==calls,'Warm path mutated manager')
    result['cases'].append({'case':'warm-generation-preserved','mechanismStartStopCalls':0})
    result['cases'].append({'case':'cold-success-cleanup','cleanup':second.release()})


def run_phase(host,leases,result,source_hash,phase,pam):
    require(phase in ('all','pam-only'),'Exact supported fixture phase required')
    if phase=='all':direct_cases(host,leases,result,source_hash)
    else:result['directCases']='NOT_RUN_IN_PAM_ONLY'
    result['cases'].append(pam.observe());pam.cleanup()


def native(output,phase='all'):
    require(phase in ('all','pam-only'),'Exact supported fixture phase required')
    require(os.getuid()==0 and os.environ.get('CI')=='true' and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('RUN_USER_MANAGER_REPRO')=='yes', 'Disposable hosted-runner opt-in required')
    require(Path('/proc/1/comm').read_text().strip()=='systemd', 'Native systemd PID1 required')
    require(output.parent.resolve()==Path(__file__).resolve().parent and not output.exists(), 'Fresh local output directory required')
    output.mkdir(mode=0o755)
    host = Host();leases=[];created=False;creation_attempted=False;pam=None
    result={'schema':1,'scope':'SYNTHETIC_USER_MANAGER_ONLY' if phase=='all' else 'SYNTHETIC_PAM_SESSION_OBSERVATION_ONLY','phase':phase,'status':'FAIL','nativeTargetDistributionAcceptance':False,
            'versions':{'osRelease':Path('/etc/os-release').read_text(),'systemd':run(['/usr/bin/systemctl','--version'])[1], 'kernel':platform.release(),'machine':platform.machine()},'cases':[]}
    try:
        creation_attempted=True;create_account();created=True
        before=host.snapshot();require(not before['busPresent'],'Cold missing bus not reproduced')
        result['coldBefore']=before;source_hash=host.offline()
        pam=PamCase(host);run_phase(host,leases,result,source_hash,phase,pam)
        result['pamObservations']=pam.observations;result['pamObservationsOmitted']=pam.observations_omitted;pam=None
        result['sourceSha256']=source_hash;result['after']=host.snapshot();result['calls']=host.calls;result['status']='PASS'
    except BaseException as error:
        result['error']={'type':type(error).__name__,'message':str(error)[:1000]}
        try:result['failureState']=host.snapshot()
        except BaseException as read_error:result['failureStateReadError']=str(read_error)[:500]
    finally:
        host.cleaning = True
        signal.alarm(60)
        if pam is not None:
            result['pamObservations']=pam.observations;result['pamObservationsOmitted']=pam.observations_omitted
        result['cleanup']=cleanup_owned(host,leases,created,creation_attempted,pam)
        if result['cleanup']['status']!='PASS':result['status']='FAIL'
        result['stopObservations']=host.stop_observations
        result['stopObservationsOmitted']=host.stop_observations_omitted
        result['elapsedSeconds']=round(time.monotonic()-host.started_at,3)
        target=output/'result.json';target.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');target.chmod(0o644)
    return result['status']=='PASS'


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--phase',choices=('all','pam-only'),default='all');args=parser.parse_args()
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,lambda *_:(_ for _ in ()).throw(RuntimeError('Bounded experiment interrupted')))
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(RuntimeError('Experiment alarm')));signal.alarm(180)
    return 0 if native(args.output.absolute(),args.phase) else 1

if __name__=='__main__':raise SystemExit(main())
