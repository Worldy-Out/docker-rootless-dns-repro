#!/usr/bin/env python3
"""Disposable hosted-runner reproduction: sandboxed root to a user bus.

Standalone synthetic code. No application imports, container engine, IP
addresses, external requests, firewall changes or deployment credentials.
"""
import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import stat
import subprocess
import sys
import time

NAME='broker-manager-fixture'
UID=16064
FIXTURE_HOME=Path('/home')/NAME
WORK=Path('/run')/NAME
STATE=Path('/var/lib')/NAME
ETC=Path('/etc')/NAME
RUNTIME=Path('/run/user')/str(UID)
OTHER_RUNTIME=Path('/run/user')/str(UID+1)
ROOT_MARKER=Path('/root')/('.'+NAME)
MANAGER=f'user@{UID}.service'
RUNTIME_UNIT=f'user-runtime-dir@{UID}.service'
CAP_MASK=sum(1<<n for n in (1,2,6,7,12,24,29))
SURROGATE='''[Unit]
Description=Inert user service for a sandbox bus query
[Service]
Type=simple
ExecStart=/usr/bin/sleep 300
Restart=no
[Install]
WantedBy=default.target
'''
FIELDS=('LoadState','ActiveState','SubState','MainPID','InvocationID','ExecMainStartTimestampMonotonic')
CASES=('original','session_only','bound','missing','foreign')
PRIVATE=RUNTIME/'systemd/private'
CONNECT_MISSING='Failed to connect to user scope bus via local transport: No such file or directory\n'


def need(ok,message):
    if not ok:raise RuntimeError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def write_new(path,raw,mode=0o600,owner=None):
    data=raw.encode()if isinstance(raw,str)else raw
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb')as stream:
        os.fchmod(stream.fileno(),mode)
        if owner is not None:os.fchown(stream.fileno(),owner,owner)
        stream.write(data);stream.flush();os.fsync(stream.fileno())
        s=os.fstat(stream.fileno())
    return {'device':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'sha256':sha(data)}


def run(argv,timeout=20,allowed=(0,)):
    child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'},start_new_session=True)
    try:out,err=child.communicate(timeout=timeout)
    except BaseException:
        try:os.killpg(child.pid,signal.SIGTERM)
        except ProcessLookupError:pass
        try:child.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            child.communicate(timeout=3)
        raise
    need(len(out)<=65536 and len(err)<=65536,'Bounded fixed-command output exceeded')
    need(child.returncode in allowed,'Fixed command failed: '+Path(argv[0]).name+' exit '+str(child.returncode))
    return {'exit':child.returncode,'stdout':out.decode(),'stderr':err.decode()}


def properties(unit):
    raw=run(['systemctl','show',unit,*['--property='+k for k in FIELDS]])['stdout']
    pairs=[line.split('=',1)for line in raw.splitlines()]
    need(len(pairs)==len(FIELDS)and all(len(p)==2 for p in pairs),'Incomplete unit readback')
    value=dict(pairs);need(set(value)==set(FIELDS),'Unknown unit properties');return value


def service_inventory():
    # An unfiltered successful inventory avoids treating an unmatched glob's
    # nonzero exit status as proof of absence on different systemd versions.
    raw=run(['systemctl','list-units','--all','--type=service','--plain','--no-legend','--no-pager'])['stdout']
    rows={}
    for line in raw.splitlines():
        fields=line.split(None,4)
        need(len(fields)==5 and fields[0].endswith('.service')and fields[0]not in rows,'Malformed service inventory')
        rows[fields[0]]=fields[1:]
    need(bool(rows),'Empty system service inventory');return rows


def active(value):
    return value['LoadState']=='loaded'and value['ActiveState']=='active'and value['SubState']=='running'and \
        value['MainPID'].isdigit()and int(value['MainPID'])>0 and re.fullmatch('[a-f0-9]{32}',value['InvocationID'])is not None


def inactive(value):return value['ActiveState']=='inactive'and value['MainPID']=='0'


def identity(value):
    need(active(value),'User manager is not a known active generation')
    return {k:value[k]for k in ('MainPID','InvocationID','ExecMainStartTimestampMonotonic')}


def socket_metadata(kind='private',directory=RUNTIME,namespace=False):
    need(kind in ('session','private'),'Unknown socket kind')
    path=directory/('bus'if kind=='session'else'systemd/private')
    try:
        parents=[directory]if kind=='session'else[directory,directory/'systemd']
        stats=[p.lstat()for p in parents];endpoint=path.lstat()
    except FileNotFoundError:return {'available':False,'reason':'MISSING'}
    except PermissionError:return {'available':False,'reason':'INACCESSIBLE'}
    if any(p.is_symlink()for p in [*parents,path]):return {'available':False,'reason':'SYMLINK'}
    def fields(x):return {'uid':x.st_uid,'gid':x.st_gid,'mode':stat.S_IMODE(x.st_mode),'device':x.st_dev,'inode':x.st_ino}
    result={'parents':[fields(x)for x in stats],'socket':fields(endpoint),'available':True,'reason':'OBSERVED'}
    if namespace:
        parents_ok=all(stat.S_ISDIR(x.st_mode)and x.st_uid==x.st_gid==0 and not x.st_mode&0o022 for x in stats)
    else:
        parents_ok=all(stat.S_ISDIR(x.st_mode)and x.st_uid==x.st_gid==UID and not x.st_mode&0o022 and x.st_mode&0o100 for x in stats)
        parents_ok=parents_ok and stat.S_IMODE(stats[0].st_mode)==0o700
    if not parents_ok:result.update(available=False,reason='FOREIGN_DIRECTORY')
    elif not stat.S_ISSOCK(endpoint.st_mode)or(endpoint.st_uid,endpoint.st_gid,stat.S_IMODE(endpoint.st_mode))!=(UID,UID,0o666 if kind=='session'else 0o700):
        result.update(available=False,reason='FOREIGN_SOCKET')
    return result


def bus_metadata(directory=RUNTIME,namespace=False):
    return socket_metadata('private',directory,namespace)


def user_prefix():
    return ['runuser','-u',NAME,'--','env','-i','PATH=/usr/sbin:/usr/bin:/sbin:/bin',
            'XDG_RUNTIME_DIR='+str(RUNTIME),'DBUS_SESSION_BUS_ADDRESS=unix:path='+str(RUNTIME/'bus'),
            'systemctl','--user']


def user_query():
    return user_prefix()+['show','docker.service','--property=LoadState','--property=ActiveState',
            '--property=MainPID','--property=UnitFileState','--property=ExecMainStartTimestampMonotonic']


def user_stop():return user_prefix()+['stop','docker.service']


def stopped_response(row):
    pairs=[x.split('=',1)for x in row['stdout'].splitlines()]
    return row['exit']==0 and len(pairs)==5 and all(len(x)==2 for x in pairs)and dict(pairs)=={
        'LoadState':'loaded','ActiveState':'inactive','MainPID':'0','UnitFileState':'disabled',
        'ExecMainStartTimestampMonotonic':'0'}


def sandbox(case):
    need(case in CASES,'Unknown synthetic case')
    props={'Type':'exec','Group':'root','UMask':'0077','NoNewPrivileges':'yes','ProtectSystem':'strict',
        'ReadWritePaths':f'/run {STATE} {ETC}','ProtectHome':'yes'if case=='original'else'tmpfs',
        'PrivateTmp':'yes','ProtectControlGroups':'yes','RestrictAddressFamilies':'AF_UNIX AF_NETLINK AF_INET AF_INET6',
        'CapabilityBoundingSet':'CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_SYS_RESOURCE CAP_AUDIT_WRITE',
        'Restart':'no','TimeoutStartSec':'25','RuntimeMaxSec':'25','KillMode':'control-group',
        'LimitNOFILE':'256','TasksMax':'32','MemoryMax':'128M'}
    if case=='session_only':props['BindReadOnlyPaths']=str(RUNTIME/'bus')
    if case=='bound':props['BindReadOnlyPaths']=str(PRIVATE)
    if case in ('missing','foreign'):
        props['BindReadOnlyPaths']=('-'if case=='missing'else'')+str(WORK/(case+'-runtime/private'))+':'+str(PRIVATE)
    return props


def security():
    fields={x.split(':',1)[0]:x.split(':',1)[1].strip()for x in Path('/proc/self/status').read_text().splitlines()if ':'in x}
    need(os.geteuid()==0 and fields['NoNewPrivs']=='1'and int(fields['CapEff'],16)==CAP_MASK and
         int(fields['CapBnd'],16)==CAP_MASK and int(fields['CapAmb'],16)==0,'Sandbox process security differs')
    return {k:fields[k]for k in ('NoNewPrivs','CapEff','CapBnd','CapAmb')}


def effective_sandbox(case,runner):
    keys=('User','Group','NoNewPrivileges','ProtectSystem','ProtectHome','PrivateTmp','ProtectControlGroups',
          'RestrictAddressFamilies','CapabilityBoundingSet','AmbientCapabilities','ReadWritePaths',
          'BindReadOnlyPaths','Restart','RuntimeMaxUSec','KillMode')
    raw=runner(['systemctl','show',NAME+'-'+case+'.service',*['--property='+k for k in keys]],timeout=8)['stdout']
    pairs=[line.split('=',1)for line in raw.splitlines()]
    need(len(pairs)==len(keys)and all(len(p)==2 for p in pairs),'Incomplete sandbox readback')
    value=dict(pairs);need(set(value)==set(keys),'Unknown sandbox fields')
    exact={'User':'','Group':'root','NoNewPrivileges':'yes','ProtectSystem':'strict',
           'ProtectHome':'yes'if case=='original'else'tmpfs','PrivateTmp':'yes','ProtectControlGroups':'yes',
           'AmbientCapabilities':'','Restart':'no','RuntimeMaxUSec':'25s','KillMode':'control-group'}
    need(all(value[k]==v for k,v in exact.items()),'Effective sandbox differs')
    want=sandbox(case)
    for name in ('ReadWritePaths','RestrictAddressFamilies','CapabilityBoundingSet'):
        need(sorted(value[name].lower().split())==sorted(want[name].lower().split()),'Effective sandbox scope differs')
    # Preserve systemd's complete presentation. Exact bind authority is proved
    # independently by the kernel mountpoint, read-only flag, original socket
    # device/inode/owner/mode and the otherwise empty namespace directory.
    # No cross-version string-format normalization is treated as authority.
    need(bool(value['BindReadOnlyPaths'])==(case!='original'),'Read-only bind presence differs')
    return value


def missing_error(reply):
    return reply['exit']==1 and reply['stdout']=='' and reply['stderr']==CONNECT_MISSING


def inside(case,runner=run):
    need(case in CASES,'Unknown probe')
    observed=bus_metadata(namespace=case!='original');sec=security()
    session=socket_metadata('session',namespace=case!='original')
    mount_rows=[line.split()for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    mounts=[r for r in mount_rows if len(r)>6 and r[4]==str(PRIVATE)]
    only_private=(sorted(p.name for p in RUNTIME.iterdir())==['systemd']and
                  sorted(p.name for p in (RUNTIME/'systemd').iterdir())==['private'])if observed['available']else False
    row={'case':case,'security':sec,'effectiveSandbox':effective_sandbox(case,runner),'bus':observed,
         'sessionBus':session,'homeHidden':not FIXTURE_HOME.exists(),
         'rootMarkerHidden':not ROOT_MARKER.exists(),'otherRuntimeHidden':not OTHER_RUNTIME.exists(),
         'socketMountReadOnly':len(mounts)==1 and 'ro'in mounts[0][5].split(','),
         'onlySocketVisible':only_private,'queryExecuted':False,'inertStopAttempted':False}
    if case in ('missing','foreign')and not observed['available']:
        row.update(status='REJECTED_BEFORE_USER_QUERY',reason=observed['reason']);return row
    reply=runner(user_query(),timeout=8,allowed=(0,1))
    row.update(queryExecuted=True,queryExit=reply['exit'],queryStderrSha256=sha(reply['stderr'].encode()),
               queryStderrBytes=len(reply['stderr'].encode()),queryFields=reply['stdout'].splitlines(),
               exactMissingPrivateSocketError=missing_error(reply))
    row['status']='STOPPED_QUERY_CONFIRMED'if stopped_response(reply)else'QUERY_REJECTED'
    if case=='bound'and stopped_response(reply):
        row['inertStopAttempted']=True
        stop=runner(user_stop(),timeout=8,allowed=(0,1))
        row['inertStop']={'exit':stop['exit'],'stdoutBytes':len(stop['stdout'].encode()),
                          'stderrBytes':len(stop['stderr'].encode())}
        need(stop=={'exit':0,'stdout':'','stderr':''},'Fixed inert stop failed')
        after=runner(user_query(),timeout=8,allowed=(0,1))
        row['afterInertStopFields']=after['stdout'].splitlines()
        need(stopped_response(after),'Inert surrogate started or changed after stop')
        row['inertStopConfirmedNeverStarted']=True
    return row


def check_case(case,row):
    need(row['case']==case and all(row[k]is True for k in ('homeHidden','rootMarkerHidden','otherRuntimeHidden')),
         'Probe identity/home isolation differs')
    if case in ('original','session_only'):
        need(row['status']=='QUERY_REJECTED'and row['queryExecuted']is True and row['queryExit']==1 and
             row['exactMissingPrivateSocketError']is True and row['queryStderrBytes']==len(CONNECT_MISSING.encode())and
             row['queryStderrSha256']==sha(CONNECT_MISSING.encode())and row['queryFields']==[]and
             row['bus']['available']is False and row['bus']['reason']in('MISSING','INACCESSIBLE')and
             row['inertStopAttempted']is False,'Missing private socket did not prove exact connect error')
        if case=='session_only':need(row['sessionBus']['available']is True,'Session-only comparison lacks session bus')
        else:need(row['sessionBus']['available']is False,'Original exposed session bus')
    elif case=='bound':
        need(row['status']=='STOPPED_QUERY_CONFIRMED'and row['queryExecuted']is True and row['bus']['available']is True and
             row['socketMountReadOnly']is True and row['onlySocketVisible']is True and
             row['sessionBus']['available']is False and row['inertStopAttempted']is True and
             row['inertStopConfirmedNeverStarted']is True,'Bound private socket did not prove inactive surrogate/stop')
    else:
        need(row['status']=='REJECTED_BEFORE_USER_QUERY'and row['queryExecuted']is False and
             row['inertStopAttempted']is False and
             row['reason']==('MISSING'if case=='missing'else'FOREIGN_SOCKET'),'Negative private socket not rejected before command')


def native_versions():
    client=run(['systemctl','--version'])['stdout'].splitlines()[0]
    manager=run(['systemctl','show','--property=Version','--value'])['stdout'].strip()
    os_release=Path('/etc/os-release').read_text()
    need(re.match(r'^systemd 259(?:[ .(]|$)',client)is not None and
         re.match(r'^259(?:[.\-]|$)',manager)is not None,'Native systemd 259 client AND PID1 required')
    need('ID=ubuntu' in os_release.splitlines()and 'VERSION_ID="26.04"'in os_release.splitlines(),
         'Native Ubuntu 26.04 required')
    return {'systemdClient':client,'systemdManager':manager,'kernel':run(['uname','-sr'])['stdout'].strip(),
            'python':sys.version.split()[0],'exact2595NativeClaimed':False}


def hosted_guard():
    need(os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('CI')=='true'and
         os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted'and os.environ.get('RUN_BROKER_MANAGER_REPRO')=='yes',
         'Explicit disposable GitHub-hosted runner opt-in required')
    need(sys.platform=='linux'and Path('/proc/1/comm').read_text().strip()=='systemd'and
         Path('/run/systemd/system').is_dir(),'Native systemd PID1 required')


def require_unused():
    for get,key in ((pwd.getpwnam,NAME),(pwd.getpwuid,UID),(grp.getgrnam,NAME),(grp.getgrgid,UID)):
        try:get(key)
        except KeyError:continue
        raise RuntimeError('Synthetic account identity already exists')
    for p in (FIXTURE_HOME,WORK,STATE,ETC,RUNTIME,OTHER_RUNTIME,ROOT_MARKER):need(not os.path.lexists(p),'Pre-existing fixture path')
    for unit in (MANAGER,RUNTIME_UNIT):need(inactive(properties(unit)),'Pre-existing user manager/runtime')
    need(run(['pgrep','-u',str(UID)],allowed=(0,1))['exit']==1,'Pre-existing UID process')
    need(not any(n.startswith(NAME+'-')for n in service_inventory()),'Pre-existing probe service')


def wait_ready(timeout=25):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        first=properties(MANAGER);bus=bus_metadata();second=properties(MANAGER)
        if first==second and active(first)and bus['available']and socket_metadata('session')['available']:
            return {'manager':identity(first),'bus':bus}
        time.sleep(.2)
    raise RuntimeError('Fresh manager/bus readiness deadline')


def wait_closed(timeout=30):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        manager=properties(MANAGER);runtime=properties(RUNTIME_UNIT)
        process=run(['pgrep','-u',str(UID)],allowed=(0,1))
        if inactive(manager)and inactive(runtime)and not os.path.lexists(RUNTIME)and process['exit']==1:
            return {'managerInactive':True,'runtimeInactive':True,'runtimePathAbsent':True,'uidProcessesAbsent':True}
        time.sleep(.2)
    raise RuntimeError('Owned manager cleanup not fully confirmed')


def file_owned(path,pin):
    s=path.lstat()
    need(stat.S_ISREG(s.st_mode)and not path.is_symlink()and s.st_nlink==1 and
         (s.st_dev,s.st_ino)==(pin['device'],pin['inode'])and sha(path.read_bytes())==pin['sha256'],
         'Owned fixture file changed')
    need((s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(pin['uid'],pin['gid'],pin['mode']),'Owned file permissions changed')


def cleanup(created):
    report={'status':'FAIL','preserved':True}
    try:
        need(created.get('setupComplete')is True,'Partial setup preserved')
        need(created.get('managerGeneration')is not None,'Unknown manager start outcome preserved')
        need(not created.get('stopAttempted')or created.get('stopConfirmed')is True,'Unknown stop outcome preserved')
        current=properties(MANAGER)
        if active(current):
            need(identity(current)==created['managerGeneration'],'Foreign manager generation preserved')
            need(not created.get('stopAttempted'),'Stop already attempted; no retry')
            created['stopAttempted']=True;run(['systemctl','stop',MANAGER],timeout=35)
        report['managerClosed']=wait_closed();created['stopConfirmed']=True
        inventory=service_inventory()
        for unit in created['probeUnits']:
            if unit in inventory:
                value=properties(unit)
                need(value['MainPID']=='0'and value['ActiveState']in('inactive','failed'),'Synthetic probe remains running')
        probe_process=run(['pgrep','-f',str(WORK/'probe.py')],allowed=(0,1))
        need(probe_process['exit']==1,'Synthetic probe process remains')
        for path,pin in created['files'].items():file_owned(path,pin)
        for path,pin in created['directories'].items():
            s=path.lstat();need(stat.S_ISDIR(s.st_mode)and not path.is_symlink()and
                               (s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==pin,
                               'Fixture directory replaced')
        need(pwd.getpwnam(NAME).pw_uid==UID and pwd.getpwnam(NAME).pw_gid==UID,'Account identity changed')
        need(not os.path.lexists(Path('/var/lib/systemd/linger')/NAME),'Unexpected linger preserved')
        if created.get('foreignSocket'):
            p=WORK/'foreign-runtime/private';s=p.lstat()
            need(stat.S_ISSOCK(s.st_mode)and(s.st_dev,s.st_ino)==created['foreignSocket'],'Foreign socket identity changed')
            p.unlink()
        for path in sorted(created['files'],key=lambda p:len(p.parts),reverse=True):path.unlink()
        for path in sorted(created['directories'],key=lambda p:len(p.parts),reverse=True):path.rmdir()
        # userdel can remove a same-name private group itself. Confirm identity
        # before deletion and accept only verified absence afterward.
        run(['userdel',NAME])
        try:g=grp.getgrnam(NAME)
        except KeyError:g=None
        if g is not None:
            need(g.gr_gid==UID,'Group identity changed');run(['groupdel',NAME])
        for get,key in ((pwd.getpwnam,NAME),(pwd.getpwuid,UID),(grp.getgrnam,NAME),(grp.getgrgid,UID)):
            try:get(key)
            except KeyError:continue
            raise RuntimeError('Synthetic identity remained after cleanup')
        report.update(status='PASS',preserved=False,accountAbsent=True,ownedFilesAbsent=True)
    except BaseException as error:report['error']=str(error)[:300]
    return report


def native(output):
    hosted_guard();versions=native_versions();require_unused()
    need(not os.path.lexists(output)and not any(p.is_symlink()for p in(output,*output.parents)),'New output directory required')
    output.mkdir(mode=0o755);output.chmod(0o755)
    created={'files':{},'directories':{},'probeUnits':[],'setupComplete':False,'managerGeneration':None,'stopAttempted':False}
    result={'schema':1,'scope':'SYNTHETIC_SYSTEMD259_PRIVATE_MANAGER_SOCKET','status':'FAIL','cases':{},'engineStarts':0,
            'surrogateStarts':0,'externalNetworkRequests':0,'productionAcceptanceClaimed':False,'probeTransport':{},
            'versions':versions}
    started=time.monotonic();foreign=None
    def expired(*_):raise TimeoutError('Synthetic scenario deadline')
    signal.signal(signal.SIGALRM,expired);signal.alarm(300)
    def directory(path,owner=0,mode=0o700):
        path.mkdir(mode=mode);os.chown(path,owner,owner);path.chmod(mode);s=path.lstat()
        created['directories'][path]=(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))
    try:
        run(['groupadd','--gid',str(UID),NAME]);run(['useradd','--uid',str(UID),'--gid',str(UID),
            '--no-create-home','--home-dir',str(FIXTURE_HOME),'--shell','/usr/sbin/nologin','--no-log-init',NAME])
        for path in (WORK,STATE,ETC):directory(path)
        directory(OTHER_RUNTIME)
        created['files'][OTHER_RUNTIME/'marker']=write_new(OTHER_RUNTIME/'marker',b'synthetic hidden marker\n')
        created['files'][ROOT_MARKER]=write_new(ROOT_MARKER,b'synthetic hidden marker\n')
        for path in (FIXTURE_HOME,FIXTURE_HOME/'.config',FIXTURE_HOME/'.config/systemd',FIXTURE_HOME/'.config/systemd/user'):directory(path,UID)
        unit=FIXTURE_HOME/'.config/systemd/user/docker.service';created['files'][unit]=write_new(unit,SURROGATE,0o600,owner=UID)
        script=WORK/'probe.py';created['files'][script]=write_new(script,Path(__file__).read_bytes())
        for name in ('missing-runtime','foreign-runtime'):directory(WORK/name,UID)
        foreign=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);foreign.bind(str(WORK/'foreign-runtime/private'))
        os.chmod(WORK/'foreign-runtime/private',0o700);s=(WORK/'foreign-runtime/private').lstat()
        created['foreignSocket']=(s.st_dev,s.st_ino);created['setupComplete']=True
        # Exactly one conditional fresh manager activation; no early linger,
        # no login, no manager unit/drop-in or default-target modifications.
        created['startAttempted']=True;run(['systemctl','start',MANAGER],timeout=35)
        ready=wait_ready();created['managerGeneration']=ready['manager'];result['managerBefore']=ready
        session=socket_metadata('session');need(session['available'],'Actual session comparison socket missing')
        result['sessionSocketBefore']=session
        user_version=run(user_prefix()+['show','--property=Version','--value'])['stdout'].strip()
        need(re.match(r'^259(?:[.\-]|$)',user_version)is not None,'User manager must be version259')
        result['versions']['userManager']=user_version
        need(stopped_response(run(user_query(),timeout=8,allowed=(0,1))),'Outside sandbox baseline query failed')
        for case in CASES:
            need(identity(properties(MANAGER))==created['managerGeneration'],'Manager changed between probes')
            need(bus_metadata()==ready['bus']and socket_metadata('session')==session,'Host socket identity changed between probes')
            file_owned(script,created['files'][script]);file_owned(unit,created['files'][unit])
            unit_name=NAME+'-'+case+'.service';created['probeUnits'].append(unit_name)
            argv=['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit_name,
                  '--setenv=BROKER_MANAGER_INSIDE=yes']
            for key,value in sandbox(case).items():argv+=['--property='+key+'='+value]
            argv+=['/usr/bin/python3','-I','-S','-B',str(script),'--inside',case]
            reply=run(argv,timeout=35,allowed=tuple(range(256)))
            result['probeTransport'][case]={'exit':reply['exit'],**{
                stream:{'bytes':len(reply[stream].encode()),'sha256':sha(reply[stream].encode()),
                        'diagnostic':reply[stream][-4000:]if reply['exit']else None}
                for stream in ('stdout','stderr')}}
            need(reply['exit']==0,'Native synthetic probe failed: '+case)
            row=json.loads(reply['stdout'])
            result['cases'][case]=row;check_case(case,row)
            if case=='bound':need(row['bus']['socket']==ready['bus']['socket'],'Bound socket is not the actual held host private socket')
            if case=='session_only':need(row['sessionBus']['socket']==session['socket'],'Session socket identity differs')
            need(stopped_response(run(user_query(),timeout=8,allowed=(0,1))),'Outside sandbox service changed')
        result['managerAfter']=wait_ready();need(result['managerAfter']==ready,'Manager/private socket changed during probes')
        result['sessionSocketAfter']=socket_metadata('session');need(result['sessionSocketAfter']==session,'Session socket changed')
        created['stopAttempted']=True;run(['systemctl','stop',MANAGER],timeout=35)
        result['stoppedManager']=wait_closed()
        created['stopConfirmed']=True
        need(bus_metadata()=={'available':False,'reason':'MISSING'},'Stopped manager bus unexpectedly available')
        result['cases']['manager_stopped_bus_absent']={'status':'PASS','queryAttempted':False,'managerRestarted':False}
        result['status']='PASS'
    except BaseException as error:result['error']={'type':type(error).__name__,'reason':str(error)[:500]}
    finally:
        signal.alarm(90)
        if foreign is not None:foreign.close()
        result['cleanup']=cleanup(created)
        signal.alarm(0)
        if result['cleanup']['status']!='PASS':result['status']='FAIL'
        result['elapsedSeconds']=round(time.monotonic()-started,3)
        result['managerStartsAttempted']=int(created.get('startAttempted',False))
        result['managerStopsAttempted']=int(created['stopAttempted'])
        write_new(output/'result.json',json.dumps(result,sort_keys=True,indent=2)+'\n',0o644)
    print(json.dumps({'status':result['status'],'cases':len(result['cases']),'cleanup':result['cleanup']['status']}))
    return 0 if result['status']=='PASS'else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside',choices=CASES);parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.inside:
        need(os.geteuid()==0 and os.environ.get('BROKER_MANAGER_INSIDE')=='yes'and
             Path(__file__)==WORK/'probe.py','Only the owned native transient probe may use inside mode')
        print(json.dumps(inside(args.inside),sort_keys=True))
    else:
        need(args.output is not None,'Output directory required');sys.exit(native(args.output.absolute()))
