"""Disposable GitHub-hosted Ubuntu 26.04 acceptance of the standby mechanisms."""

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
import time

import broker
import native_repro as docker
from native_standby_fixture import EPOCH, HOME, POLICY, ROOT
import network_policy as network
import standby_service as service


HERE = Path(__file__).resolve().parent
RUN = Path('/run/standby-native')
LIB = service.RELEASE
SERVER = 'standby-native-server'
CLIENT = 'standby-native-client'
UID = 1002
UNIT_PATH = Path('/etc/systemd/system')
PEER = ['ip','netns','exec',CLIENT]
HOST = ['ip','netns','exec',SERVER]
MODULES = ['standby_service.py','standby_window.py','root_helper.py','broker.py','network_policy.py','native_standby_fixture.py']


def require(ok, name):
    if not ok:
        raise RuntimeError(name)


def run(*args, data=None, timeout=20, check=True):
    result = subprocess.run(args,input=data,capture_output=True,text=True,timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f'{args[0]} exit {result.returncode}: {result.stderr[-500:]}')
    return result


RPC = '''import json,socket,sys
with socket.socket(socket.AF_UNIX) as peer:
 peer.settimeout(40);peer.connect(sys.argv[1]);peer.sendall(sys.argv[2].encode()+b"\\n");peer.shutdown(socket.SHUT_WR)
 print(peer.makefile().readline().strip())
'''
ECHO = '''import socket,threading
def echo(peer):
 with peer:
  while data:=peer.recv(1024):peer.sendall(data)
with socket.socket() as service:
 service.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 service.bind(("11.77.0.1",443));service.listen()
 print("READY",flush=True)
 while True:threading.Thread(target=echo,args=(service.accept()[0],),daemon=True).start()
'''
CLIENT_CODE = '''import socket,sys
with socket.socket() as peer:
 peer.settimeout(.55);peer.bind((sys.argv[1],0))
 try:peer.connect(("11.77.0.1",int(sys.argv[2])))
 except TimeoutError:print("TCP_BLOCKED",flush=True);raise SystemExit(0)
 print("TCP_CONNECTED",flush=True)
 for data in sys.stdin:
  data=data.rstrip().encode()
  try:
   peer.sendall(data);response=peer.recv(1024)
   print("ECHO" if response==data else "WRONG",flush=True)
  except TimeoutError:print("NO_BYTES",flush=True)
'''


def rpc(message, *, endpoint=service.CONTROL):
    result = run('runuser','-u','uzel-runtime','--','/usr/bin/python3','-I','-B','-c',RPC,str(endpoint),json.dumps(message),check=False)
    return json.loads(result.stdout) if result.stdout.strip() else None


def command(action,data=None):
    state = rpc({'action':'status'})
    request = {'action':action,'data':data,'generation':state['generation'],'sequence':state['sequence']+1}
    return request,rpc(request)


def proc_client():
    child = subprocess.Popen([*PEER,'/usr/bin/python3','-B','-u','-c',CLIENT_CODE,'11.77.0.2','443'],
                             stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    require(child.stdout.readline().strip()=='TCP_CONNECTED','Approved client could not connect')
    return child


def push(child, value, expected):
    child.stdin.write(value+'\n');child.stdin.flush()
    require(child.stdout.readline().strip()==expected,'Established data plane differs: '+expected)


def fresh(source='11.77.0.2', port='443'):
    return run(*PEER,'/usr/bin/python3','-B','-c',CLIENT_CODE,source,port,data='probe\n',timeout=3).stdout.splitlines()


def gate_file():
    return json.loads((ROOT/'state.json').read_text())


def await_until(test, seconds, why):
    deadline = time.monotonic()+seconds
    while time.monotonic()<deadline:
        if test():
            return
        time.sleep(.2)
    require(False,why)


def broker_fixture():
    for path in (RUN,ROOT,LIB,Path('/etc/uzel-standby'),HOME):
        require(not path.exists(),'Existing fixture path: '+str(path))
    for name in (service.UNIT,*broker.systemd_units(UID)):
        require(not (UNIT_PATH/name).exists(),'Existing unit: '+name)
    run('groupadd','--gid',str(UID),'uzel-runtime')
    run('useradd','-M','-l','-u',str(UID),'-g',str(UID),'-d',str(HOME.parent),'-s','/bin/bash','uzel-runtime')
    run('usermod','-p','x','uzel-runtime')
    for path in (RUN,ROOT,LIB,Path('/etc/uzel-standby'),HOME):
        path.mkdir(parents=True,mode=0o755)
    Path('/etc/wireguard').mkdir(mode=0o700,exist_ok=True)
    Path('/var/lib/uzel-ops').mkdir(mode=0o700,exist_ok=True)
    ROOT.chmod(0o700)
    HOME.chmod(0o700);os.chown(HOME,UID,UID);os.chown(HOME.parent,UID,UID)
    Path('/etc/uzel-role').write_text('dp-a\n')
    key = Path('/etc/uzel-standby/peer.key');key.write_bytes(secrets.token_bytes(32));key.chmod(0o600)
    for name in MODULES:
        shutil.copyfile(HERE/name,LIB/name);(LIB/name).chmod(0o644)
    run('ip','netns','add',SERVER);run('ip','netns','add',CLIENT)
    run('ip','link','add','cienp0','netns',SERVER,'type','veth','peer','name','cienp1','netns',CLIENT)
    for namespace,ifname,ips in ((HOST,'cienp0',('11.77.0.1/24',)),(PEER,'cienp1',('11.77.0.2/24','11.77.0.3/24'))):
        for address in ips:
            run(*namespace,'ip','addr','add',address,'dev',ifname)
        run(*namespace,'ip','link','set',ifname,'up')
        run(*namespace,'ip','link','set','lo','up')
    run(*HOST,'nft','-f','-',data=network.nft_rules(POLICY))
    table = json.loads(run(*HOST,'nft','-j','list','table','inet',network.TABLE).stdout)
    state = {'schema':1,'role':'dp-a','epoch':EPOCH,'phase':'ACTIVE','bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
             'leaseRevision':0,'tableSnapshot':network.stable_table(table,POLICY),'lastControlAt':time.monotonic(),'testWindow':None}
    path=ROOT/'state.json';path.write_text(json.dumps(state));path.chmod(0o600)
    unit = service.units(UID)[service.UNIT].replace(' -B /usr/local/lib/uzel-standby/standby_service.py',
        ' -B -E /usr/local/lib/uzel-standby/native_standby_fixture.py service').replace(' -I -B -E ',' -B -E ')
    (UNIT_PATH/service.UNIT).write_text(unit)
    for name,body in broker.systemd_units(UID).items():
        if name.endswith('.service'):
            body = body.replace(' -I -B /usr/local/lib/uzel-ops/root_helper.py',
                ' -B -E /usr/local/lib/uzel-standby/native_standby_fixture.py')
            body = body.replace('[Service]\n',f'[Service]\nNetworkNamespacePath=/run/netns/{SERVER}\n',1)
        (UNIT_PATH/name).write_text(body)
    run('systemctl','daemon-reload');run('loginctl','enable-linger','uzel-runtime')
    run('systemctl','start',f'user@{UID}.service','uzel-ops.socket','uzel-ops-watchdog.timer',service.UNIT)
    await_until(service.CONTROL.is_socket,10,'Fixed service socket did not appear')


def ssh_start():
    path = RUN/'sshd_config'
    identity = RUN/'operator'
    host = RUN/'host'
    for key in (identity,host):
        run('ssh-keygen','-t','ed25519','-q','-N','','-f',str(key))
    authorized = HOME/'.authorized_keys';authorized.write_text(identity.with_suffix('.pub').read_text());os.chown(authorized,UID,UID);authorized.chmod(0o600)
    path.write_text(f'ListenAddress 127.0.0.1\nPort 22220\nHostKey {host}\nAuthorizedKeysFile {authorized}\n'
                    'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n'
                    'AllowUsers uzel-runtime\nUsePAM yes\nPidFile /run/standby-native/sshd.pid\n')
    daemon = subprocess.Popen(['/usr/sbin/sshd','-D','-e','-f',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        state = rpc({'action':'status'})
        spec = json.dumps({'action':'start','generation':state['generation'],'sequence':1,'data':None})
        import shlex
        ssh = ['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={RUN}/known_hosts',
               '-o','ConnectTimeout=2','-i',str(identity),'-p','22220','uzel-runtime@127.0.0.1']
        (RUN/'known_hosts').write_text('[127.0.0.1]:22220 '+host.with_suffix('.pub').read_text())
        await_until(lambda:daemon.poll() is not None or ':22220' in run('ss','-H','-ltn').stdout,5,'Local test sshd unavailable')
        remote = shlex.join(['/usr/bin/python3','-I','-B','-c',RPC,str(service.CONTROL),spec])
        result = json.loads(run(*ssh,remote).stdout)
        pid = run('systemctl','show','-p','MainPID','--value',service.UNIT).stdout.strip()
        daemon.terminate();daemon.wait(timeout=5)
        time.sleep(4.5)
        require(result['result']['status']=='STANDBY' and pid.isdigit() and pid!='0' and
                run('systemctl','show','-p','MainPID','--value',service.UNIT).stdout.strip()==pid and
                rpc({'action':'status'})['running'] and daemon.poll() is not None,'Service did not survive SSH exit')
        return pid
    finally:
        if daemon.poll() is None:
            daemon.terminate();daemon.wait(timeout=5)


def kernel_cases(results):
    broker_fixture()
    pid = ssh_start()
    require(rpc({'action':'window_status'},endpoint=broker.SOCKET) is None,'Same UID outside service cgroup reached broker')
    results['nativeLifecycle'] = {'status':'PASS','samePidAfterSsh':pid,'brokerDeniedSameUidOutsideCgroup':True}
    with subprocess.Popen([*HOST,'/usr/bin/python3','-B','-u','-c',ECHO],stdout=subprocess.PIPE,text=True) as server:
        try:
            require(server.stdout.readline().strip()=='READY','Synthetic listener unavailable')
            require(fresh()==['TCP_BLOCKED'],'Closed baseline unexpectedly admits connections')
            request,first = command('window-open',150)
            require(first and first['result']['status']=='TEST_WINDOW','First test window failed')
            require(rpc(request)==first,'Replay did not return original ACK')
            require(command('window-open',150)[1]['status']=='BLOCKED','Second simultaneous window accepted')
            require(fresh('11.77.0.3')==['TCP_BLOCKED'] and fresh(port='8443')==['TCP_BLOCKED'],'Scope expanded')
            with proc_client() as child:
                try:
                    push(child,'before-renew','ECHO')
                    initial = first['result']['gate']['leaseRevision']
                    await_until(lambda:gate_file()['leaseRevision']>initial,12,'On-host lease did not renew')
                    push(child,'after-renew','ECHO')
                    deadline = gate_file()['testWindow']['effectiveEndUtcMs']
                    require(deadline<first['result']['window']['endUtcMs'],'Credential revoke reserve missing')
                    command('window-close')
                    require(fresh()==['TCP_BLOCKED'],'Manual close accepted new TCP')
                    push(child,'after-close','NO_BYTES')
                finally:
                    child.terminate()
            results['manualClose'] = {'status':'PASS','newBlocked':True,'establishedBlocked':True,'replayedAckExact':True,'secondWindowDenied':True}

            _,opened = command('window-open',150)
            require(opened['result']['status']=='TEST_WINDOW','Closed fixture prevented a distinct second window')
            with proc_client() as child:
                try:
                    push(child,'before-unknown','ECHO')
                    (HOME/'unknown').touch()
                    await_until(lambda:gate_file()['testWindow']['cleanupSha256'] is not None,12,'Unknown authority did not close')
                    require(fresh()==['TCP_BLOCKED'],'Unknown authority allowed new flow')
                    push(child,'after-unknown','NO_BYTES')
                finally:
                    child.terminate()
            results['unknownAuthority'] = {'status':'PASS','closed':True}

            (HOME/'unknown').unlink()
            await_until(lambda:run('systemctl','is-active',service.UNIT,check=False).returncode!=0,8,'Failed actor still running')
            run('systemctl','start',service.UNIT)
            await_until(service.CONTROL.is_socket,8,'Fresh service did not open control')
            command('start')
            command('window-open',150)
            with proc_client() as child:
                try:
                    push(child,'before-exit','ECHO')
                    run('systemctl','kill','--kill-whom=main','--signal=SIGKILL',service.UNIT)
                    run('systemctl','stop','uzel-ops-watchdog.timer','uzel-ops-watchdog.service')
                    revision = gate_file()['leaseRevision']
                    require(fresh()[:1]==['TCP_CONNECTED'],'Lease gone before testing independent kernel expiry')
                    time.sleep(32)
                    require(fresh()==['TCP_BLOCKED'],'Expired kernel lease accepted new TCP')
                    push(child,'after-expiry','NO_BYTES')
                    require(gate_file()['leaseRevision']==revision and gate_file()['testWindow']['active'],
                            'Userspace closed instead of kernel expiry')
                finally:
                    child.terminate()
            results['kernelExpiry'] = {'status':'PASS','seconds':30,'noUserspaceClose':True,'newBlocked':True,'establishedBlocked':True}
            run('systemctl','start','uzel-ops-watchdog.service')
            require(not gate_file()['testWindow']['active'] and gate_file()['testWindow']['cleanupSha256'] is None,
                    'Watchdog falsely marked credential cleanup')
        finally:
            server.terminate()


def host_state():
    def projection(args):
        value = run(*args).stdout
        if args[0]=='nft':
            return re.sub(r'counter packets \d+ bytes \d+','counter packets 0 bytes 0',value)
        if args[0]=='ss':
            return '\n'.join(sorted(value.splitlines()))
        rows = json.loads(value)
        return json.dumps([{k:v for k,v in r.items() if k not in ('expires','valid_life_time','preferred_life_time')} for r in rows],sort_keys=True)
    return {args[0]+str(index):hashlib.sha256(projection(args).encode()).hexdigest() for index,args in enumerate([
       ['nft','list','ruleset'],['ip','-j','-4','route','show','table','all'],['ip','-j','-6','route','show','table','all'],
       ['ip','-j','rule','show'],['ss','-H','-ltnu']])}


def docker_integrity():
    docker.setup()
    engine = docker.start_engine()
    require(engine['ServerVersion']=='29.1.3','Wrong rootless Docker version')
    docker.docker('pull','--platform=linux/amd64',docker.IMAGE,timeout=180)
    docker.docker('network','create','--internal','synthetic-data')
    data = docker.HOME_DIR/'synthetic-db.sqlite'
    import sqlite3
    with sqlite3.connect(str(data)) as conn:
        conn.executescript('CREATE TABLE audit(id INTEGER PRIMARY KEY, value TEXT); INSERT INTO audit VALUES(1, \'synthetic\');')
    before_data = hashlib.sha256(data.read_bytes()).hexdigest()
    cid = docker.docker('create','--network','synthetic-data','--network-alias','db-fixture','--restart','no',
        '-v',str(data)+':/synthetic-db.sqlite:ro',docker.IMAGE,'sh','-c','test -s /synthetic-db.sqlite').stdout.strip()
    before = docker.inspect(cid)['NetworkSettings']['Networks']
    docker.STATE['containerIds'].append(cid)
    docker.docker('start','-a',cid)
    stopped = docker.inspect(cid)
    require(not stopped['State']['Running'] and stopped['State']['ExitCode']==0 and stopped['NetworkSettings']['Networks']==before,
            'Stopped container attachment identity drift')
    stop = docker.stop_engine()
    disk = json.loads((docker.HOME_DIR/'docker'/'containers'/cid/'config.v2.json').read_bytes())
    require(disk['NetworkSettings']['Networks']==before and not disk['State']['Running'] and
            hashlib.sha256(data.read_bytes()).hexdigest()==before_data,'Stopped attachment or database evidence differs')
    return {'status':'PASS','version':engine['ServerVersion'],'attachmentsSha256':service.digest(before),
            'syntheticDatabaseSha256':before_data,'engineStop':stop}


def cleanup(docker_started):
    run('systemctl','stop',service.UNIT,'uzel-ops-watchdog.timer','uzel-ops-watchdog.service','uzel-ops.socket',check=False)
    run('loginctl','disable-linger','uzel-runtime',check=False)
    run('loginctl','terminate-user','uzel-runtime',check=False)
    for namespace in (SERVER,CLIENT):
        run('ip','netns','del',namespace,check=False)
    for name in (service.UNIT,*broker.systemd_units(UID)):
        (UNIT_PATH/name).unlink(missing_ok=True)
    run('systemctl','daemon-reload')
    return docker.cleanup() if docker_started else {'status':'PASS'}


def main():
    release = Path('/etc/os-release').read_text()
    version = run('systemctl','--version').stdout.splitlines()[0]
    require(os.geteuid()==0 and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and
            os.environ.get('GITHUB_ACTIONS')=='true' and 'VERSION_ID="26.04"' in release and version.startswith('systemd 259 '),
            'Disposable Ubuntu 26.04 with systemd 259 required')
    require(not Path('/etc/uzel-role').exists(),'Production role marker present')
    out = HERE/'standby-native-receipt.json'
    value = {'status':'FAIL','systemd':version,'kernel':os.uname().release,'nft':run('nft','--version').stdout.strip(),
             'commit':os.environ['REVIEW_HEAD_SHA'],'sourceHashes':{name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in MODULES}}
    baseline = host_state()
    docker_started = False
    signal.signal(signal.SIGALRM,docker.deadline)
    signal.alarm(540)
    try:
        kernel_cases(value)
        docker_started = True
        value['stoppedIntegrity'] = docker_integrity()
        value['status']='PASS'
    except Exception as error:
        value['error'] = str(error)
        import traceback
        value['trace'] = traceback.format_exc(limit=6)
    finally:
        signal.alarm(0)
        value['cleanup'] = cleanup(docker_started)
        value['hostSecurityExact'] = host_state()==baseline
        if value['cleanup']['status']!='PASS' or not value['hostSecurityExact']:
            value['status']='FAIL'
        service.require(not out.exists(),'Native receipt already exists')
        out.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n');out.chmod(0o644)
        if value['status']!='PASS':
            print(json.dumps(value,sort_keys=True))
    return int(value['status']!='PASS')


if __name__=='__main__':
    raise SystemExit(main())
