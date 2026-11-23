#!/usr/bin/python3
"""Fixed-command owner-installed network helper; never execute runtime-owned code.

Install/release approval and native kernel acceptance are separate prerequisites.
No import-time mutation. Public CLI is exactly status/start/stop/renew/close.
"""
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import re
import select
import socket
import stat
import struct
import subprocess
import sys
import time

RELEASE=Path('/usr/local/lib/uzel-ops')
STATE=Path('/var/lib/uzel-ops')
SAFE_ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'}
WINDOW_CLEANUP_RESERVE_MS=25000
WINDOW_NFT_TIMEOUT=3
WINDOW_CLEANUP_TIMEOUT=90
WINDOW_HEARTBEAT_MAX_AGE=45
MAX_WINDOW_LEASES=180
STANDBY_CGROUP='/system.slice/uzel-standby.service'
SO_PEERPIDFD=getattr(socket,'SO_PEERPIDFD',77)  # Linux UAPI


class RequestRejected(RuntimeError):
    """The request was refused before any durable intent or kernel mutation."""


def accept_request(ok,message):
    if not ok:raise RequestRejected(message)


def require(ok,message):
    if not ok:raise RuntimeError(message)


def digest(data):return hashlib.sha256(data).hexdigest()


def directory(path,uid=0):
    for p in [path,*path.parents]:
        s=p.lstat()
        require(stat.S_ISDIR(s.st_mode) and not p.is_symlink() and s.st_uid==uid and not s.st_mode&0o022,'Unsafe root directory')


def read_regular(path,mode=0o600,uid=0,maximum=2*1024*1024):
    directory(path.parent,uid)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as f:
        s=os.fstat(f.fileno())
        require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==uid and s.st_gid==uid and stat.S_IMODE(s.st_mode)==mode and s.st_size<=maximum,'Unsafe root file')
        data=f.read(maximum+1);require(len(data)<=maximum,'Oversized root file')
    return data


def write_atomic(path,obj):
    """Root-only directory, no overwrite of a foreign/symlink target."""
    directory(path.parent)
    if path.exists() or path.is_symlink():read_regular(path)
    # A killed writer can leave a pending file. The committed intent continues
    # to govern recovery, and the watchdog can record stop without touching it.
    tmp=path.with_suffix(path.suffix+'.pending-'+os.urandom(8).hex())
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write((json.dumps(obj,sort_keys=True)+'\n').encode());f.flush();os.fsync(f.fileno())
    os.replace(tmp,path)
    d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(d)
    finally:os.close(d)


def command(argv,input=None,check=True,timeout=30):
    r=subprocess.run([str(v) for v in argv],input=input,text=True,capture_output=True,
                     env=SAFE_ENV,cwd='/',timeout=timeout)
    # Never print arguments, stdout/stderr or private file contents on failure.
    if check:require(r.returncode==0,'Command failure: '+Path(argv[0]).name+' exit '+str(r.returncode))
    return r


def load_release():
    directory(RELEASE)
    manifest=json.loads(read_regular(RELEASE/'manifest.json'))
    require(set(manifest)=={'schema','files'} and manifest['schema']==1,'Invalid root release manifest')
    require(set(manifest['files'])=={'root_helper.py','network_policy.py','policy.json','wireguard.conf'},'Unexpected root code closure')
    require({p.name for p in RELEASE.iterdir()}==set(manifest['files'])|{'manifest.json'},'Unmanifested root release entry')
    for name,expected in manifest['files'].items():
        require(digest(read_regular(RELEASE/name))==expected,'Root release hash mismatch')
    # Only after ownership/hash closure verification may our own module import.
    sys.path.insert(0,str(RELEASE))
    import network_policy
    policy=network_policy.validate(json.loads(read_regular(RELEASE/'policy.json')))
    return policy,network_policy


class Helper:
    def __init__(self,policy,module):
        self.p=policy;self.n=module;self.role=policy['role'];self.r=module.ROLES[self.role]
        self.path=STATE/'state.json'
        self.wg=Path('/etc/wireguard')/('uzel-operational-'+self.role+'.conf')
        self.boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        require(Path('/etc/uzel-role').read_text().strip()==self.role,'Host role differs')
        require(pwd.getpwnam('uzel-runtime').pw_uid==self.r['uid'],'Runtime UID differs')
        directory(STATE)
        self.state=json.loads(read_regular(self.path)) if self.path.exists() else None
        if self.state:
            require(self.state.get('epoch')==policy['epoch'] and self.state.get('role')==self.role,'Foreign root state')

    def save(self,phase,**fields):
        self.state={**(self.state or {}),'schema':1,'role':self.role,'epoch':self.p['epoch'],
                    'bootId':self.boot,'phase':phase,'updatedAt':time.time(),**fields}
        write_atomic(self.path,self.state)

    def user(self,*args,check=True):
        u=str(self.r['uid'])
        return command(['runuser','-u','uzel-runtime','--','env','-i','PATH='+SAFE_ENV['PATH'],
                        'XDG_RUNTIME_DIR=/run/user/'+u,'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/'+u+'/bus',*args],check=check,timeout=120)

    def stopped(self):
        r=self.user('systemctl','--user','show','docker.service','-p','MainPID','-p','ActiveState',check=False)
        processes=command(['pgrep','-u',str(self.r['uid']),'-f','dockerd|rootlesskit|containerd|slirp4netns|rw-node|xray|postgres|valkey|caddy'],check=False)
        require(processes.returncode==1 and not processes.stdout,'Runtime still present')
        require(r.returncode==0 and set(r.stdout.splitlines())=={'MainPID=0','ActiveState=inactive'},'Engine not stopped or unreadable')
        workload_cgroups_absent(self.r['uid'])

    def table_raw(self):
        # Enumerating successfully distinguishes absence from a failed inspect.
        all_tables=json.loads(command(['nft','-j','list','tables']).stdout)
        require(isinstance(all_tables,dict) and set(all_tables)=={'nftables'} and isinstance(all_tables['nftables'],list),'Malformed table inventory')
        for row in all_tables['nftables']:
            require(isinstance(row,dict) and len(row)==1,'Malformed table row')
            if 'metainfo' in row:
                require(isinstance(row['metainfo'],dict),'Malformed nft metadata');continue
            require('table' in row and isinstance(row['table'],dict),'Unexpected table inventory entry')
            item=row['table']
            require(set(item)<= {'family','name','handle','flags','comment'} and
                    item.get('family') in ['ip','ip6','inet','arp','bridge','netdev'] and
                    isinstance(item.get('name'),str) and bool(item['name']),'Malformed table identity')
        matches=[row['table'] for row in all_tables['nftables'] if isinstance(row,dict) and
                 isinstance(row.get('table'),dict) and row['table'].get('family')=='inet' and row['table'].get('name')==self.n.TABLE]
        require(len(matches)<=1,'Duplicate table inventory')
        if not matches:return None
        return json.loads(command(['nft','-j','list','table','inet',self.n.TABLE]).stdout)

    def table(self):
        raw=self.table_raw()
        return None if raw is None else self.n.stable_table(raw,self.p)

    def verify_table(self):
        require(self.state and self.state.get('tableSnapshot') is not None,'Missing owned table proof')
        require(self.table()==self.state['tableSnapshot'],'Owned table drift; preserve safety gate')

    def interface(self):
        inventory=json.loads(command(['ip','-j','-d','link','show']).stdout)
        require(isinstance(inventory,list) and all(isinstance(x,dict) and 'ifname' in x for x in inventory),'Malformed link inventory')
        links=[x for x in inventory if x['ifname']==self.n.INTERFACE]
        if not links:return None
        require(len(links)==1 and links[0].get('linkinfo',{}).get('info_kind')=='wireguard','Wrong interface kind')
        def rows(args):return json.loads(command(args).stdout)
        return {'ifindex':links[0]['ifindex'],'ifname':links[0]['ifname'],'flags':links[0]['flags'],
                'mtu':links[0]['mtu'],'addresses':rows(['ip','-j','address','show','dev',self.n.INTERFACE]),
                'routes':rows(['ip','-j','-4','route','show','table','all','dev',self.n.INTERFACE]),
                'public':{field:command(['wg','show',self.n.INTERFACE,field]).stdout.strip() for field in
                    ['public-key','listen-port','fwmark','peers','allowed-ips','endpoints','persistent-keepalive']}}

    def verify_interface(self):
        require(self.state and self.state.get('interfaceSnapshot') is not None,'Missing interface proof')
        require(self.interface()==self.state['interfaceSnapshot'],'Interface drift; preserve for owner')

    def check_host(self):
        require(command(['sysctl','-n','net.ipv4.ip_forward']).stdout.strip()=='0','IPv4 forwarding drift')
        require(command(['sysctl','-n','net.ipv6.conf.all.forwarding']).stdout.strip()=='0','IPv6 forwarding drift')
        unit=Path('/srv/uzel/.config/systemd/user/docker.service')
        s=unit.lstat()
        require(stat.S_ISREG(s.st_mode) and not unit.is_symlink() and s.st_uid==self.r['uid'] and s.st_nlink==1 and not s.st_mode&0o022,'Unsafe runtime unit')
        require(digest(unit.read_bytes())==self.p['runtimeUnitSha256'],'Unreviewed runtime unit')
        require('wg (enforce)' in Path('/sys/kernel/security/apparmor/profiles').read_text().splitlines(),'WG AppArmor not enforcing')

    def validate_wg(self):
        text=read_regular(RELEASE/'wireguard.conf',maximum=4096).decode()
        section=None;values={}
        for line in text.splitlines():
            line=line.strip()
            if not line:continue
            if line in ['[Interface]','[Peer]']:
                require(line not in values,'Duplicate WG section');section=line;values[line]={};continue
            require(section and '=' in line,'Malformed WG configuration')
            key,value=map(str.strip,line.split('=',1))
            require(key not in values[section],'Duplicate WG field');values[section][key]=value
        require(set(values)=={'[Interface]','[Peer]'},'Wrong WG sections')
        a,b=values['[Interface]'],values['[Peer]']
        require(set(a)=={'PrivateKey','ListenPort'} and a['ListenPort']=='51820','Wrong WG interface configuration')
        require(b=={'PublicKey':self.p['wireguardPeerPublicKey'],'AllowedIPs':self.r['remote']+'/32',
                    'Endpoint':self.r['peer']+':51820','PersistentKeepalive':'25'},'Wrong WG peer/route')
        require(command(['wg','pubkey'],input=a['PrivateKey']+'\n').stdout.strip()==self.p['wireguardPublicKey'],'WG private/public identity mismatch')
        return text

    def check_wireguard_route(self):
        query=['ip','-j','-4','route','get',self.r['peer']]
        unmarked,=json.loads(command(query,timeout=5).stdout)
        marked,=json.loads(command([*query,'mark',self.n.WIREGUARD_FWMARK],timeout=5).stdout)
        require(unmarked['dev']==self.n.WIREGUARD_UPLINK and unmarked['dst']==self.r['peer'] and
                unmarked['prefsrc']==self.r['ip'] and
                marked=={**unmarked,'mark':int(self.n.WIREGUARD_FWMARK,16)},'WireGuard mark changes the peer route')

    def start(self):
        if self.state and self.state['phase']=='ACTIVE':
            require(self.state['bootId']==self.boot,'Reboot requires owner state reconciliation')
            self.check_host();self.verify_table();self.verify_interface();return {'status':'ALREADY_ACTIVE_NO_MUTATION'}
        require(self.state is None or self.state['phase']=='CLOSED','Prior operation unfinished; stop/review before new start')
        previous=(self.state or {}).get('testWindow')
        if 'testWindowMaxSeconds' in self.p:
            accept_request(previous is None or previous['cleanupSha256'] is not None,
                           'Last operator window cleanup requires independent recovery')
        self.check_host();self.stopped()
        require(self.table() is None and self.interface() is None,'Operational network already present')
        require(not command(['nft','list','ruleset']).stdout.strip(),'Nonempty host firewall needs explicit review')
        for tool in ['iptables-save','ip6tables-save']:
            require(not command([tool]).stdout.strip(),'Legacy firewall needs explicit review')
        self.check_wireguard_route()
        directory(self.wg.parent)
        require(stat.S_IMODE(self.wg.parent.stat().st_mode)==0o700,'WireGuard parent must be0700')
        require(not self.wg.exists() and not self.wg.is_symlink(),'Existing WG file')
        text=self.validate_wg();rules=self.n.nft_rules(self.p)
        command(['nft','--check','-f','-'],input=rules)
        window_state={'testWindow':{**previous,'active':False} if previous else None} if 'testWindowMaxSeconds' in self.p else {}
        self.save('START_INTENT',tableSnapshot=None,interfaceSnapshot=None,wgFile=None,leaseRevision=0,stopAttempted=False,
                  **window_state)
        fd=os.open(self.wg,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:f.write(text);f.flush();os.fsync(f.fileno());s=os.fstat(f.fileno())
        self.save('WG_FILE_CREATED',wgFile={'dev':s.st_dev,'ino':s.st_ino,'sha256':digest(text.encode())})
        # Fail closed before creating the management interface or any workload.
        self.save('TABLE_CREATE_INTENT')
        command(['nft','-f','-'],input=rules)
        self.save('TABLE_CREATED',tableSnapshot=self.table())
        self.save('INTERFACE_CREATE_INTENT')
        command(['ip','link','add',self.n.INTERFACE,'type','wireguard'])
        self.save('INTERFACE_CREATED',interfaceSnapshot=self.interface())
        for label,args in [('WG_CONFIGURED',['wg','setconf',self.n.INTERFACE,str(self.wg)]),
                           ('WG_MARKED',['wg','set',self.n.INTERFACE,'fwmark',self.n.WIREGUARD_FWMARK]),
                           ('ADDRESS_SET',['ip','address','add',self.r['management']+'/32','dev',self.n.INTERFACE]),
                           ('LINK_UP',['ip','link','set','dev',self.n.INTERFACE,'up']),
                           ('ROUTE_SET',['ip','route','add',self.r['remote']+'/32','dev',self.n.INTERFACE,'src',self.r['management']])]:
            self.verify_interface();self.verify_table();self.save(label+'_INTENT')
            command(args);self.save(label,interfaceSnapshot=self.interface())
            if label=='WG_MARKED':
                require(self.state['interfaceSnapshot']['public']['fwmark']==self.n.WIREGUARD_FWMARK,
                        'WireGuard mark readback differs')
        self.save('ACTIVE',lastControlAt=time.monotonic())
        return {'status':'MANAGEMENT_ACTIVE_VPN_GATE_CLOSED','role':self.role}

    def prepare_test_window(self,window,proof_sha):
        accept_request(isinstance(window,dict) and set(window)=={'id','readyAtUtcMs','endUtcMs','fixtureEndsUtcMs'} and
                isinstance(window['id'],str) and re.fullmatch('[0-9a-f]{32}',window['id']) and
                all(type(window[k]) is int for k in ('readyAtUtcMs','endUtcMs','fixtureEndsUtcMs')),
                'Exact operator test window required')
        ready=window['readyAtUtcMs'];end=min(window['endUtcMs'],window['fixtureEndsUtcMs']-WINDOW_CLEANUP_RESERVE_MS)
        monotonic=time.monotonic();now=time.time_ns()//1000000
        accept_request(ready<=now<end and all(0<window[k]-ready<=self.p['testWindowMaxSeconds']*1000
                    for k in ('endUtcMs','fixtureEndsUtcMs')),'Expired or oversized test window')
        previous=self.state.get('testWindow')
        gate=self.lease_observation()
        if previous and previous['active']:
            accept_request(previous['request']==window and gate['leaseComplete'] is True and gate['leaseOpen'] is True and
                    gate['remainingMilliseconds']>1000 and proof_sha not in previous['proofs'] and
                    len(previous['proofs'])<MAX_WINDOW_LEASES,
                    'Live window revision, fresh evidence or kernel lease changed')
            return {**previous,'proofs':[*previous['proofs'],proof_sha]}
        accept_request(not gate['leaseOpen'] and (previous is None or
                previous['cleanupSha256'] is not None and window['id']!=previous['request']['id'] and
                ready>previous['request']['readyAtUtcMs']),
                'New operator window and an empty leased set required')
        return {'request':window,'effectiveEndUtcMs':end,'deadlineMonotonic':monotonic+(end-now)/1000,
                'active':True,'proofs':[proof_sha],'cleanupByMonotonic':None,'cleanupSha256':None}

    def test_window_remaining(self,window):
        return min(window['deadlineMonotonic']-time.monotonic(),
                   (window['effectiveEndUtcMs']-time.time_ns()//1000000)/1000)

    def test_window_supervised(self):
        last=self.state.get('lastControlAt')
        return type(last) in (float,int) and 0<=time.monotonic()-last<=WINDOW_HEARTBEAT_MAX_AGE

    def lease(self,enable,expected_revision=None,proof_sha=None,*,window=None):
        require(self.state and self.state['phase']=='ACTIVE' and self.state['bootId']==self.boot,'Network not active in current boot')
        self.check_host();self.verify_table();self.verify_interface()
        require(self.role=='dp-a','No CP public VPN gate')
        window_policy='testWindowMaxSeconds' in self.p
        if enable:
            validate=accept_request if window_policy else require
            validate(type(expected_revision) is int and expected_revision==self.state.get('leaseRevision'),'Stale lease revision')
            validate(isinstance(proof_sha,str) and re.fullmatch('[0-9a-f]{64}',proof_sha),'Authority proof digest required')
        accept_request((not enable and window is None) or (enable and (window is not None)==window_policy),
                'Window metadata and installed policy must agree')
        window_state={}
        if window_policy:
            if enable:accept_request(self.test_window_supervised(),'Stale operator runtime heartbeat')
            active=self.prepare_test_window(window,proof_sha) if enable else self.state.get('testWindow')
            if enable:
                accept_request(self.test_window_remaining(active)>=30+WINDOW_NFT_TIMEOUT+1,
                               'Insufficient time for another kernel lease')
            if not enable and (active is None or active['active'] is False) and not self.lease_observation()['leaseOpen']:
                return {'status':'VPN_GATE_CLOSED','seconds':0,'leaseRevision':self.state['leaseRevision']}
            window_state={'testWindow':active}
        self.save('LEASE_INTENT',leaseEnable=enable,**window_state)
        seconds=self.p['leaseSeconds']
        if enable and window_policy:
            # Account for the bounded nft request after the last clock sample.
            seconds=min(seconds,math.floor(self.test_window_remaining(active))-WINDOW_NFT_TIMEOUT-1)
            require(seconds>=30 and self.test_window_supervised(),'Window or runtime heartbeat expired before nft apply')
            command(['nft','-f','-'],input=self.n.lease_transaction(self.p,True,seconds=seconds),timeout=WINDOW_NFT_TIMEOUT)
        else:
            command(['nft','-f','-'],input=self.n.lease_transaction(self.p,enable))
        self.verify_table()
        observed=self.lease_observation(expected_seconds=seconds) if enable and window_policy else self.lease_observation()
        if enable and window_policy and self.test_window_remaining(active)*1000<observed['remainingMilliseconds']:
            command(['nft','-f','-'],input=self.n.lease_transaction(self.p,False),timeout=WINDOW_NFT_TIMEOUT)
            require(not self.lease_observation()['leaseOpen'],'Clock discontinuity ingress close unconfirmed')
            raise RuntimeError('Clock discontinuity during kernel lease')
        require(observed['leaseComplete'] and seconds*1000-2000<=observed['remainingMilliseconds']<=seconds*1000+1000
                if enable else not observed['leaseOpen'],'Lease kernel readback differs')
        if window_policy and active and not enable:
            window_state={'testWindow':{**active,'active':False,'cleanupByMonotonic':time.monotonic()+WINDOW_CLEANUP_TIMEOUT}}
        self.save('ACTIVE',lastLeaseAt=time.monotonic() if enable else None,
            leaseRevision=self.state.get('leaseRevision',0)+1,authorityProofSha256=proof_sha if enable else None,**window_state)
        return {'status':'LEASE_RENEWED' if enable else 'VPN_GATE_CLOSED','seconds':seconds if enable else 0,
                'leaseRevision':self.state['leaseRevision']}

    def window_finalize(self,window_id,expected_revision,proof_sha):
        accept_request(self.role=='dp-a' and 'testWindowMaxSeconds' in self.p and self.state and
                       self.state['phase']=='ACTIVE' and self.state['bootId']==self.boot,
                       'No active operator runtime to finalize')
        current=self.state.get('testWindow')
        accept_request(current and not current['active'] and window_id==current['request']['id'] and
                       type(expected_revision) is int and expected_revision==self.state['leaseRevision'] and
                       isinstance(proof_sha,str) and re.fullmatch('[0-9a-f]{64}',proof_sha) and
                       proof_sha not in current['proofs'] and
                       (current['cleanupSha256']==proof_sha or current['cleanupSha256'] is None and
                        time.monotonic()<current['cleanupByMonotonic']), 'Stale or unresolved window cleanup')
        self.check_host();self.verify_table();self.verify_interface()
        require(not self.lease_observation()['leaseOpen'],'Cleanup recorded while public ingress still open')
        if current['cleanupSha256'] is None:
            self.save('ACTIVE',testWindow={**current,'cleanupSha256':proof_sha})
        return {'status':'WINDOW_CLEANUP_RECORDED','windowId':window_id,'leaseRevision':expected_revision}

    def stop(self):
        if not self.state:
            require(self.table() is None and self.interface() is None,'Unknown network resources')
            self.stopped();return {'status':'NO_OPERATIONAL_RESOURCES'}
        require(self.state['bootId']==self.boot,'Reboot requires independent state reconciliation')
        if self.state['phase']=='CLOSED':
            require(self.table() is None and self.interface() is None and not self.wg.exists(),'Resources remain after closed receipt')
            self.stopped();return {'status':'ALREADY_CLOSED_NO_MUTATION'}
        # An intent with no captured postcondition is unknown. Do not guess a
        # table/interface snapshot and delete foreign resources after lost ACK.
        # A foreign/drifted gate must not prevent stopping our known user Engine.
        # Do not delete or rewrite that gate before proving its exact ownership.
        self.save('STOP_ENGINE_INTENT',stopAttempted=True)
        close_error=None;closed_early=False
        if self.role=='dp-a' and 'testWindowMaxSeconds' in self.p:
            try:
                if self.table() is not None:
                    self.verify_table()
                    command(['nft','-f','-'],input=self.n.lease_transaction(self.p,False),timeout=WINDOW_NFT_TIMEOUT)
                    require(not self.lease_observation()['leaseOpen'],'Engine stop ingress close unconfirmed')
                closed_early=True
            except Exception as error:
                close_error=error
        self.user('systemctl','--user','stop','docker.service',check=False)
        self.stopped();self.save('ENGINE_STOPPED')
        if close_error is not None:raise close_error
        if self.table() is not None:
            self.verify_table()
            if self.role=='dp-a' and not closed_early:command(['nft','-f','-'],input=self.n.lease_transaction(self.p,False))
        if self.interface() is not None:
            self.verify_interface();self.save('INTERFACE_DELETE_INTENT')
            command(['ip','link','delete',self.n.INTERFACE])
            require(self.interface() is None,'Interface deletion unconfirmed')
            self.save('INTERFACE_DELETED')
        if self.table() is not None:
            self.verify_table();self.save('TABLE_DELETE_INTENT')
            command(['nft','delete','table','inet',self.n.TABLE])
            require(self.table() is None,'Table deletion unconfirmed');self.save('TABLE_DELETED')
        if self.wg.exists() or self.wg.is_symlink():
            data=read_regular(self.wg,maximum=4096);s=self.wg.lstat();expected=self.state.get('wgFile')
            require(expected=={'dev':s.st_dev,'ino':s.st_ino,'sha256':digest(data)},'WG file drift')
            os.unlink(self.wg)
        self.check_host();self.stopped()
        window=self.state.get('testWindow')
        if 'testWindowMaxSeconds' in self.p and window:
            self.save('CLOSED',testWindow={**window,'active':False})
        else:self.save('CLOSED')
        return {'status':'CLOSED_ENGINE_STOPPED_OWN_NETWORK_REMOVED'}

    def lease_observation(self,*,expected_seconds=None):
        remaining=[]
        raw=self.table_raw()
        if raw is not None:
            self.n.stable_table(raw,self.p)
            for row in raw['nftables']:
                if 'set' in row:
                    info=row['set']
                    for entry in info.get('elem',[]):
                        element=entry['elem']
                        require(expected_seconds is None or element.get('timeout',info['timeout'])==expected_seconds,
                                'Kernel element timeout differs from requested duration')
                        remaining.append(element['expires'])
        # JSON seconds round down. A present zero-second element can still pass
        # packets, and a partially populated set is not a closed gate.
        return {'leaseOpen':bool(remaining),'leaseComplete':len(remaining)==len(self.p['sourceIPv4s']),
                'remainingMilliseconds':min(self.p['leaseSeconds']*1000,(max(remaining)+1)*1000) if remaining else 0}

    def status(self):
        phase=self.state['phase'] if self.state else 'UNINITIALIZED'
        if phase=='ACTIVE':self.check_host();self.verify_table();self.verify_interface()
        observed=self.lease_observation()
        handshake=self.management_handshake() if phase=='ACTIVE' and self.state['bootId']==self.boot else None
        return {'role':self.role,'phase':phase,'bootMatches':not self.state or self.state['bootId']==self.boot,
                'epoch':self.p['epoch'],'policySha256':digest(self.n.canonical(self.p)),'leaseSeconds':self.p['leaseSeconds'],
                'leaseRevision':(self.state or {}).get('leaseRevision',0),'observedAt':time.monotonic(),
                'managementHandshake':handshake,**observed}

    def window_status(self):
        accept_request(self.role=='dp-a' and 'testWindowMaxSeconds' in self.p,'Test window policy is not installed')
        status=self.status()
        window=(self.state or {}).get('testWindow')
        return {'phase':status['phase'],'bootMatches':status['bootMatches'],'leaseRevision':status['leaseRevision'],
                'leaseOpen':status['leaseOpen'],'remainingMilliseconds':status['remainingMilliseconds'],
                'window':window['request'] if window else None,'windowActive':bool(window and window['active']),
                'effectiveEndUtcMs':window['effectiveEndUtcMs'] if window else None,
                'lastProofSha256':(self.state or {}).get('authorityProofSha256'),
                'cleanupSha256':window['cleanupSha256'] if window else None}

    def management_handshake(self):
        """Read dynamic kernel proof separately from the immutable interface seal.

        A configured interface or keepalive is not a successful handshake. No
        private key, endpoint or traffic content is returned to the runtime.
        The caller has just checked the full pinned interface configuration.
        """
        require(self.state and self.state['phase']=='ACTIVE' and self.state['bootId']==self.boot,
                'No current-boot active management link')
        wall_before=time.time();mono_before=time.monotonic()
        raw=command(['wg','show',self.n.INTERFACE,'latest-handshakes'],timeout=3).stdout
        wall_after=time.time();mono_after=time.monotonic()
        require(0<=mono_after-mono_before<=4 and
                abs((wall_after-wall_before)-(mono_after-mono_before))<=1,'Clock changed during handshake read')
        rows=raw.splitlines()
        require(len(rows)==1,'Exactly one management peer required')
        fields=rows[0].split('\t')
        require(len(fields)==2 and fields[0]==self.p['wireguardPeerPublicKey'] and
                fields[1].isascii() and fields[1].isdigit(),'Wrong peer or malformed handshake')
        timestamp=int(fields[1])
        require(timestamp<=wall_after,'Future management handshake')
        return {'ownPublicKeySha256':digest(self.p['wireguardPublicKey'].encode()),
                'peerPublicKeySha256':digest(fields[0].encode()),'lastHandshakeAt':timestamp,
                'ageSeconds':wall_after-timestamp if timestamp else None,
                'observedAt':wall_after,'observedMonotonic':mono_after}

    def heartbeat(self):
        require(self.state and self.state['phase']=='ACTIVE' and self.state['bootId']==self.boot,'Inactive or old-boot network')
        self.check_host();self.verify_table();self.verify_interface()
        self.save('ACTIVE',lastControlAt=time.monotonic())
        return {'status':'CONTROL_HEARTBEAT_RECORDED','watchdogSeconds':180}

    def watchdog(self):
        if not self.state or self.state['phase']=='CLOSED':return {'status':'NO_ACTIVE_OPERATION'}
        if self.state['phase']=='BLOCKED' and self.state.get('stopAttempted') is True:
            return {'status':'BLOCKED_STOP_ALREADY_ATTEMPTED_NO_AUTOMATIC_RETRY'}
        require(self.state['bootId']==self.boot,'Old-boot state requires explicit recovery')
        last=self.state.get('lastControlAt',0)
        require(type(last) in (int,float) and 0<=last<=time.monotonic(),'Invalid monotonic heartbeat')
        if self.state['phase']=='ACTIVE' and time.monotonic()-last<180:
            window=self.state.get('testWindow')
            if 'testWindowMaxSeconds' in self.p and window:
                if window['active'] and (self.test_window_remaining(window)<=0 or not self.lease_observation()['leaseComplete']):
                    self.lease(False)
                    return {'status':'WATCHDOG_TEST_WINDOW_CLOSED'}
                if not window['active'] and window['cleanupSha256'] is None and time.monotonic()>=window['cleanupByMonotonic']:
                    return self.stop()
            return {'status':'WATCHDOG_CURRENT'}
        # No workload launch. Unknown resources remain, owned Engine is stopped.
        return self.stop()


def require_service_peer(peer,pid):
    fd=peer.getsockopt(socket.SOL_SOCKET,SO_PEERPIDFD)
    require(fd>=0,'Missing service peer pidfd')
    try:
        alive=select.poll();alive.register(fd,select.POLLIN)
        require(not alive.poll(0),'Service peer exited')
        pid_info=(Path('/proc/self/fdinfo')/str(fd)).read_text().splitlines()
        require(f'Pid:\t{pid}' in pid_info,'Service peer PID changed')
        membership=(Path('/proc')/str(pid)/'cgroup').read_text().splitlines()
        require(membership==['0::'+STANDBY_CGROUP] and not alive.poll(0),
                'Peer is outside the fixed system service')
    finally:os.close(fd)


def broker_request(fd,runtime_uid,*,standby=False):
    """systemd Accept=yes stdin socket; kernel peer identity, no shell/paths."""
    with socket.fromfd(fd,socket.AF_UNIX,socket.SOCK_STREAM) as peer:
        deadline=time.monotonic()+3
        require(peer.family==socket.AF_UNIX,'Unix peer required')
        pid,uid,gid=struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        require(pid>0 and uid==runtime_uid and (not standby or gid==runtime_uid),'Unauthorized broker peer')
        if standby:require_service_peer(peer,pid)
        data=b''
        while b'\n' not in data:
            remaining=deadline-time.monotonic()
            require(remaining>0,'Broker request absolute deadline exceeded')
            peer.settimeout(remaining)
            chunk=peer.recv(385-len(data))
            require(time.monotonic()<=deadline,'Broker request absolute deadline exceeded')
            require(chunk and len(data)+len(chunk)<=384,'Missing or oversized broker request')
            data+=chunk
        require(data.endswith(b'\n') and data.count(b'\n')==1,'Exactly one broker request required')
        obj=json.loads(data)
        require(isinstance(obj,dict) and obj.get('action') in ['status','start','stop','renew','close','heartbeat',
                'window_status','window_finalize'],'Unknown broker action')
        keys={'action','expectedRevision','proofSha256'} if obj['action']=='renew' else {'action'}
        if obj['action']=='window_finalize':keys.update(('windowId','proofSha256','expectedRevision'))
        if obj['action']=='renew' and 'window' in obj:keys.add('window')
        else:require(len(data)<=256,'Oversized legacy broker request')
        require(set(obj)==keys,'Unexpected broker fields')
        if standby:require_service_peer(peer,pid)
        return obj


def workload_cgroups_absent(uid,proc=Path('/proc')):
    """Rootless containers can have subordinate UIDs; process-name checks alone
    do not prove they stopped. Read all process cgroups, preserving unknowns.
    """
    owner='/user.slice/user-'+str(uid)+'.slice/'
    require(proc.is_dir(),'Process inventory unavailable')
    for entry in proc.iterdir():
        if not entry.name.isdigit():continue
        try:data=(entry/'cgroup').read_text()
        except FileNotFoundError:
            require(not entry.exists(),'Process cgroup disappeared while process remained');continue
        require(bool(data.strip()),'Empty process cgroup state')
        if owner in data:
            require(not any(token in data for token in ['docker.service','docker-','/docker/','containerd']),
                    'Owned workload cgroup still contains a process')


def acquire_state_lock(fd, wait_seconds):
    """Wait briefly for an observation or heartbeat before its single dispatch."""
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise
            time.sleep(min(0.05, remaining))
            if time.monotonic() >= deadline:
                raise


def main():
    require(os.geteuid()==0 and len(sys.argv)==2 and sys.argv[1] in ['status','start','stop','close','watchdog','broker'],'Exact owner-installed helper action required')
    os.umask(0o077);policy,module=load_release();caller=os.environ.get('SUDO_UID')
    require(caller is None,'Use the fixed authenticated broker, not sudo')
    request=(broker_request(0,module.ROLES[policy['role']]['uid'],standby='standbyService' in policy)
             if sys.argv[1]=='broker' else {'action':sys.argv[1]})
    directory(STATE)
    fd=os.open(STATE/'lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a+') as lock:
        s=os.fstat(lock.fileno());require(s.st_uid==0 and s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1,'Unsafe lock')
        action=request['action']
        wait_seconds = 2 if sys.argv[1]=='broker' and action in ('status','heartbeat','window_status') else 0
        acquire_state_lock(lock.fileno(), wait_seconds)
        current = (STATE/'lock').lstat()
        require((current.st_dev,current.st_ino,current.st_mode,current.st_uid,current.st_gid,current.st_nlink)==
                (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink),'Root state lock changed while acquired')
        h=Helper(policy,module)
        try:
            if action in ['renew','close']:
                args={'window':request['window']} if 'window' in request else {}
                answer=h.lease(action=='renew',request.get('expectedRevision'),request.get('proofSha256'),**args)
            elif action=='window_finalize':
                answer=h.window_finalize(request['windowId'],request['expectedRevision'],request['proofSha256'])
            else:answer=getattr(h,action)()
        except RequestRejected:
            raise
        except BaseException:
            # No automatic retry or broad cleanup after ambiguous mutation.
            # Kernel timeout closes the data-plane gate without this process.
            if h.state and h.state['phase']!='CLOSED':
                h.save('BLOCKED',blockedFromPhase=h.state['phase'])
            raise
        print(json.dumps({'action':action,'role':h.role,'epoch':h.p['epoch'],'result':answer}))


if __name__=='__main__':
    try:main()
    except BaseException as error:
        print(json.dumps({'status':'BLOCKED','errorType':type(error).__name__,
                          'reason':str(error)[:200],'retryBlindly':False}),file=sys.stderr)
        sys.exit(1)
