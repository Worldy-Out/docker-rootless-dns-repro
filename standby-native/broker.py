"""Bounded unprivileged RPC and owner-installed unit renderer, no sudo.

Rendering is PREPARED only. Installing/enabling these units and linger requires
the sealed owner installation package; importing this module changes nothing.
"""
import json
import math
import os
from pathlib import Path
import socket
import stat

SOCKET=Path('/run/uzel-ops/broker.sock')


def require(ok,message):
    if not ok:raise RuntimeError(message)


def window_fields(value):
    return (isinstance(value,dict) and set(value)=={'id','readyAtUtcMs','endUtcMs','fixtureEndsUtcMs'} and
            hex_string(value['id'],32) and all(type(value[k]) is int for k in ('readyAtUtcMs','endUtcMs','fixtureEndsUtcMs')))


def hex_string(value,length):
    return isinstance(value,str) and len(value)==length and all(c in '0123456789abcdef' for c in value)


def request(action,expected_revision=None,proof_sha256=None,*,window=None,window_id=None,deadline_monotonic_ms=None):
    require(action in ['start','stop','status','heartbeat','close','renew','window_status','window_finalize'],
            'Unknown fixed broker action')
    payload={'action':action}
    if action in ('renew','window_finalize'):
        require(type(expected_revision) is int and expected_revision>=0,'Explicit lease revision required')
        require(hex_string(proof_sha256,64),'Authority or cleanup receipt digest required')
        payload.update(expectedRevision=expected_revision,proofSha256=proof_sha256)
    else:require(expected_revision is None and proof_sha256 is None,'Unexpected action arguments')
    if window is not None:
        require(action=='renew' and window_fields(window),'Exact test window required')
        payload['window']=window
    if deadline_monotonic_ms is not None:
        require(action=='renew' and window is not None and type(deadline_monotonic_ms) is int and
                0<deadline_monotonic_ms<2**53,'Exact local monotonic deadline required')
        payload['deadlineMonotonicMs']=deadline_monotonic_ms
    if action=='window_finalize':
        require(hex_string(window_id,32),'Exact cleanup window identity required')
        payload['windowId']=window_id
    else:require(window_id is None,'Unexpected cleanup window identity')
    raw=(json.dumps(payload,separators=(',',':'))+'\n').encode()
    require(len(raw)<=(384 if window is not None else 256),'Oversized broker request')
    return raw


def validate_reply(value,action,role,epoch,expected_revision=None,*,window_id=None):
    require(isinstance(value,dict) and set(value)=={'action','role','epoch','result'} and
            value['action']==action and value['role']==role and value['epoch']==epoch,'Broker response identity differs')
    r=value['result']
    require(isinstance(r,dict),'Broker result missing')
    if action=='status':
        require(set(r)=={'role','phase','bootMatches','epoch','policySha256','leaseSeconds','leaseRevision','observedAt','leaseOpen','leaseComplete','remainingMilliseconds','managementHandshake'},'Incomplete observed gate status')
        require(isinstance(r['policySha256'],str) and len(r['policySha256'])==64 and all(c in '0123456789abcdef' for c in r['policySha256']),'Missing installed root policy digest')
        require(r['role']==role and r['epoch']==epoch and r['phase']=='ACTIVE' and r['bootMatches'] is True,'Root gate not active in current boot')
        require(type(r['leaseRevision']) is int and r['leaseRevision']>=0 and type(r['leaseSeconds']) is int and 30<=r['leaseSeconds']<=120,'Invalid root gate revision/TTL')
        require(type(r['leaseOpen']) is bool and type(r['leaseComplete']) is bool and type(r['remainingMilliseconds']) is int and 0<=r['remainingMilliseconds']<=r['leaseSeconds']*1000,'Invalid observed lease expiry')
        require((r['leaseOpen'] and r['remainingMilliseconds']>0) or (not r['leaseOpen'] and r['remainingMilliseconds']==0 and not r['leaseComplete']),'Inconsistent lease state')
        if role=='cp':require(not r['leaseOpen'] and not r['leaseComplete'] and r['remainingMilliseconds']==0,'CP can never have public VPN lease')
        require(type(r['observedAt']) in [int,float] and math.isfinite(r['observedAt']) and r['observedAt']>=0,'Missing monotonic observation')
        h=r['managementHandshake']
        require(isinstance(h,dict) and set(h)=={'ownPublicKeySha256','peerPublicKeySha256','lastHandshakeAt','ageSeconds','observedAt','observedMonotonic'},'Missing management handshake observation')
        require(all(isinstance(h[k],str) and len(h[k])==64 and all(c in '0123456789abcdef' for c in h[k])
                    for k in ['ownPublicKeySha256','peerPublicKeySha256']) and
                h['ownPublicKeySha256']!=h['peerPublicKeySha256'],'Invalid management identities')
        require(type(h['lastHandshakeAt']) is int and h['lastHandshakeAt']>=0 and
                all(type(h[k]) in [int,float] and math.isfinite(h[k]) and h[k]>=0 for k in ['observedAt','observedMonotonic']) and
                0<=r['observedAt']-h['observedMonotonic']<=5 and h['lastHandshakeAt']<=h['observedAt'],'Invalid management timestamps')
        if h['lastHandshakeAt']==0:require(h['ageSeconds'] is None,'Never-handshaken peer cannot have an age')
        else:require(type(h['ageSeconds']) in [int,float] and math.isfinite(h['ageSeconds']) and h['ageSeconds']>=0 and
                     abs(h['ageSeconds']-(h['observedAt']-h['lastHandshakeAt']))<0.001,'Inconsistent management age')
    elif action in ['renew','close']:
        require(set(r)=={'status','seconds','leaseRevision'} and r['status']==('LEASE_RENEWED' if action=='renew' else 'VPN_GATE_CLOSED'),'Invalid lease response')
        require(type(r['leaseRevision']) is int and r['leaseRevision']>=0,'Missing committed lease revision')
        require(type(r['seconds']) is int and (30<=r['seconds']<=120 if action=='renew' else r['seconds']==0),'Invalid committed lease TTL')
        if action=='renew':require(r['leaseRevision']==expected_revision+1,'Unconfirmed lease revision')
    elif action=='window_status':
        require(role=='dp-a' and set(r)=={'phase','bootMatches','leaseRevision','leaseOpen','remainingMilliseconds',
                'window','windowActive','effectiveEndUtcMs','lastProofSha256','cleanupSha256'} and
                isinstance(r['phase'],str) and type(r['bootMatches']) is bool and
                type(r['leaseOpen']) is type(r['windowActive']) is bool and
                type(r['leaseRevision']) is int and r['leaseRevision']>=0 and
                type(r['remainingMilliseconds']) is int and 0<=r['remainingMilliseconds']<=120000 and
                r['leaseOpen']==(r['remainingMilliseconds']>0) and
                all(r[k] is None or hex_string(r[k],64) for k in ('lastProofSha256','cleanupSha256')),
                'Invalid test window readback')
        if r['window'] is None:
            require(r['effectiveEndUtcMs'] is None and not r['windowActive'] and not r['leaseOpen'] and
                    r['lastProofSha256'] is None and r['cleanupSha256'] is None,'Window proof for absent state')
        else:
            require(window_fields(r['window']) and type(r['effectiveEndUtcMs']) is int and
                    r['window']['readyAtUtcMs']<r['effectiveEndUtcMs']<=min(r['window']['endUtcMs'],r['window']['fixtureEndsUtcMs']) and
                    (not r['windowActive'] or r['cleanupSha256'] is None),'Invalid bound or cleanup latch')
    elif action=='window_finalize':
        require(role=='dp-a' and r=={'status':'WINDOW_CLEANUP_RECORDED','windowId':window_id,'leaseRevision':expected_revision},
                'Window cleanup acknowledgement differs')
    elif action=='heartbeat':
        require(r=={'status':'CONTROL_HEARTBEAT_RECORDED','watchdogSeconds':180},'Invalid control heartbeat receipt')
    elif action=='start':
        require(r in [{'status':'ALREADY_ACTIVE_NO_MUTATION'},{'status':'MANAGEMENT_ACTIVE_VPN_GATE_CLOSED','role':role}],'Invalid activation receipt')
    else:
        require(set(r)=={'status'} and r['status'] in ['CLOSED_ENGINE_STOPPED_OWN_NETWORK_REMOVED','NO_OPERATIONAL_RESOURCES','ALREADY_CLOSED_NO_MUTATION'],'Stop not confirmed')
    return r


def call(action,role,epoch,expected_revision=None,proof_sha256=None,*,window=None,window_id=None,deadline_monotonic_ms=None):
    data=request(action,expected_revision,proof_sha256,window=window,window_id=window_id,
                 deadline_monotonic_ms=deadline_monotonic_ms)
    for p in [SOCKET.parent,*SOCKET.parent.parents]:
        s=p.lstat()
        require(stat.S_ISDIR(s.st_mode) and not p.is_symlink() and s.st_uid==0 and not s.st_mode&0o022,'Unsafe broker directory')
    s=SOCKET.lstat()
    require(stat.S_ISSOCK(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o660 and s.st_gid==os.getgid(),'Unsafe broker endpoint')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as peer:
        peer.settimeout(150 if action in ['start','stop'] else 25);peer.connect(str(SOCKET));peer.sendall(data);peer.shutdown(socket.SHUT_WR)
        result=b''
        while b'\n' not in result:
            chunk=peer.recv(4097-len(result))
            require(chunk and len(result)+len(chunk)<=4096,'Broker EOF or oversized response')
            result+=chunk
        require(result.endswith(b'\n') and result.count(b'\n')==1,'Invalid broker response framing')
        value=json.loads(result)
        return validate_reply(value,action,role,epoch,expected_revision,window_id=window_id)


def systemd_units(runtime_uid):
    if type(runtime_uid) is not int or runtime_uid not in (1001, 1002):
        raise RuntimeError('Exact installed runtime UID required')
    # System units default to root. Do not add redundant User=root: with NNP
    # and seccomp restrictions systemd can drop CAP_SETUID from the effective
    # set despite its presence in CapabilityBoundingSet. The otherwise exact
    # pattern passed the synthetic native implicit-root A/B on systemd 255.
    # Hide all homes and other runtime directories. Expose only the fixed
    # role's private user-manager socket, read-only in this mount namespace.
    # Local systemctl --user manager commands use this path on systemd 259.
    # This does not start a user manager or grant runtime callers new RPCs.
    common=f'''[Service]
Type=exec
Group=root
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/run /var/lib/uzel-ops /etc/wireguard
ProtectHome=tmpfs
BindReadOnlyPaths=/run/user/{runtime_uid}/systemd/private
PrivateTmp=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_SYS_RESOURCE CAP_AUDIT_WRITE
Restart=no
TimeoutStartSec=150
RuntimeMaxSec=150
KillMode=control-group
LimitNOFILE=256
TasksMax=32
MemoryMax=128M
'''
    return {'uzel-ops.socket':'''[Unit]
Description=Fixed UZEL operational root broker
[Socket]
ListenStream=/run/uzel-ops/broker.sock
SocketUser=root
SocketGroup=uzel-runtime
SocketMode=0660
DirectoryMode=0755
Accept=yes
MaxConnections=4
RemoveOnStop=yes
[Install]
WantedBy=sockets.target
''','uzel-ops@.service':'''[Unit]
Description=One authenticated operational request
'''+common+'''StandardInput=socket
StandardOutput=socket
StandardError=journal
ExecStart=/usr/bin/python3 -I -B /usr/local/lib/uzel-ops/root_helper.py broker
''','uzel-ops-watchdog.service':'''[Unit]
Description=Stop owned runtime after lost operational supervision
'''+common+'''ExecStart=/usr/bin/python3 -I -B /usr/local/lib/uzel-ops/root_helper.py watchdog
''','uzel-ops-watchdog.timer':'''[Unit]
Description=Independent bounded operational watchdog
[Timer]
OnBootSec=30
OnUnitActiveSec=30
AccuracySec=1
Unit=uzel-ops-watchdog.service
[Install]
WantedBy=timers.target
'''}
