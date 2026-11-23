"""Fixed finite system service for the existing CP and DP-A actors."""

import argparse
import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import socket
import stat
import struct
import sys
import time

UNIT = 'uzel-standby.service'
RELEASE = Path('/usr/local/lib/uzel-standby')
CONTROL = Path('/run/uzel-standby/control.sock')
MAX_RUNTIME = 7200
STOP_RESERVE = 430
PERIOD = 25
FRAME_LIMIT = 32768


class Rejected(RuntimeError):
    """A request refused without a state transition."""


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def read_frame(peer, seconds=3):
    deadline = time.monotonic()+seconds
    value = bytearray()
    while not value.endswith(b'\n'):
        remaining = deadline-time.monotonic()
        require(remaining > 0 and len(value) < FRAME_LIMIT, 'Frame limit')
        peer.settimeout(remaining)
        part = peer.recv(FRAME_LIMIT-len(value))
        require(part and time.monotonic() < deadline, 'Incomplete frame')
        value.extend(part)
    require(value.count(b'\n') == 1, 'Exactly one request frame')
    row = json.loads(value)
    require(isinstance(row, dict), 'Invalid request')
    return row


def send_frame(peer, value):
    raw = encode(value)
    require(len(raw) <= FRAME_LIMIT, 'Reply too large')
    peer.settimeout(3)
    peer.sendall(raw)


def units(uid):
    require(uid in (1001, 1002), 'Exact runtime UID required')
    return {UNIT: f'''[Unit]
Description=Bounded UZEL standby runtime
After=user@{uid}.service uzel-ops.socket uzel-ops-watchdog.timer
Requires=user@{uid}.service uzel-ops.socket uzel-ops-watchdog.timer

[Service]
Type=exec
User=uzel-runtime
Group=uzel-runtime
Slice=system.slice
Delegate=no
UMask=0077
RuntimeDirectory=uzel-standby
RuntimeDirectoryMode=0700
WorkingDirectory=/srv/uzel
Environment=HOME=/srv/uzel XDG_RUNTIME_DIR=/run/user/{uid} DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus LC_ALL=C
ExecStart=/usr/bin/python3 -I -B /usr/local/lib/uzel-standby/standby_service.py
LoadCredential=peer.key:/etc/uzel-standby/peer.key
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/srv/uzel/operational -/srv/uzel/operational-backup-fence
ProtectHome=tmpfs
BindReadOnlyPaths=/run/user/{uid}
ProtectControlGroups=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
Restart=no
RuntimeMaxSec={MAX_RUNTIME + STOP_RESERVE}s
TimeoutStopSec={STOP_RESERVE}s
KillMode=mixed
TasksMax=64
'''}


class PeerAuthority:
    """One request/reply over the private WG path. Fresh nonce and role-bound MAC."""

    def __init__(self, key, epoch, own, far, port):
        require(len(key)==32 and re.fullmatch('[0-9a-f]{32}', epoch), 'Pinned authority key/epoch required')
        self.key, self.epoch, self.own, self.far, self.port = key, epoch, own, far, port
        self.seen = {}

    def envelope(self, kind, body):
        payload = {'kind':kind, 'epoch':self.epoch, 'body':body}
        mac = hmac.new(self.key, encode(payload), hashlib.sha256).hexdigest()
        return {**payload, 'mac':mac}

    def verify(self, kind, value):
        require(set(value)=={'kind','epoch','body','mac'} and value['kind']==kind and value['epoch']==self.epoch and
                isinstance(value['body'], dict) and isinstance(value['mac'], str) and
                hmac.compare_digest(value['mac'], self.envelope(kind,value['body'])['mac']), 'Peer authentication failed')
        return value['body']

    def connect(self, action, data=None, *, timeout=24):
        query = {'nonce':secrets.token_hex(16), 'sentUtcMs':time.time_ns()//1_000_000, 'action':action, 'data':data}
        with socket.create_connection((self.far, self.port), timeout=4, source_address=(self.own, 0)) as peer:
            send_frame(peer, self.envelope('authority-request',query))
            answer = self.verify('authority-reply',read_frame(peer,timeout))
        require(set(answer)=={'nonce','requestSha256','result'} and answer['nonce']==query['nonce'] and
                answer['requestSha256']==digest(query), 'Authority response is unrelated')
        return answer['result']

    def listen(self):
        peer = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        peer.bind((self.own,self.port));peer.listen(3)
        return peer

    def reply(self, peer, address, dispatch):
        require(address[0]==self.far and peer.getsockname()[0]==self.own, 'Authority peer address changed')
        request = self.verify('authority-request',read_frame(peer))
        now = time.time_ns()//1_000_000
        require(set(request)=={'nonce','sentUtcMs','action','data'} and isinstance(request['nonce'],str) and
                re.fullmatch('[a-f0-9]{32}',request['nonce']) and type(request['sentUtcMs']) is int and
                abs(now-request['sentUtcMs'])<=5000, 'Unbound authority request')
        mono = time.monotonic()
        self.seen = {k:t for k,t in self.seen.items() if 0<=mono-t<30}
        require(len(self.seen)<64 and request['nonce'] not in self.seen, 'Duplicate authority request')
        self.seen[request['nonce']] = mono
        result = dispatch(request['action'],request['data'])
        send_frame(peer,self.envelope('authority-reply',{'nonce':request['nonce'],'requestSha256':digest(request),'result':result}))


class Control:
    """Only status and generation-bound transitions. Socket loss has no lifecycle effect."""

    def __init__(self, actor, evidence):
        self.actor = actor
        self.evidence = evidence
        self.nonce = secrets.token_hex(16)
        self.sequence = 0
        self.last_request = self.last_reply = None

    def dispatch(self, request):
        if request == {'action':'status'}:
            return {'generation':self.nonce,'sequence':self.sequence,**self.actor.status()}
        if (set(request)!={'action','generation','sequence','data'} or request['generation']!=self.nonce or
                type(request['sequence']) is not int or not isinstance(request['action'],str)):
            raise Rejected('Malformed or stale request')
        proof = digest(request)
        if request['sequence']==self.sequence and self.last_request==proof:
            return self.last_reply
        if request['sequence']!=self.sequence+1:
            raise Rejected('Stale or unresolved request')
        self.actor.validate(request['action'],request['data'])
        sequence = request['sequence']
        self.evidence.save('host-request-intent',{'requestSha256':proof,'action':request['action'],'sequence':sequence})
        result = self.actor.command(request['action'],request['data'])
        answer = {'generation':self.nonce,'sequence':sequence,'result':result}
        self.evidence.save('host-request-result',answer)
        self.sequence,self.last_request,self.last_reply = sequence,proof,answer
        return answer


def serve(actor, evidence, *, control_path=CONTROL, clock=time.monotonic, period=PERIOD):
    local = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    stopping = False

    def stop_signal(*_):
        nonlocal stopping
        stopping = True

    def public_error(error):
        return {'status':'BLOCKED','errorType':type(error).__name__,'errorSha256':digest(str(error))}

    previous = signal.signal(signal.SIGTERM,stop_signal)
    listener = None
    control = Control(actor,evidence)
    start = clock()
    next_tick = start+period
    try:
        local.bind(str(control_path));local.listen(4)
        with selectors.DefaultSelector() as ready:
            ready.register(local,selectors.EVENT_READ)
            while not stopping and not actor.terminal and clock()<start+MAX_RUNTIME-STOP_RESERVE:
                if clock()>=next_tick:
                    actor.tick()
                    next_tick = clock()+period
                authority = actor.listener
                if listener is not authority:
                    if listener is not None:
                        ready.unregister(authority_fd)
                        listener.close()
                    listener = authority
                    if listener is not None:
                        authority_fd = listener.fileno()
                        ready.register(listener,selectors.EVENT_READ)
                events = ready.select(max(0,min(next_tick-clock(),2)))
                for item,_ in events:
                    if item.fileobj.fileno()<0 or stopping or actor.terminal:
                        continue
                    with item.fileobj.accept()[0] as peer:
                        if item.fileobj is local:
                            _,uid,gid = struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                            if (uid,gid)!=(os.getuid(),os.getgid()):
                                continue
                            try:
                                request = read_frame(peer)
                            except (OSError,ValueError,RuntimeError):
                                continue
                            try:
                                answer = control.dispatch(request)
                            except Rejected as error:
                                answer = public_error(error)
                            try:
                                send_frame(peer,answer)
                            except OSError:
                                pass  # Exact repeat returns the recorded ACK, without another effect.
                        else:
                            actor.serve_peer(peer,peer.getpeername())
        if not actor.terminal:
            evidence.save('host-controlled-stop',actor.stop())
        return 0
    except Exception as error:
        try:
            evidence.save('host-failure',public_error(error))
        finally:
            actor.fail(error)
        return 1
    finally:
        if listener is not None:
            listener.close()
        local.close();signal.signal(signal.SIGTERM,previous)


def immutable_files(release):
    for path in (release,*release.parents):
        row = path.lstat()
        require(stat.S_ISDIR(row.st_mode) and row.st_uid==0 and not row.st_mode&0o022, 'Unsafe release directory')

    def read(path):
        with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as opened:
            row = os.fstat(opened.fileno())
            require(stat.S_ISREG(row.st_mode) and row.st_uid==0 and not row.st_mode&0o022 and
                    row.st_nlink==1 and row.st_size<=8*1024*1024, 'Unsafe immutable release file')
            data = opened.read()
            def identity(s):
                return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_size,s.st_nlink,s.st_mtime_ns,s.st_ctime_ns)
            require(identity(row)==identity(os.fstat(opened.fileno()))==identity(path.lstat()), 'Release file changed')
            return data

    manifest = json.loads(read(release/'manifest.json'))
    require(isinstance(manifest,dict) and len(manifest)<=90 and
            all(re.fullmatch('[a-zA-Z0-9_.-]+',name) and name not in ('.','..','manifest.json') and
                isinstance(sha,str) and re.fullmatch('[a-f0-9]{64}',sha) for name,sha in manifest.items()), 'Unsafe manifest')
    require({path.name for path in release.iterdir()}=={*manifest,'manifest.json'}, 'Release closure differs')
    values = {name:read(release/name) for name in manifest}
    require(all(hashlib.sha256(raw).hexdigest()==manifest[name] for name,raw in values.items()), 'Release hash differs')
    return values


def main():
    require(os.getuid()==os.getgid() and os.getuid() in (1001,1002), 'Runtime identity differs')
    require(Path('/proc/self/cgroup').read_text().strip()=='0::/system.slice/'+UNIT, 'Not the approved system service')
    require(ctypes.CDLL(None).prctl(4,0,0,0,0)==0, 'Cannot restrict process dump access')  # PR_SET_DUMPABLE
    os.umask(0o077)
    data = immutable_files(RELEASE)
    sys.path.insert(0,str(RELEASE))
    from standby_roles import run
    return run(data,Path(os.environ['CREDENTIALS_DIRECTORY'],'peer.key').read_bytes())


def client():
    parser = argparse.ArgumentParser()
    parser.add_argument('request',help='One JSON request or status')
    args = parser.parse_args()
    request = {'action':'status'} if args.request=='status' else json.loads(args.request)
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as peer:
        peer.settimeout(3);peer.connect(str(CONTROL));send_frame(peer,request)
        print(json.dumps(read_frame(peer,390)))


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status':'STANDBY_SERVICE_FAILED','type':type(error).__name__,'sha256':digest(str(error))}),file=sys.stderr)
        raise SystemExit(1)
