#!/usr/bin/env python3
"""Standalone disposable Linux CI fixture. No deployment imports or networking."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import grp
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

NAME = 'broker-fixture'
UID, OTHER_UID = 16052, 16053
LIB = Path('/usr/local/lib/broker-fixture')
STATE = Path('/var/lib/broker-fixture')
RUN = Path('/run/broker-fixture')
ETC = Path('/etc/broker-fixture')
SOCK = RUN / 'broker.sock'
MAX_REQUEST = 256
CAPABILITIES = [1, 2, 6, 7, 12, 24, 29]
CAP_MASK = sum(1 << bit for bit in CAPABILITIES)


class ProbeFailure(RuntimeError):
    def __init__(self, stage, error):
        self.stage = stage
        # All probe inputs/commands/error messages are fixed fixture literals;
        # caller-provided bytes are never interpolated into diagnostic messages.
        self.error_type = type(error).__name__
        super().__init__(str(error)[:800])


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def write_new(path, value, mode=0o600):
    data = value.encode() if isinstance(value, str) else value
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), mode)
    return {'inode': path.stat().st_ino, 'sha256': hashlib.sha256(data).hexdigest()}


def run(argv, timeout=20, ok=(0,), input=None):
    child = subprocess.Popen(argv, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = child.communicate(input, timeout=timeout)
    except BaseException:
        # Only this newly created process group; never global user/process kills.
        try: os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError: pass
        try: child.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            try: os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            child.communicate(timeout=3)
        raise
    result = subprocess.CompletedProcess(argv, child.returncode, stdout, stderr)
    require(result.returncode in ok, 'Command failed: ' + argv[0] + ' exit ' + str(result.returncode)
            + ': ' + result.stderr.decode(errors='replace')[-1000:])
    return result


def unit_files():
    # The paths are synthetic. The capability and sandbox directives are explicit
    # so native evidence can compare them with the effective service properties.
    common = '''[Service]
Type=exec
User=root
Group=root
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/run /var/lib/broker-fixture /etc/broker-fixture
ProtectHome=yes
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
    return {
        NAME + '.socket': '''[Unit]
Description=Synthetic bounded broker socket
[Socket]
ListenStream=/run/broker-fixture/broker.sock
SocketUser=root
SocketGroup=broker-fixture
SocketMode=0660
DirectoryMode=0755
Accept=yes
MaxConnections=4
RemoveOnStop=yes
[Install]
WantedBy=sockets.target
''',
        NAME + '@.service': '[Unit]\nDescription=Synthetic one-request root broker\n' + common + '''StandardInput=socket
StandardOutput=socket
StandardError=journal
ExecStart=/usr/bin/python3 -I -B /usr/local/lib/broker-fixture/worker.py --connection
''',
        NAME + '-watchdog.service': '[Unit]\nDescription=Synthetic stop-only watchdog\n' + common + '''ExecStart=/usr/bin/python3 -I -B /usr/local/lib/broker-fixture/worker.py --watchdog
''',
        NAME + '-watchdog.timer': '''[Unit]
Description=Synthetic bounded watchdog timer
[Timer]
OnBootSec=30
OnUnitActiveSec=30
AccuracySec=1
Unit=broker-fixture-watchdog.service
[Install]
WantedBy=timers.target
''',
        NAME + '-forbidden.service': '''[Unit]
Description=Synthetic sentinel must never start
[Service]
Type=oneshot
ExecStart=/usr/bin/touch /var/lib/broker-fixture/UNEXPECTED_DAEMON_START
Restart=no
'''}


def decode_request(data):
    require(isinstance(data, bytes) and 0 < len(data) <= MAX_REQUEST, 'FRAME_SIZE')
    require(data.endswith(b'\n') and data.count(b'\n') == 1, 'FRAME_SHAPE')
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError):
        raise RuntimeError('FRAME_JSON')
    require(type(value) is dict and value == {'op': 'probe'}, 'FIXED_OPERATION_ONLY')
    return value


def read_frame(peer):
    deadline = time.monotonic() + 3
    data = b''
    while True:
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'FRAME_DEADLINE')
        peer.settimeout(remaining)
        chunk = peer.recv(MAX_REQUEST + 1 - len(data))
        if not chunk:
            return decode_request(data)
        data += chunk
        require(len(data) <= MAX_REQUEST, 'FRAME_SIZE')
        # One request is accepted only after EOF; no ignored trailing bytes.


def proc_security():
    values = {}
    for line in Path('/proc/self/status').read_text().splitlines():
        key, _, value = line.partition(':')
        if key in ['NoNewPrivs', 'CapEff', 'CapBnd', 'CapAmb']:
            values[key] = value.strip()
    require(set(values) == {'NoNewPrivs', 'CapEff', 'CapBnd', 'CapAmb'}, 'Security fields unavailable')
    require(values['NoNewPrivs'] == '1', 'NoNewPrivileges not effective')
    require(int(values['CapEff'], 16) == CAP_MASK and int(values['CapBnd'], 16) == CAP_MASK
            and int(values['CapAmb'], 16) == 0, 'Capabilities differ: ' + json.dumps(values, sort_keys=True))
    return values


def harmless_probe():
    stage = 'root-identity'
    try:
        require(os.getuid() == 0, 'Broker not root')
        stage = 'process-security'
        security = proc_security()
        stage = 'fixed-root-command'
        root = run(['/usr/bin/id', '-u']).stdout.strip()
        stage = 'fixed-unprivileged-command'
        child = run(['/usr/sbin/runuser', '-u', NAME, '--', '/usr/bin/id', '-u']).stdout.strip()
        require(root == b'0' and child == str(UID).encode(), 'Fixed identity command failed')
        stage = 'source-read-only'
        blocked, observed_errno = False, None
        try:
            write_new(LIB / 'UNEXPECTED_WRITABLE_SOURCE', b'unexpected')
        except OSError as error:
            # EROFS proves ProtectSystem, not an ordinary DAC permission failure.
            import errno
            observed_errno = error.errno
            blocked = error.errno == errno.EROFS
        require(blocked, 'ProtectSystem source write errno: ' + str(observed_errno))
        for directory in [STATE, ETC]:
            stage = 'declared-state-write:' + directory.name
            fd, path = None, directory / ('probe-' + str(os.getpid()))
            try:
                fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.write(fd, b'synthetic\n')
                os.fsync(fd)
            finally:
                if fd is not None:
                    os.close(fd)
                    path.unlink()
    except Exception as error:
        raise ProbeFailure(stage, error) from None
    return {'rootUid': 0, 'childUid': UID, 'security': security, 'sourceReadOnly': True,
            'declaredStatePathsWritable': True, 'fixedCommandOnly': True}


def connection():
    with socket.socket(fileno=0) as peer:
        stage = 'peer-credentials'
        try:
            pid, uid, gid = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(pid > 0 and uid == UID and gid == UID, 'PEER_UID_REJECTED')
            stage = 'bounded-request-frame'
            read_frame(peer)
            stage = 'fixed-probe'
            response = {'status': 'PASS', 'peerUid': uid, 'probe': harmless_probe()}
        except Exception as error:
            response = {'status': 'REJECT', 'reason': type(error).__name__,
                        'stage': error.stage if isinstance(error, ProbeFailure) else stage}
            if isinstance(error, ProbeFailure):
                response['diagnostic'] = {'errorType': error.error_type, 'fixedProbeDetail': str(error)}
        try:
            peer.sendall(json.dumps(response, sort_keys=True).encode() + b'\n')
        except OSError:
            pass


def watchdog():
    proc_security()
    heartbeat = json.loads((STATE / 'heartbeat.json').read_text())
    require(set(heartbeat) == {'at'} and type(heartbeat['at']) in [int, float], 'Invalid heartbeat')
    age = time.monotonic() - heartbeat['at']
    require(age >= 0, 'Clock domain differs')
    if age >= 3:
        target = STATE / 'watchdog.json'
        if not target.exists():
            write_new(target, json.dumps({'decision': 'STOP_ONLY_MARKER', 'ageSeconds': age,
                                         'startsExecuted': 0, 'security': proc_security()}))
    # Deliberately no systemctl, process start, or restart action. The independent
    # timer can only write this harmless one-time stop intent for the fixture.


CLIENT = '''import json,socket,sys,time
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(8);s.connect(sys.argv[1])
s.sendall(bytes.fromhex(sys.argv[2]))
if sys.argv[3]=='stall':time.sleep(4)
else:s.shutdown(socket.SHUT_WR)
b=b''
while True:
 try:c=s.recv(4096)
 except ConnectionResetError:break
 if not c:break
 b+=c
 if len(b)>4096:raise RuntimeError('oversized reply')
s.close();print(b.decode(),end='')
'''


def client(user, data, mode='eof'):
    command = ['/usr/bin/python3', '-I', '-B', '-c', CLIENT, str(SOCK), data.hex(), mode]
    if user:
        command = ['/usr/sbin/runuser', '-u', user, '--'] + command
    result = run(command, timeout=12)
    return json.loads(result.stdout)


def owned_stat(path, mode):
    row = path.lstat()
    require(row.st_uid == 0 and stat.S_IMODE(row.st_mode) == mode and not path.is_symlink(),
            'Unexpected owned path: ' + str(path))
    return row


def unlink_owned(path, receipt):
    row = owned_stat(path, 0o644 if path.suffix in ['.service', '.socket', '.timer'] else 0o600)
    require(stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and row.st_ino == receipt['inode']
            and hashlib.sha256(path.read_bytes()).hexdigest() == receipt['sha256'], 'Owned file changed')
    path.unlink()


def names_present():
    result = run(['systemctl', 'list-units', '--all', '--plain', '--no-legend', 'broker-fixture*'])
    rows = []
    allowed = set(unit_files())
    for line in result.stdout.decode().splitlines():
        fields = line.split()
        if fields and fields[0] == '●':
            fields.pop(0)
        if fields:
            name = fields[0]
            require(name in allowed or (name.startswith(NAME + '@') and name.endswith('.service')),
                    'Unexpected fixture unit name')
            rows.append(name)
    return rows


def stopped(unit):
    result = run(['systemctl', 'show', unit, '-p', 'ActiveState', '-p', 'MainPID'])
    values = dict(line.split('=', 1) for line in result.stdout.decode().splitlines())
    require(values.get('ActiveState') in ['inactive', 'failed'] and values.get('MainPID', '0') == '0',
            'Unit stop unconfirmed: ' + unit)


def cleanup(created):
    result = {'status': 'FAIL', 'unitsStopped': False, 'usersRemoved': False, 'filesRemoved': False}
    try:
        require(not created.get('pendingAccount'), 'Account creation outcome unknown; preserve for inspection')
        if created['reloaded']:
            units = names_present()
            run(['systemctl', 'stop', NAME + '.socket', NAME + '-watchdog.timer', NAME + '-watchdog.service'], timeout=25)
            for name in units:
                run(['systemctl', 'stop', name], timeout=20)
                stopped(name)
            for name in [NAME + '.socket', NAME + '-watchdog.timer']:
                if name in created['enabled']:
                    run(['systemctl', 'disable', name])
            result['unitsStopped'] = True
        else:
            result['unitsStopped'] = True
        for user, expected in reversed(created['users']):
            require(pwd.getpwnam(user).pw_uid == expected, 'User identity changed')
            procs = run(['pgrep', '-u', str(expected)], ok=(0, 1))
            require(procs.returncode == 1 and not procs.stdout and not procs.stderr, 'Fixture user still has processes')
            run(['userdel', user])
        if created['group']:
            try: group = grp.getgrnam(NAME)
            except KeyError:
                # userdel can remove its now-empty same-name primary group.
                # Accept only absence of BOTH the owned name and owned GID.
                try: grp.getgrgid(UID)
                except KeyError: pass
                else: raise RuntimeError('Owned GID was replaced by a foreign group')
            else:
                require(group.gr_gid == UID, 'Group identity changed')
                run(['groupdel', NAME])
                for lookup, value in [(grp.getgrnam, NAME), (grp.getgrgid, UID)]:
                    try: lookup(value)
                    except KeyError: pass
                    else: raise RuntimeError('Group removal unconfirmed')
        result['usersRemoved'] = True
        for path, receipt in reversed(list(created['files'].items())):
            unlink_owned(path, receipt)
        if created['reloaded']:
            run(['systemctl', 'daemon-reload'])
        # Worker-generated files are narrowly enumerated, never recursively deleted.
        for path in [STATE / 'watchdog.json', LIB / 'UNEXPECTED_WRITABLE_SOURCE']:
            if path.exists():
                row = owned_stat(path, 0o600)
                require(stat.S_ISREG(row.st_mode) and row.st_nlink == 1, 'Unexpected generated file')
                path.unlink()
        require(not (STATE / 'UNEXPECTED_DAEMON_START').exists(), 'Forbidden daemon ran')
        for path, inode in reversed(created['dirs']):
            row = path.lstat()
            require(stat.S_ISDIR(row.st_mode) and not path.is_symlink() and row.st_uid == 0 and row.st_ino == inode,
                    'Directory ownership changed')
            path.rmdir()
        result['filesRemoved'] = True
        require(not SOCK.exists(), 'Socket remains')
        result['status'] = 'PASS'
    except Exception as error:
        result['error'] = str(error)
    return result


def native(output):
    require(sys.platform == 'linux' and os.getuid() == 0, 'Disposable Linux root runner only')
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('CI') == 'true'
            and os.environ.get('RUN_BROKER_REPRO') == 'yes'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'Explicit hosted disposable CI opt-in required')
    require(Path('/run/systemd/system').is_dir(), 'Real systemd required')
    require(Path('/proc/1/comm').read_text().strip() == 'systemd', 'Real systemd PID 1 required')
    require(not output.exists(), 'Output must be new')
    for path in [LIB, STATE, RUN, ETC]:
        require(not path.exists() and not path.is_symlink(), 'Refuse existing fixture path')
    for name in [NAME, 'broker-other']:
        try:
            pwd.getpwnam(name)
        except KeyError:
            pass
        else:
            raise RuntimeError('Refuse existing fixture user')
    for value in [UID, OTHER_UID]:
        try:
            pwd.getpwuid(value)
        except KeyError:
            pass
        else:
            raise RuntimeError('Refuse occupied fixture UID')
    try:
        grp.getgrnam(NAME)
    except KeyError:
        pass
    else:
        raise RuntimeError('Refuse existing fixture group')
    try:
        grp.getgrgid(UID)
    except KeyError:
        pass
    else:
        raise RuntimeError('Refuse occupied fixture GID')
    units = unit_files()
    for base in ['/etc/systemd/system', '/run/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system']:
        # Includes foreign drop-ins, aliases and dependency links, not just the
        # five unit filenames. The fixture never merges with existing units.
        require(not list(Path(base).rglob('broker-fixture*')), 'Refuse existing fixture unit or drop-in')
    require(not names_present(), 'Refuse already loaded fixture units')
    output.mkdir(mode=0o755)
    os.chmod(output, 0o755)
    created = {'users': [], 'group': False, 'dirs': [], 'files': {}, 'reloaded': False, 'enabled': []}
    report = {'status': 'FAIL', 'cases': {}, 'scope': 'SYNTHETIC_AF_UNIX_SYSTEMD_ONLY'}
    started = time.monotonic()
    def deadline(signum, frame):
        raise RuntimeError('Fixture deadline exceeded')
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(330)
    try:
        created['pendingAccount'] = 'group'
        run(['groupadd', '--gid', str(UID), NAME]); created['group'] = True
        require(grp.getgrnam(NAME).gr_gid == UID, 'Created group readback differs')
        created['pendingAccount'] = None
        for user, uid in [(NAME, UID), ('broker-other', OTHER_UID)]:
            created['pendingAccount'] = user
            run(['useradd', '--uid', str(uid), '--gid', NAME, '--no-create-home', '--no-log-init', '--shell', '/usr/sbin/nologin', user])
            created['users'].append((user, uid))
            require(pwd.getpwnam(user).pw_uid == uid and pwd.getpwnam(user).pw_gid == UID, 'Created account readback differs')
            created['pendingAccount'] = None
        for path, mode in [(LIB, 0o700), (STATE, 0o700), (RUN, 0o755), (ETC, 0o700)]:
            path.mkdir(mode=mode); os.chmod(path, mode); created['dirs'].append((path, path.stat().st_ino))
        created['files'][LIB / 'worker.py'] = write_new(LIB / 'worker.py', Path(__file__).read_bytes())
        created['files'][STATE / 'heartbeat.json'] = write_new(STATE / 'heartbeat.json', json.dumps({'at': time.monotonic()}))
        for name, content in units.items():
            path = Path('/etc/systemd/system') / name
            created['files'][path] = write_new(path, content, 0o644)
        run(['systemd-analyze', 'verify', *[str(Path('/etc/systemd/system') / name) for name in units]])
        run(['systemctl', 'daemon-reload']); created['reloaded'] = True
        for name in [NAME + '.socket', NAME + '-watchdog.timer']:
            created['enabled'].append(name)  # Before effect, including partial failures.
            run(['systemctl', 'enable', '--now', name])
        row = owned_stat(SOCK, 0o660)
        require(stat.S_ISSOCK(row.st_mode) and row.st_gid == UID, 'Socket permissions differ')
        report['socket'] = {'uid': row.st_uid, 'gid': row.st_gid, 'mode': oct(stat.S_IMODE(row.st_mode)), 'activation': 'Accept=yes'}
        report['effectiveSandbox'] = run(['systemctl', 'show', NAME + '-watchdog.service', '-p', 'NoNewPrivileges', '-p', 'ProtectSystem',
                                         '-p', 'CapabilityBoundingSet', '-p', 'Restart', '-p', 'RuntimeMaxUSec', '-p', 'KillMode', '-p', 'ReadWritePaths']).stdout.decode()
        positive = client(NAME, b'{"op":"probe"}\n')
        report['initialProbeResponse'] = positive
        require(positive.get('status') == 'PASS', 'Positive broker request failed')
        report['cases']['authorized_fixed_probe'] = positive
        tests = [('wrong_uid_same_group', 'broker-other', b'{"op":"probe"}\n', 'eof'),
                 ('root_uid_rejected', None, b'{"op":"probe"}\n', 'eof'),
                 ('unknown_operation', NAME, b'{"op":"start"}\n', 'eof'),
                 ('path_argument', NAME, b'{"op":"probe","path":"/tmp/other"}\n', 'eof'),
                 ('malformed_json', NAME, b'{broken}\n', 'eof'),
                 ('two_frames', NAME, b'{"op":"probe"}\n{"op":"probe"}\n', 'eof'),
                 ('oversized', NAME, b'x' * 257, 'eof'),
                 ('bounded_incomplete', NAME, b'{"op":', 'stall')]
        for name, user, payload, mode in tests:
            tick = time.monotonic()
            value = client(user, payload, mode)
            require(value.get('status') == 'REJECT', 'Negative request accepted: ' + name)
            report['cases'][name] = {'status': 'PASS', 'reply': value, 'elapsedSeconds': time.monotonic() - tick}
        # A rejected/malformed caller must not poison later socket activation.
        require(client(NAME, b'{"op":"probe"}\n').get('status') == 'PASS', 'Broker unusable after rejection')
        end = time.monotonic() + 65
        while not (STATE / 'watchdog.json').exists() and time.monotonic() < end:
            time.sleep(0.25)
        timer_result = json.loads((STATE / 'watchdog.json').read_text())
        require(timer_result['decision'] == 'STOP_ONLY_MARKER' and timer_result['startsExecuted'] == 0
                and timer_result['ageSeconds'] >= 3, 'Timer did not observe stale heartbeat')
        stopped(NAME + '-forbidden.service')
        require(not (STATE / 'UNEXPECTED_DAEMON_START').exists(), 'Watchdog started sentinel daemon')
        report['cases']['timer_stale_no_daemon_start'] = {'status': 'PASS', 'observation': timer_result}
        properties = run(['systemctl', 'show', NAME + '-watchdog.service', '-p', 'NoNewPrivileges', '-p', 'ProtectSystem',
                          '-p', 'CapabilityBoundingSet', '-p', 'Restart', '-p', 'RuntimeMaxUSec', '-p', 'KillMode', '-p', 'ReadWritePaths'])
        report['effectiveSandbox'] = properties.stdout.decode()
        report['status'] = 'PASS'
    except Exception as error:
        report['error'] = str(error)
    finally:
        # Main phase <=330 seconds, scoped cleanup <=90 seconds. A timed-out
        # cleanup remains FAIL/preserved, never an excuse to broaden deletion.
        signal.alarm(90)
        report['cleanup'] = cleanup(created)
        signal.alarm(0)
        if report['cleanup']['status'] != 'PASS':
            report['status'] = 'FAIL'
        report['elapsedSeconds'] = time.monotonic() - started
        write_new(output / 'result.json', json.dumps(report, indent=2, sort_keys=True) + '\n', 0o644)
    print(json.dumps({'status': report['status'], 'cases': len(report['cases']), 'cleanup': report['cleanup']['status']}))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--connection', action='store_true')
    parser.add_argument('--watchdog', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.connection:
        connection()
    elif args.watchdog:
        watchdog()
    else:
        require(args.output is not None, 'Output required')
        sys.exit(native(args.output.resolve()))
