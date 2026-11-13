#!/usr/bin/env python3
"""Disposable, native Docker 29.1.3 rootless DNS-null persistence reproducer.

Run only as root on a fresh GitHub-hosted Ubuntu 24.04 runner. Two synthetic
BusyBox containers are primed before the baseline. The actual scenario seeds
three null fields in the stopped fixture, performs one cold engine restart,
and starts /bin/true once to force a real metadata persistence checkpoint.
No external daemon, production data, credentials or network ports are used.
"""
import copy
import grp
import hashlib
import json
import os
import pwd
import re
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

from disk_metadata import DNS_FIELDS, audit, fingerprints, read_snapshot

UID = 16013
USER = 'docker-repro'
HOME_DIR = Path('/var/lib/docker-dns-repro')
BIN = Path('/opt/docker-dns-repro/bin')
BASE = Path('/var/tmp/docker-dns-repro')
RUNTIME = Path('/run/user/16013')
APPARMOR = Path('/etc/apparmor.d/docker-dns-repro-rootlesskit')
DELEGATE = Path('/etc/systemd/system/user@16013.service.d')
STATIC = 'https://download.docker.com/linux/static/stable/x86_64/'
ARCHIVES = {
    'docker-29.1.3.tgz': 'c019c608ba2bb009dd673f3230e4d743f36a78d36166c6c2444c05d0aa9ff0d9',
    'docker-rootless-extras-29.1.3.tgz': '32dc3dd0d8b512ccf30a7efe84d360b5ade65ac4fec92a2a5ad0fe791da6ab0d',
}
IMAGE = 'busybox:1.37.0@sha256:66a6306db78bf2dbf3487f293aa8d6990d8e506fdffab9cc43fe422becf886e4'
ENV = {
    'HOME': str(HOME_DIR), 'USER': USER, 'LOGNAME': USER,
    'PATH': str(BIN) + ':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    'XDG_RUNTIME_DIR': str(RUNTIME), 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + str(RUNTIME / 'bus'),
    'DOCKER_HOST': 'unix://' + str(RUNTIME / 'docker.sock'),
}
STATE = {'stage': 'entry', 'groups': [], 'containerIds': [], 'unitCreated': False,
         'profileLoaded': False, 'accountCreated': False, 'managerStarted': False}


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def write(path, value, mode=0o600):
    path = Path(path)
    require(not path.exists() and not path.is_symlink(), 'Evidence path already exists')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    os.fchmod(fd, mode)
    with os.fdopen(fd, 'w') as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write('\n')


class CommandDeadline(RuntimeError):
    pass


def run(args, timeout=30, check=True):
    """One bounded process group; no retries and no inherited daemon context."""
    proc = subprocess.Popen([str(a) for a in args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except BaseException as error:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate(timeout=5)
        if isinstance(error, subprocess.TimeoutExpired):
            raise CommandDeadline('Command deadline: ' + Path(str(args[0])).name) from error
        raise
    result = subprocess.CompletedProcess(args, proc.returncode, stdout, stderr)
    if check and result.returncode:
        # Inputs are exclusively synthetic, but omit argument strings and mask
        # addresses/URL queries before publishing bounded error diagnostics.
        detail = re.sub(r'(https?://[^?\s]+)\?[^\s]+', r'\1?<redacted>', stderr[-2000:])
        detail = re.sub(r'(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])', '<address>', detail)
        STATE['commandFailure'] = {'executable': Path(str(args[0])).name, 'exit': result.returncode, 'stderr': detail}
        raise RuntimeError('Command failed: ' + Path(str(args[0])).name + ' exit ' + str(result.returncode))
    return result


def userrun(*args, **kwargs):
    return run(['runuser', '-u', USER, '--', 'env', '-i',
                *[key + '=' + value for key, value in ENV.items()], *args], **kwargs)


def docker(*args, **kwargs):
    return userrun(str(BIN / 'docker'), *args, **kwargs)


def props():
    result = userrun('systemctl', '--user', 'show', 'docker.service', '-p', 'MainPID',
                     '-p', 'ActiveState', '-p', 'ControlGroup', '-p', 'Restart',
                     '-p', 'RuntimeMaxUSec', '-p', 'TimeoutStopUSec')
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)


def until(check, seconds, message):
    deadline = time.monotonic() + seconds
    while True:
        value = check()
        if value:
            return value
        require(time.monotonic() < deadline, message)
        time.sleep(0.2)


def protected(row):
    mounts = sorted(copy.deepcopy(row['Mounts']), key=lambda item: item['Destination'])
    require(len({item['Destination'] for item in mounts}) == len(mounts), 'Duplicate mount destination')
    return {key: copy.deepcopy(row[key]) for key in ['Id', 'Name', 'Image', 'Config', 'HostConfig']} | {
        'Mounts': mounts, 'NetworkSettings': copy.deepcopy(row['NetworkSettings']['Networks'])}


def diff_paths(before, after, path=''):
    """Diagnostic JSON pointers only; this does not alter comparison semantics."""
    if before == after:
        return []
    if isinstance(before, dict) and isinstance(after, dict):
        paths = []
        for key in sorted(set(before) | set(after)):
            child = path + '/' + str(key).replace('~', '~0').replace('/', '~1')
            if key not in before or key not in after:
                paths.append(child)
            else:
                paths.extend(diff_paths(before[key], after[key], child))
        return paths
    if isinstance(before, list) and isinstance(after, list):
        paths = []
        for index in range(max(len(before), len(after))):
            child = path + '/' + str(index)
            if index >= len(before) or index >= len(after):
                paths.append(child)
            else:
                paths.extend(diff_paths(before[index], after[index], child))
        return paths
    return [path or '/']


def capture_readback(out, phase, ids, network, before_engine, before_network):
    raw = {name: inspect(cid) for name, cid in ids.items()}
    current = {'engine': {name: protected(row) for name, row in raw.items()},
               'network': network_snapshot(network)}
    expected = {'engine': before_engine, 'network': before_network}
    paths = diff_paths(expected, current)
    write(out / ('synthetic-' + phase + '-readback.json'),
          {'expected': expected, 'current': current, 'rawEngine': raw, 'diffPaths': paths}, 0o644)
    STATE['comparison'] = {'phase': phase, 'diffPaths': paths[:128],
                           'diffCount': len(paths), 'truncated': len(paths) > 128}
    return raw, current, '; '.join(paths[:12])


def inspect(cid):
    return json.loads(docker('inspect', cid).stdout)[0]


def network_snapshot(network):
    return json.loads(docker('network', 'inspect', network).stdout)[0]


def remember_groups():
    group = props()['ControlGroup']
    if group:
        STATE['groups'].append(group)
    root = Path('/sys/fs/cgroup/user.slice/user-16013.slice')
    if root.is_dir():
        for cid in STATE['containerIds']:
            STATE['groups'].extend('/' + str(p.relative_to('/sys/fs/cgroup'))
                                   for p in root.rglob('docker-' + cid + '.scope'))


def stop_proof():
    state = props()
    require(state['MainPID'] == '0' and state['ActiveState'] in ['inactive', 'failed'], 'Engine stop unconfirmed')
    require(userrun('pgrep', '-u', str(UID), '-f', 'dockerd|rootlesskit|containerd|slirp4netns',
                    check=False).returncode == 1, 'Engine processes remain')
    for name in set(STATE['groups']):
        require(name.startswith('/') and '..' not in Path(name).parts, 'Unsafe cgroup path')
        path = Path('/sys/fs/cgroup') / name.lstrip('/')
        if path.exists():
            for file in [path / 'cgroup.procs', *path.rglob('cgroup.procs')]:
                if file.exists():
                    require(not file.read_text().strip(), 'Container or engine cgroup remains populated')
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(1)
    try:
        try:
            client.connect(str(RUNTIME / 'docker.sock'))
        except OSError:
            pass
        else:
            raise RuntimeError('Engine socket still accepts connections')
    finally:
        client.close()
    for cid in STATE['containerIds']:
        data = json.loads((HOME_DIR / 'docker/containers' / cid / 'config.v2.json').read_text())
        require(not any(data['State'].get(key) for key in ['Running', 'Paused', 'Restarting', 'Pid']),
                'Synthetic container not stopped')
    return {'engineMainPID': 0, 'engineState': state['ActiveState'], 'engineProcesses': 0,
            'recordedCgroupsEmpty': True, 'engineSocketUnavailable': True, 'allSyntheticContainersStopped': True}


def stop_engine():
    remember_groups()
    userrun('systemctl', '--user', 'stop', 'docker.service', timeout=45)
    return stop_proof()


def start_engine():
    before = props()
    require(before['MainPID'] == '0' and before['ActiveState'] == 'inactive', 'Start requires stopped engine')
    require(before['Restart'] == 'no' and before['RuntimeMaxUSec'] == '5min'
            and before['TimeoutStopUSec'] == '30s', 'Systemd deadline/restart mismatch')
    userrun('systemctl', '--user', 'start', '--no-block', 'docker.service')

    def ready():
        try:
            value = docker('info', '--format', '{{json .}}', timeout=4, check=False)
            return json.loads(value.stdout) if value.returncode == 0 else None
        except CommandDeadline:
            return None

    info = until(ready, 60, 'Docker API readiness deadline')
    require(info['ServerVersion'] == '29.1.3' and 'name=rootless' in info['SecurityOptions'], 'Pinned rootless engine required')
    require(info['CgroupVersion'] == '2' and info['CgroupDriver'] == 'systemd', 'Cgroup delegation mismatch')
    require(info['DockerRootDir'] == str(HOME_DIR / 'docker'), 'Unexpected Docker data root')
    remember_groups()
    return info


def pull_and_create():
    STATE['stage'] = 'synthetic_fixture_setup'
    docker('pull', '--platform=linux/amd64', IMAGE, timeout=180)
    image = json.loads(docker('image', 'inspect', IMAGE).stdout)[0]
    require(any(value.endswith('@' + IMAGE.split('@')[1]) for value in image['RepoDigests']), 'Pinned image digest mismatch')
    require(image['Architecture'] == 'amd64', 'Wrong synthetic image architecture')
    network = docker('network', 'create', '--internal', 'dns-repro-internal').stdout.strip()
    require(re.fullmatch(r'[a-f0-9]{64}', network), 'Invalid fixture network ID')
    bind = HOME_DIR / 'bind-fixture'
    bind.mkdir(mode=0o700)
    os.chown(bind, UID, UID)
    (bind / 'fixture.txt').write_text('synthetic read-only fixture\n')
    os.chown(bind / 'fixture.txt', UID, UID)
    ids = {}
    for name in ['control', 'fixture']:
        args = ['create', '--name=dns-repro-' + name, '--pull=never', '--network=dns-repro-internal',
                '--network-alias=' + name, '--restart=no', '--read-only', '--cap-drop=ALL',
                '--security-opt=no-new-privileges', '--pids-limit=32', '--memory=32m', '--memory-swap=32m',
                '--entrypoint=/bin/true']
        if name == 'fixture':
            args.append('--volume=' + str(bind) + ':/fixture:ro')
        cid = docker(*args, IMAGE).stdout.strip()
        require(re.fullmatch(r'[a-f0-9]{64}', cid), 'Invalid synthetic container ID')
        ids[name] = cid
        STATE['containerIds'].append(cid)
        # Materialize its ordinary endpoint once, before capturing any baseline.
        # The cold-reload scenario below starts only the fixture, once.
        docker('start', cid)
        require(docker('wait', cid).stdout.strip() == '0', 'Setup /bin/true failed')
        current = inspect(cid)
        require(not current['State']['Running'] and current['State']['Pid'] == 0, 'Setup container not stopped')
        require(not current['HostConfig']['PortBindings'], 'Unexpected published ports')
        require(current['HostConfig']['RestartPolicy']['Name'] == 'no', 'Unexpected restart policy')
    require(set(docker('ps', '-aq', '--no-trunc').stdout.split()) == set(ids.values()), 'Foreign fixture container')
    require(network_snapshot(network)['Internal'] is True, 'Fixture network is not internal')
    return ids, network


def scenario(out):
    start_engine()
    ids, network = pull_and_create()
    before_engine = {name: protected(inspect(cid)) for name, cid in ids.items()}
    before_network = network_snapshot(network)
    stop_engine()
    before_disk = {name: read_snapshot(HOME_DIR / 'docker/containers' / cid, UID) for name, cid in ids.items()}
    STATE['stage'] = 'seed_legacy_nulls_engine_stopped'
    stop_proof()
    file = HOME_DIR / 'docker/containers' / ids['fixture'] / 'hostconfig.json'
    h = copy.deepcopy(before_disk['fixture']['spec']['hostconfig'])
    require(all(key in h and h[key] in [None, []] for key in DNS_FIELDS), 'Unexpected initial DNS configuration')
    for key in DNS_FIELDS:
        h[key] = None
    s = file.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == UID and s.st_nlink == 1
            and stat.S_IMODE(s.st_mode) == 0o600 and not file.is_symlink(), 'Unsafe synthetic metadata file')
    # Only this newly created disposable fixture is written; engine is proven off.
    with file.open('w') as output:
        output.write(json.dumps(h, separators=(',', ':')) + '\n')
        output.flush()
        os.fsync(output.fileno())
    seeded = read_snapshot(file.parent, UID)
    require(seeded['spec']['config'] == before_disk['fixture']['spec']['config']
            and seeded['spec']['mountpoints'] == before_disk['fixture']['spec']['mountpoints'], 'Seed changed unrelated components')
    before_disk['fixture'] = seeded
    write(out / 'synthetic-before.json', {'disk': before_disk, 'engine': before_engine, 'network': before_network}, 0o644)
    STATE['stage'] = 'cold_engine_reload'
    start_engine()
    _, cold, paths = capture_readback(out, 'cold', ids, network, before_engine, before_network)
    for name in ids:
        require(cold['engine'][name] == before_engine[name], 'Cold reload changed protected spec or full attachments: ' + paths)
    require(cold['network'] == before_network, 'Cold reload changed full network snapshot: ' + paths)
    STATE['stage'] = 'single_fixture_checkpoint'
    docker('start', ids['fixture'])
    remember_groups()
    require(docker('wait', ids['fixture']).stdout.strip() == '0', 'Checkpoint /bin/true failed')
    raw_checkpoint, checkpoint, paths = capture_readback(out, 'checkpoint', ids, network, before_engine, before_network)
    for name in ids:
        current = raw_checkpoint[name]
        require(not any(current['State'].get(key) for key in ['Running', 'Paused', 'Restarting', 'Pid']), 'Checkpoint container not stopped')
        require(checkpoint['engine'][name] == before_engine[name], 'Checkpoint changed protected spec or full attachments: ' + paths)
    require(checkpoint['network'] == before_network, 'Checkpoint changed full network snapshot: ' + paths)
    stopped = stop_engine()
    STATE['stage'] = 'disk_audit'
    after_disk = {name: read_snapshot(HOME_DIR / 'docker/containers' / cid, UID) for name, cid in ids.items()}
    receipts = {name: audit(before_disk[name], after_disk[name], '29.1.3') for name in ids}
    require(receipts['control']['status'] == 'PASS_EXACT_DISK_SPEC', 'Control raw disk changed')
    require(receipts['fixture']['status'] == 'PASS_CONFIRMED_DOCKER_29_1_3_DNS_DEFAULTS', 'Expected DNS persistence transition missing')
    write(out / 'synthetic-after.json', {'disk': after_disk, 'audit': receipts}, 0o644)
    return {'status': 'PASS', 'dockerVersion': '29.1.3', 'image': IMAGE, 'audit': receipts,
            'rawBefore': {name: fingerprints(value) for name, value in before_disk.items()},
            'rawAfter': {name: fingerprints(value) for name, value in after_disk.items()},
            'setupContainerStarts': 2, 'scenarioContainerStarts': 1, 'scenarioProcess': '/bin/true',
            'engineStartsTotal': 2, 'coldEngineRestarts': 1, 'setupPulls': 1, 'scenarioPulls': 0,
            'legacyNullsSeededOnlyInNewStoppedFixture': True, 'fullAttachmentsExact': True,
            'fullNetworkSnapshotExact': True, 'controlContainerRawSpecExact': True,
            'configAndMountPointsExact': True, 'stop': stopped}


def preflight():
    require(os.geteuid() == 0 and os.uname().machine == 'x86_64', 'Root amd64 disposable runner required')
    require(os.environ.get('CI') == 'true' and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'GitHub-hosted runner only')
    require(Path('/proc/1/comm').read_text().strip() == 'systemd', 'Native systemd required')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(release.get('ID') == 'ubuntu' and release.get('VERSION_ID', '').strip('"') == '24.04', 'Ubuntu 24.04 required')
    require(Path('/opt/hostedtoolcache').is_dir(), 'Hosted runner toolcache absent')
    require(not any(Path(p).exists() for p in ['/etc/kubernetes', '/etc/rancher', '/var/lib/kubelet']), 'Existing managed workload marker')
    require(Path('/sys/fs/cgroup/cgroup.controllers').is_file(), 'Unified cgroup v2 required')
    require(not profile_loaded(), 'Existing fixture AppArmor profile; no reuse')
    for path in [HOME_DIR, BIN.parent, BASE, RUNTIME, APPARMOR, DELEGATE]:
        require(not path.exists() and not path.is_symlink(), 'Existing fixture path; no reuse')
    for lookup, value in [(pwd.getpwnam, USER), (pwd.getpwuid, UID), (grp.getgrnam, USER), (grp.getgrgid, UID)]:
        try:
            lookup(value)
        except KeyError:
            continue
        raise RuntimeError('Existing fixture account or group; no reuse')
    require(re.fullmatch(r'[a-f0-9]{40}', os.environ.get('REVIEW_HEAD_SHA', '')), 'Exact source SHA required')
    out = Path(os.environ['OUT_DIR'])
    workspace = Path(__file__).resolve().parent
    require(out.is_absolute() and out.parent.resolve(strict=True) == workspace and out.name == 'results', 'Unexpected artifact path')
    require(not out.exists() and not out.is_symlink(), 'Existing output path; no reuse')
    out.mkdir(mode=0o755)
    out.chmod(0o755)
    return out


def profile_loaded():
    return any(line.split(' ', 1)[0] == 'docker-dns-repro-rootlesskit'
               for line in Path('/sys/kernel/security/apparmor/profiles').read_text().splitlines())


def setup():
    STATE['stage'] = 'download_pinned_static_archives'
    BASE.mkdir(mode=0o700)
    BIN.mkdir(parents=True, mode=0o755)
    BIN.parent.chmod(0o755)
    BIN.chmod(0o755)
    for name, expected in ARCHIVES.items():
        archive = BASE / name
        with urllib.request.urlopen(STATIC + name, timeout=45) as source, archive.open('xb') as output:
            while chunk := source.read(1024 * 1024):
                output.write(chunk)
        require(hashlib.sha256(archive.read_bytes()).hexdigest() == expected, 'Official archive SHA256 mismatch')
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                if member.isdir():
                    continue
                path = Path(member.name)
                require(member.isfile() and len(path.parts) == 2 and path.parts[0] in ['docker', 'docker-rootless-extras']
                        and not (BIN / path.name).exists(), 'Unexpected static archive entry')
                with tar.extractfile(member) as source, (BIN / path.name).open('xb') as output:
                    output.write(source.read())
                (BIN / path.name).chmod(0o755)
    require('29.1.3' in run([BIN / 'dockerd', '--version']).stdout, 'Wrong static Docker version')
    STATE['stage'] = 'create_disposable_account'
    run(['groupadd', '--gid', str(UID), USER])
    run(['useradd', '--no-log-init', '--no-create-home', '--no-user-group', '--uid', str(UID), '--gid', USER,
         '--home-dir', str(HOME_DIR), '--shell', '/bin/bash', USER], timeout=45)
    STATE['accountCreated'] = True
    require(pwd.getpwnam(USER).pw_uid == UID and pwd.getpwnam(USER).pw_gid == UID, 'Fixture account identity mismatch')
    HOME_DIR.mkdir(mode=0o700)
    os.chown(HOME_DIR, UID, UID)
    for path in ['/etc/subuid', '/etc/subgid']:
        require(any(line.startswith(USER + ':') and int(line.split(':')[2]) >= 65536
                    for line in Path(path).read_text().splitlines()), 'Subordinate ID range unavailable')
    STATE['stage'] = 'scoped_apparmor_and_user_manager'
    APPARMOR.write_text('abi <abi/4.0>,\ninclude <tunables/global>\nprofile docker-dns-repro-rootlesskit '
                        + str(BIN / 'rootlesskit') + ' flags=(unconfined) {\n  userns,\n}\n')
    APPARMOR.chmod(0o644)
    run(['apparmor_parser', '-r', APPARMOR])
    STATE['profileLoaded'] = True
    require(profile_loaded(), 'Scoped profile not loaded')
    DELEGATE.mkdir(mode=0o755)
    (DELEGATE / 'delegate.conf').write_text('[Service]\nDelegate=cpu cpuset io memory pids\n')
    run(['systemctl', 'daemon-reload'])
    run(['loginctl', 'enable-linger', USER])
    run(['systemctl', 'start', 'user@16013.service'])
    STATE['managerStarted'] = True
    until(lambda: (RUNTIME / 'bus').is_socket(), 15, 'Fixture user manager unavailable')
    controllers = Path('/sys/fs/cgroup/user.slice/user-16013.slice/user@16013.service/cgroup.controllers')
    require({'cpu', 'memory', 'pids'} <= set(controllers.read_text().split()), 'Missing delegated controllers')
    unit = HOME_DIR / '.config/systemd/user/docker.service'
    unit.parent.mkdir(parents=True, mode=0o700)
    unit.write_text('[Unit]\nDescription=Disposable rootless DNS persistence reproducer\n[Service]\n'
                    + ''.join('Environment=' + key + '=' + value + '\n' for key, value in ENV.items())
                    + 'ExecStart=' + str(BIN / 'dockerd-rootless.sh') + ' --host=' + ENV['DOCKER_HOST']
                    + ' --config-file=' + str(HOME_DIR / 'daemon.json')
                    + '\nRestart=no\nRuntimeMaxSec=300\nTimeoutStartSec=70\nTimeoutStopSec=30\n'
                    'Delegate=yes\nTasksMax=infinity\nLimitNOFILE=infinity\nLimitNPROC=infinity\nKillMode=mixed\n')
    write(HOME_DIR / 'daemon.json', {'data-root': str(HOME_DIR / 'docker'), 'storage-driver': 'overlay2',
                                   'live-restore': False, 'log-driver': 'local'})
    for path in HOME_DIR.rglob('*'):
        os.chown(path, UID, UID)
    STATE['unitCreated'] = True
    userrun('systemctl', '--user', 'daemon-reload')


def cleanup():
    proof = {'status': 'PASS', 'syntheticFilesPreservedForRunnerDisposal': True}
    errors = []
    # useradd may partially succeed before a timeout. Discover only the identity
    # which preflight proved absent; never skip cleanup because its call failed.
    try:
        user = pwd.getpwnam(USER)
        require(user.pw_uid == UID and user.pw_dir == str(HOME_DIR), 'Unexpected cleanup account')
        STATE['accountCreated'] = True
    except KeyError:
        pass
    if STATE['accountCreated']:
        if STATE['unitCreated'] and (RUNTIME / 'bus').is_socket():
            try:
                proof['engine'] = stop_engine()
            except BaseException as error:
                errors.append('engine_stop: ' + type(error).__name__ + ': ' + str(error))
        elif STATE['unitCreated']:
            errors.append('user manager unavailable before engine stop proof')
        for args in [['loginctl', 'disable-linger', USER], ['loginctl', 'terminate-user', USER]]:
            try:
                run(args, timeout=40)
            except BaseException as error:
                errors.append(Path(args[0]).name + ': ' + type(error).__name__)
        try:
            require(not Path('/var/lib/systemd/linger', USER).exists(), 'Linger still enabled')
            until(lambda: run(['pgrep', '-u', str(UID)], check=False).returncode == 1,
                  10, 'Fixture UID processes remain')
            proof['lingerDisabled'] = True
            proof['fixtureUserProcesses'] = 0
        except BaseException as error:
            errors.append('user_cleanup: ' + str(error))
    if not errors:
        if DELEGATE.exists():
            (DELEGATE / 'delegate.conf').unlink()
            DELEGATE.rmdir()
            run(['systemctl', 'daemon-reload'])
        # Parser completion can be lost after a successful kernel load. Read
        # actual named policy state instead of trusting the local success flag.
        if profile_loaded():
            require(APPARMOR.is_file() and not APPARMOR.is_symlink()
                    and APPARMOR.stat().st_uid == 0, 'Scoped policy file unavailable for verified unload')
            run(['apparmor_parser', '-R', APPARMOR])
            require(not profile_loaded(), 'Scoped AppArmor policy remains loaded')
        if APPARMOR.exists():
            APPARMOR.unlink()
        proof['scopedPolicyRemoved'] = True
    if errors:
        proof.update(status='FAIL_UNCONFIRMED_CLEANUP', errors=errors)
    return proof


def deadline(_signal, _frame):
    raise RuntimeError('Bounded job deadline or termination signal')


def main():
    os.umask(0o077)
    out = preflight()  # No cleanup mutation when preflight rejects an existing host.
    signal.signal(signal.SIGALRM, deadline)
    signal.signal(signal.SIGTERM, deadline)
    signal.alarm(780)
    result = {'status': 'FAIL', 'sourceHead': os.environ['REVIEW_HEAD_SHA']}
    try:
        setup()
        result.update(scenario(out))
    except BaseException as error:
        result.update(status='FAIL', failedStage=STATE['stage'],
                      error=type(error).__name__ + ': ' + str(error)[:500],
                      commandFailure=copy.deepcopy(STATE.get('commandFailure')),
                      comparison=copy.deepcopy(STATE.get('comparison')))
    finally:
        signal.alarm(0)
        try:
            final = cleanup()
        except BaseException as error:
            final = {'status': 'FAIL_UNCONFIRMED_CLEANUP', 'error': type(error).__name__ + ': ' + str(error)[:500]}
        result['cleanup'] = final
        if final['status'] != 'PASS':
            result['status'] = 'FAIL'
        result.update(staticSource=STATIC, archiveSha256=ARCHIVES,
                      archiveProvenance='SHA256 computed from official HTTPS archives; not a publisher signature',
                      fixtureOnly=True, automaticRetries=0,
                      limitation='Ubuntu24.04 hosted runner, official static Docker29.1.3, synthetic seeded legacy nulls; no production environment reproduced')
        write(out / 'result.json', result, 0o644)
        print(json.dumps({'status': result['status'], 'stage': STATE['stage'], 'cleanup': final['status']}))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
