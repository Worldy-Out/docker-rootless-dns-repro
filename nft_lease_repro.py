#!/usr/bin/env python3
"""Disposable Linux namespace reproduction of a timed TCP access gate.

No external traffic, existing network changes, application code, or credentials.
Requires a disposable GitHub Actions Linux runner, root, iproute2, and nftables.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import uuid


CLIENT = '192.0.2.1'
SERVER = '192.0.2.2'
GATED = 18080
CONTROL = 18081
TTL = 4
TABLE = 'timed_gate'
SCRIPT = Path(__file__).resolve()
MAX_CASE_SECONDS = 30


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def rules(ct_first=False):
    def chain(direction, selector):
        early = 'ct state established,related accept\n' if ct_first else ''
        late = '' if ct_first else 'ct state established,related accept\n'
        address = 'saddr' if direction == 'input' else 'daddr'
        return f'''chain {direction} {{
 type filter hook {direction} priority -50; policy accept;
 {early}tcp {selector} {GATED} ip {address} @allowed accept
 tcp {selector} {GATED} counter drop
 {late}}}'''
    return f'''table inet {TABLE} {{
 comment "synthetic timed TCP gate"
 set allowed {{ type ipv4_addr; flags timeout; timeout {TTL}s; }}
 {chain('input', 'dport')}
 {chain('output', 'sport')}
}}
add element inet {TABLE} allowed {{ {CLIENT} timeout {TTL}s }}
'''


def renew_rules():
    # One atomic netlink transaction, fixed reviewed element only. Plain add of
    # an already present element is not assumed to reset its expiration.
    return f'''delete element inet {TABLE} allowed {{ {CLIENT} }}
add element inet {TABLE} allowed {{ {CLIENT} timeout {TTL}s }}
'''


def drop_counters(table):
    counters = {}
    for item in table['nftables']:
        rule = item.get('rule', {})
        expressions = rule.get('expr', [])
        if rule.get('table') == TABLE and any('drop' in row for row in expressions):
            counter = [row['counter'] for row in expressions if 'counter' in row]
            require(rule['chain'] not in counters and len(counter) == 1, 'Unexpected drop-rule count')
            counters[rule['chain']] = counter[0]
    require(set(counters) == {'input', 'output'}, 'Both gate counters required')
    return counters


def lease_present(value):
    rows = [item['set'] for item in value['nftables'] if 'set' in item]
    require(len(rows) == 1 and rows[0]['name'] == 'allowed' and
            rows[0]['family'] == 'inet' and rows[0]['table'] == TABLE,
            'Unexpected lease set readback')
    # libnftables JSON encodes timeout/expires in seconds (not kernel-internal
    # milliseconds). A per-element timeout equal to the set default is omitted.
    # Do not infer units from magnitude or accept a permanent bare address.
    item = rows[0]
    require(item.get('type') == 'ipv4_addr' and item.get('flags') in (['timeout'], 'timeout') and
            type(item.get('timeout')) is int and item['timeout'] == TTL,
            'Unexpected set type, timeout flag or default lease')
    elements = rows[0].get('elem', [])
    require(isinstance(elements, list) and len(elements) <= 1, 'Unexpected lease elements')
    for element in elements:
        require(isinstance(element, dict) and set(element) == {'elem'}, 'Unknown timed element encoding')
        fields = element['elem']
        require(isinstance(fields, dict) and {'val', 'expires'} <= set(fields) <= {'val', 'timeout', 'expires'},
                'Unexpected timed element fields')
        timeout = fields.get('timeout', item['timeout'])
        require(fields['val'] == CLIENT and type(timeout) is int and timeout == TTL and
                type(fields['expires']) is int and 0 <= fields['expires'] <= timeout,
                'Unexpected lease address or timeout')
    return bool(elements)


def measure(case, first, second, denied, counters):
    require(case in {'unsafe-order', 'gate-first', 'renewal'}, 'Unknown measurement case')
    require(second['atMonotonic'] - first['atMonotonic'] >= 2, 'Short measurement window')
    for sample in (first, second):
        require(set(sample['streams']) == {'gated', 'control'}, 'Wrong stream identities')
        for stream in sample['streams'].values():
            require(type(stream['bytes']) is int and stream['bytes'] > 0 and stream['closed'] is False,
                    'An established fixture stream terminated independently of the gate')
            require(type(stream['lastByteMonotonic']) in (int, float) and
                    stream['lastByteMonotonic'] <= sample['atMonotonic'], 'Invalid receive timestamp')
    require(second['streams']['control']['bytes'] > first['streams']['control']['bytes'] and
            second['atMonotonic'] - second['streams']['control']['lastByteMonotonic'] < 0.6,
            'Ungated active control did not continue')
    require(denied == {'newGatedConnectionConnected': False}, 'Expired lease accepted a new connection')
    require(counters['input']['packets'] > 0, 'No observed kernel input denial')
    delta = second['streams']['gated']['bytes'] - first['streams']['gated']['bytes']
    if case == 'unsafe-order':
        require(delta > 0, 'Unsafe ct-first control did not reproduce the bypass')
        verdict = 'EXPECTED_UNSAFE_ESTABLISHED_FLOW_BYPASS_REPRODUCED'
    else:
        require(delta == 0, 'Expired gate continued an established flow')
        require(counters['output']['packets'] > 0, 'No observed kernel output denial')
        verdict = 'PASS_ESTABLISHED_AND_NEW_GATED_TRAFFIC_BLOCKED_CONTROL_CONTINUES'
    return verdict, delta


def emit(value):
    print(json.dumps(value), flush=True)


def server_worker():
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    listeners = []
    clients = []
    threads = []

    def stream(conn):
        clients.append(conn)
        conn.settimeout(0.5)
        counter = 0
        try:
            while not stop.is_set():
                counter += 1
                conn.sendall(('sample-%08d\n' % counter).encode())
                stop.wait(0.1)
        except (OSError, TimeoutError):
            pass
        finally:
            conn.close()

    try:
        for port in (GATED, CONTROL):
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((SERVER, port))
            listener.listen(8)
            listener.setblocking(False)
            listeners.append(listener)
        emit({'ready': 'server', 'pid': os.getpid()})
        deadline = time.monotonic() + MAX_CASE_SECONDS
        while not stop.is_set() and time.monotonic() < deadline:
            for listener in select.select(listeners, [], [], 0.2)[0]:
                conn, _ = listener.accept()
                require(len(threads) < 12, 'Unexpected fixture connection count')
                thread = threading.Thread(target=stream, args=(conn,), daemon=True)
                thread.start();threads.append(thread)
        require(stop.is_set(), 'Server lifetime deadline expired')
    finally:
        stop.set()
        for listener in listeners:
            listener.close()
        for conn in clients:
            try: conn.shutdown(socket.SHUT_RDWR)
            except OSError: pass
        for thread in threads:
            thread.join(timeout=1)


def client_worker():
    stop = threading.Event()
    lock = threading.Lock()
    state = {}
    connections = []
    threads = []

    def receive(kind, conn):
        try:
            while not stop.is_set():
                try: data = conn.recv(4096)
                except socket.timeout: continue
                with lock:
                    if not data:
                        state[kind]['closed'] = True
                        break
                    state[kind]['bytes'] += len(data)
                    state[kind]['lastByteMonotonic'] = time.monotonic()
        except OSError:
            with lock: state[kind]['closed'] = True
        finally:
            conn.close()

    try:
        for kind, port in [('gated', GATED), ('control', CONTROL)]:
            conn = socket.create_connection((SERVER, port), timeout=2)
            conn.settimeout(0.2)
            connections.append(conn)
            state[kind] = {'bytes': 0, 'lastByteMonotonic': None, 'closed': False}
            thread = threading.Thread(target=receive, args=(kind, conn), daemon=True)
            thread.start();threads.append(thread)
        emit({'ready': 'client', 'pid': os.getpid(), 'connectionsCreated': 2})
        deadline = time.monotonic() + MAX_CASE_SECONDS
        while time.monotonic() < deadline:
            if not select.select([sys.stdin], [], [], 0.2)[0]: continue
            line = sys.stdin.readline()
            if not line: break
            request = json.loads(line)
            require(set(request) == {'op'}, 'Unexpected fixture request')
            if request['op'] == 'sample':
                with lock: emit({'atMonotonic': time.monotonic(), 'streams': state})
            elif request['op'] == 'new':
                connected = False
                try:
                    conn = socket.create_connection((SERVER, GATED), timeout=0.6)
                    connected = True;conn.close()
                except (OSError, TimeoutError): pass
                emit({'newGatedConnectionConnected': connected})
            elif request['op'] == 'finish':
                emit({'finished': True});break
            else: raise RuntimeError('Unknown fixture operation')
    finally:
        stop.set()
        for conn in connections:
            try: conn.shutdown(socket.SHUT_RDWR)
            except OSError: pass
        for thread in threads:
            thread.join(timeout=1)


class Lab:
    def __init__(self, case, directory):
        self.case, self.directory = case, directory
        suffix = uuid.uuid4().hex[:10]
        self.names = {'server': 'lease-s-'+suffix, 'client': 'lease-c-'+suffix}
        self.namespaces = {}
        self.namespace_intents = set()
        self.workers = []
        self.commands = []
        self.cleanup = None
        self.sequence = 0

    def run(self, args, *, data=None, check=True, timeout=8):
        result = subprocess.run(args, input=data, capture_output=True, text=True,
                                timeout=timeout, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        self.commands.append({'argv': args, 'exit': result.returncode,
                              'stderrSha256': hashlib.sha256(result.stderr.encode()).hexdigest()})
        if check:
            require(result.returncode == 0, 'Fixture command failed: '+args[0]+' '+str(result.returncode))
        return result

    def inside(self, role, args, **kwargs):
        return self.run(['ip', 'netns', 'exec', self.names[role], *args], **kwargs)

    def save(self, name, value):
        path = self.directory/name
        with path.open('x') as stream:
            json.dump(value, stream, indent=2);stream.write('\n')
        path.chmod(0o644)  # All records are synthetic; artifact uploader is unprivileged.

    def table(self, name):
        raw = self.inside('server', ['nft', '-j', 'list', 'table', 'inet', TABLE]).stdout
        value = json.loads(raw);self.save(name, value);return value

    def active_element(self):
        value = json.loads(self.inside('server', ['nft', '-j', 'list', 'set', 'inet', TABLE, 'allowed']).stdout)
        return lease_present(value)

    def create(self):
        for role, name in self.names.items():
            path = Path('/run/netns')/name
            require(not path.exists() and not path.is_symlink(), 'Namespace name already exists')
            self.namespace_intents.add(role)
            self.run(['ip', 'netns', 'add', name])
            info = path.lstat()
            require(info.st_uid == 0 and not path.is_symlink(), 'Unsafe namespace handle')
            self.namespaces[role] = (info.st_dev, info.st_ino)
        self.run(['ip', '-n', self.names['server'], 'link', 'add', 's0', 'type', 'veth',
                  'peer', 'name', 'c0', 'netns', self.names['client']])
        for role, interface, address in [('server', 's0', SERVER), ('client', 'c0', CLIENT)]:
            self.run(['ip', '-n', self.names[role], 'addr', 'add', address+'/30', 'dev', interface])
            self.run(['ip', '-n', self.names[role], 'link', 'set', interface, 'up'])
            self.run(['ip', '-n', self.names[role], 'link', 'set', 'lo', 'up'])
            route = json.loads(self.run(['ip', '-n', self.names[role], '-j', 'route', 'show', 'table', 'all']).stdout)
            require(not any(row.get('dst') == 'default' for row in route), 'Unexpected default route')
        self.save('rules.json', {'ctEstablishedFirst': self.case == 'unsafe-order', 'text': rules(self.case == 'unsafe-order')})

    def launch(self, role, mode):
        error = (self.directory/(mode+'-stderr.txt')).open('x')
        os.fchmod(error.fileno(), 0o644)
        process = subprocess.Popen(['ip', 'netns', 'exec', self.names[role], sys.executable, '-I', '-B', str(SCRIPT), '--worker', mode],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error,
                                   text=True, bufsize=1, start_new_session=True,
                                   env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        self.workers.append((process, error))
        ready = self.read(process)
        require(ready.get('ready') == mode and ready.get('pid') == process.pid, 'Worker identity/readiness mismatch')
        return process

    def read(self, process):
        require(select.select([process.stdout], [], [], 4)[0], 'Fixture worker response timeout')
        line = process.stdout.readline()
        require(bool(line), 'Fixture worker EOF')
        return json.loads(line)

    def call(self, client, op):
        client.stdin.write(json.dumps({'op': op})+'\n');client.stdin.flush()
        return self.read(client)

    def check(self):
        self.create()
        server = self.launch('server', 'server')
        self.inside('server', ['nft', '-c', '-f', '-'], data=rules(self.case == 'unsafe-order'))
        self.inside('server', ['nft', '-f', '-'], data=rules(self.case == 'unsafe-order'))
        applied = time.monotonic()
        self.table('table-active.json')
        client = self.launch('client', 'client')
        time.sleep(0.6)
        baseline = self.call(client, 'sample')
        require(all(s['bytes'] > 0 and not s['closed'] for s in baseline['streams'].values()), 'Both real TCP baselines required')
        renewal = None
        if self.case == 'renewal':
            time.sleep(1)
            require(self.active_element(), 'Lease expired before renewal test')
            self.inside('server', ['nft', '-f', '-'], data=renew_rules())
            renewed = time.monotonic()
            self.table('table-renewed.json')
            while time.monotonic() < applied + TTL + 0.3: time.sleep(0.05)
            post_original = self.call(client, 'sample')
            require(self.active_element(), 'Renewal did not extend the kernel lease')
            require(post_original['streams']['gated']['bytes'] > baseline['streams']['gated']['bytes'] and
                    post_original['atMonotonic'] - post_original['streams']['gated']['lastByteMonotonic'] < 0.6,
                    'Original gated connection did not survive renewal')
            renewal = {'renewedAtMonotonic': renewed, 'sampleAfterOriginalExpiry': post_original,
                       'sameConnectionsNoReconnect': True}
        deadline = time.monotonic() + TTL + 2
        while self.active_element():
            require(time.monotonic() < deadline, 'Kernel timeout failed')
            time.sleep(0.1)
        expired = time.monotonic()
        self.table('table-after-expiry.json')
        # Drain any pre-expiry in-flight bytes before the no-traffic interval.
        # This is a scoped timeout behaviour proof, not a millisecond cutoff SLA.
        time.sleep(0.7)
        first = self.call(client, 'sample')
        time.sleep(2)
        second = self.call(client, 'sample')
        denied = self.call(client, 'new')
        counters = drop_counters(self.table('table-final.json'))
        require(server.poll() is None and client.poll() is None, 'Workers must remain alive during measurement')
        verdict, delta = measure(self.case, first, second, denied, counters)
        result = {'status': verdict, 'case': self.case, 'kernelLeaseSeconds': TTL,
                  'leaseExpiredObservedMonotonic': expired, 'baseline': baseline,
                  'afterExpirySamples': [first, second], 'gatedBytesDuringObservation': delta,
                  'newConnection': denied, 'renewal': renewal,
                  'dropCounters': counters,
                  'sameConnectionsNoReconnect': True, 'workersAliveDuringChecks': True,
                  'coverage': 'SYNTHETIC_IPV4_TCP_ONLY_NOT_VPN_OR_USER_REVOCATION'}
        self.call(client, 'finish');client.stdin.close()
        require(client.wait(timeout=3) == 0, 'Client did not stop cleanly')
        os.killpg(server.pid, signal.SIGTERM)
        require(server.wait(timeout=3) == 0, 'Server did not stop cleanly')
        self.save('measurement.json', result)
        return result

    def close(self):
        errors = []
        for process, stream in reversed(self.workers):
            try:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try: process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL);process.wait(timeout=3)
                require(process.poll() is not None, 'Owned worker remains')
            except BaseException as exc: errors.append(type(exc).__name__)
            finally: stream.close()
        for role in ['client', 'server']:
            if role not in self.namespaces:
                if role in self.namespace_intents and (Path('/run/netns')/self.names[role]).exists():
                    errors.append('Unconfirmed namespace creation; preserve unknown handle')
                continue
            try:
                path = Path('/run/netns')/self.names[role];info = path.lstat()
                require(not path.is_symlink() and info.st_uid == 0 and
                        (info.st_dev, info.st_ino) == self.namespaces[role], 'Namespace identity changed; preserve it')
                occupants = self.run(['ip', 'netns', 'pids', self.names[role]]).stdout.strip()
                require(not occupants, 'Namespace still has processes; preserve it')
                self.run(['ip', 'netns', 'delete', self.names[role]])
                require(not path.exists(), 'Namespace cleanup not confirmed')
            except BaseException as exc: errors.append(type(exc).__name__)
        self.cleanup = {'status': 'PASS_SCOPED_CLEANUP' if not errors else 'CLEANUP_UNCONFIRMED',
                        'errors': errors, 'existingHostNetworkConfigured': False}
        self.save('cleanup.json', self.cleanup);self.save('commands.json', self.commands)
        return not errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker', choices=['server', 'client'])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.worker:
        return server_worker() if args.worker == 'server' else client_worker()
    require(sys.platform == 'linux' and os.geteuid() == 0, 'Disposable Linux root runner required')
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('CI') == 'true' and
            os.environ.get('RUN_NFT_LEASE_REPRO') == 'yes', 'Explicit disposable CI fixture opt-in required')
    require(args.output is not None, 'New artifact directory required')
    def interrupted(*_):
        raise KeyboardInterrupt('Fixture interrupted; scoped cleanup required')
    for sig in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]:
        signal.signal(sig, interrupted)
    for binary in ['ip', 'nft']:
        require(shutil.which(binary) is not None, 'Missing fixture dependency: '+binary)
    output = args.output.resolve();output.mkdir(mode=0o755)
    os.chmod(output, 0o755)
    result = {'schema': 1, 'scope': 'GENERIC_KERNEL_TCP_LEASE_REPRODUCTION', 'cases': {},
              'externalTraffic': False, 'applicationsOrCredentials': False, 'realInfrastructure': False}
    failed = False
    for case in ['unsafe-order', 'gate-first', 'renewal']:
        folder = output/case;folder.mkdir(mode=0o755);folder.chmod(0o755)
        lab = Lab(case, folder)
        try: result['cases'][case] = lab.check()
        except BaseException as exc:
            result['cases'][case] = {'status': 'FAIL', 'exception': type(exc).__name__, 'reason': str(exc)}
            failed = True
        finally:
            if not lab.close(): failed = True
        if failed: break
    result['status'] = 'FAIL' if failed else 'PASS_SYNTHETIC_KERNEL_LEASE_CONTRACT'
    result['limits'] = ['Does not test VPN authentication or selective user revocation.',
                        'IPv4/TCP only; no public ingress or production deployment.',
                        'The observation interval starts after a 700ms in-flight drain allowance.',
                        'Host SSH, routes, firewall and existing namespaces are never configured.']
    path = output/'result.json';path.write_text(json.dumps(result, indent=2)+'\n');path.chmod(0o644)
    emit({'status': result['status'], 'cases': list(result['cases'])})
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
