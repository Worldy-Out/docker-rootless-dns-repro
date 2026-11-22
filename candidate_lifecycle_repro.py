#!/usr/bin/env python3
"""Synthetic rootless Engine 29.1.3 create/start/stop and recovery evidence."""
import copy
import http.client
import json
import os
import signal
import socket

import native_repro as host
from candidate_default_repro import api


NETWORKS = ('synthetic-lifecycle-data', 'synthetic-lifecycle-control')
STATIC_ENDPOINT = ('NetworkID', 'IPAMConfig', 'Links', 'Aliases', 'DriverOpts', 'GwPriority')
LIVE_ENDPOINT = {'EndpointID', 'Gateway', 'IPAddress', 'IPPrefixLen', 'MacAddress'}
COMMAND = ['/bin/sh', '-c', "trap 'exit 0' TERM; echo READY; while :; do sleep 1 & wait $!; done"]


def write_intent(path, value):
    host.write(path, value, 0o644)
    with path.open('rb') as stream:
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create(image, name, network_spec):
    request = {'Image': image, 'Hostname': 'synthetic-host', 'Cmd': COMMAND,
               'HostConfig': {'NetworkMode': NETWORKS[0], 'RestartPolicy': {'Name': 'no'},
                              'OomKillDisable': None, 'OomScoreAdj': 200, 'CapDrop': ['ALL'], 'ReadonlyRootfs': True,
                              'SecurityOpt': ['no-new-privileges'], 'Memory': 256 * 1024**2,
                              'MemorySwap': 256 * 1024**2, 'PidsLimit': 64,
                              'Binds': [str(host.HOME_DIR/'synthetic-mounts'/label) + ':/'+label+':ro' for label in ('two', 'one')]},
               'NetworkingConfig': {'EndpointsConfig': network_spec}}
    result = api('POST', '/containers/create?name='+name, request)
    host.STATE['containerIds'].append(result['Id'])
    host.require(not result.get('Warnings'), 'Unexpected create warning')
    return result['Id']


def endpoints(row):
    return row['NetworkSettings']['Networks']


def canonical(row):
    return {**row, 'Mounts': sorted(row['Mounts'], key=lambda mount: mount['Destination'])}


def network_request(method, path, expected, body=None):
    conn = http.client.HTTPConnection('docker', timeout=12)
    conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.sock.settimeout(12)
    try:
        conn.sock.connect(str(host.RUNTIME/'docker.sock'))
        conn.request(method, '/v1.52'+path, None if body is None else json.dumps(body),
                     {'Content-Type': 'application/json'})
        result = conn.getresponse()
        raw = result.read(1024)
        host.require(result.status == expected and not raw.strip(), 'Unexpected network API result: '+str(result.status))
    finally:
        conn.close()


def snapshot(cids, network_ids):
    host.require(set(host.docker('ps', '-aq', '--no-trunc').stdout.split()) == set(cids), 'Unexpected container set')
    return {'containers': {cid: canonical(host.inspect(cid)) for cid in cids},
            'networks': {name: host.network_snapshot(name) for name in network_ids}}


def expected_dns(row, endpoint):
    return list(dict.fromkeys([row['Name'].lstrip('/'), *endpoint['Aliases'], row['Id'][:12], row['Config']['Hostname']]))


def verify_candidate(created, observed, *, running):
    before, after = host.protected(created), host.protected(observed)
    before.pop('NetworkSettings')
    after.pop('NetworkSettings')
    host.require(before['HostConfig']['OomKillDisable'] is False, 'Pinned Engine did not record false on create')
    host.require(before['HostConfig']['OomScoreAdj'] == after['HostConfig']['OomScoreAdj'] == 200,
                 'Explicit OomScoreAdj must be static, observed '+str(after['HostConfig']['OomScoreAdj']))
    before['HostConfig']['OomKillDisable'] = None
    host.require(before == after, 'Static candidate spec changed: '+', '.join(host.diff_paths(before, after)[:12]))
    previous, current = endpoints(created), endpoints(observed)
    host.require(set(previous) == set(current) == set(NETWORKS), 'Candidate attachment set changed')
    for name, endpoint in current.items():
        base = previous[name]
        host.require({k: endpoint[k] for k in STATIC_ENDPOINT} == {k: base[k] for k in STATIC_ENDPOINT},
                     'Attachment identity, aliases, IPAM or priority changed')
        expected = {**base, 'DNSNames': expected_dns(observed, base)}
        if running:
            host.require(bool(endpoint['EndpointID'] and endpoint['IPAddress'] and endpoint['MacAddress'] and endpoint['IPPrefixLen'] > 0),
                         'Live endpoint lacks allocated fields')
            expected.update({k: endpoint[k] for k in LIVE_ENDPOINT})
        host.require(endpoint == expected, 'Unexpected full endpoint transition: '+', '.join(host.diff_paths(expected, endpoint)[:12]))
    state = observed['State']
    host.require(state['Running'] is running and (state['Pid'] > 0 if running else state['Pid'] == 0) and
                 state['Status'] == ('running' if running else 'exited') and not state['OOMKilled'] and
                 state['StartedAt'] != '0001-01-01T00:00:00Z' and state['ExitCode'] == 0 and observed['RestartCount'] == 0,
                 'Candidate runtime state differs')


def prove_peers(before, after, cid, *, running):
    host.require(set(before['containers']) == set(after['containers']) and
                 all(before['containers'][key] == after['containers'][key] for key in before['containers'] if key != cid),
                 'Other container metadata changed')
    host.require(set(before['networks']) == set(after['networks']), 'Other Docker network added or removed')
    for name, former in before['networks'].items():
        current = after['networks'][name]
        expected = copy.deepcopy(former)
        if running:
            row = after['containers'][cid]
            endpoint = endpoints(row)[name]
            expected['Containers'][cid] = {'Name': row['Name'].lstrip('/'), 'EndpointID': endpoint['EndpointID'],
                                           'MacAddress': endpoint['MacAddress'],
                                           'IPv4Address': endpoint['IPAddress']+'/'+str(endpoint['IPPrefixLen']), 'IPv6Address': ''}
            status = expected.pop('Status', None)
            current = copy.deepcopy(current)
            # Allocation counters are validated alongside membership, separately
            # from the rest of the network's static fields.
            allocated = current.pop('Status', None)
            before_subnets = status['IPAM']['Subnets'] if status is not None else None
            after_subnets = allocated['IPAM']['Subnets'] if allocated is not None else None
            host.require((status is None and allocated is None) or
                         (before_subnets is not None and after_subnets is not None and set(before_subnets) == set(after_subnets) and
                          all(after_subnets[k] == {**v,
                          'IPsInUse': v['IPsInUse']+1, 'DynamicIPsAvailable': v['DynamicIPsAvailable']-1}
                              for k, v in before_subnets.items())), 'Network IPAM allocation counters differ')
        host.require(current == expected, 'Full network peer readback changed: '+', '.join(host.diff_paths(expected, current)[:12]))


def stop(cid):
    if host.inspect(cid)['State']['Running']:
        host.docker('stop', '--time=15', cid, timeout=25)
    host.require(host.inspect(cid)['State']['Running'] is False, 'Candidate stop unconfirmed')


def cycle(out, label, cids, names, *, withhold_ack):
    host.STATE['stage'] = label+'-created'
    cid = cids[-1]
    before = snapshot(cids, names)
    created = before['containers'][cid]
    host.require(created['State']['Status'] == 'created' and created['State']['StartedAt'] == '0001-01-01T00:00:00Z' and
                 all(ep['DNSNames'] is None for ep in endpoints(created).values()), 'Candidate must be truly created')
    write_intent(out/(label+'-intent.json'), {'state': 'START_INTENT', 'cid': cid, 'startMaximum': 1})
    try:
        host.STATE['stage'] = label+'-start'
        response = host.docker('start', cid)
        # The lab client can lose the acknowledgement after the real daemon
        # handles the request. Readback must recover the outcome without retry.
        received = None if withhold_ack else response.stdout.strip()
        host.require(received in (None, cid), 'Unexpected acknowledgement')
        host.STATE['stage'] = label+'-running-readback'
        host.until(lambda: 'READY' in host.docker('logs', cid).stdout, 10, 'Candidate did not reach its readiness marker')
        host.remember_groups()
        live = snapshot(cids, names)
        verify_candidate(created, live['containers'][cid], running=True)
        prove_peers(before, live, cid, running=True)
    finally:
        stop(cid)
    after = snapshot(cids, names)
    host.STATE['stage'] = label+'-stopped-readback'
    verify_candidate(created, after['containers'][cid], running=False)
    prove_peers(before, after, cid, running=False)
    host.require(live['containers'][cid]['State']['StartedAt'] == after['containers'][cid]['State']['StartedAt'], 'Recovered another start')
    for change in ('OomKillDisable', 'Memory', 'Aliases', 'NetworkID', 'IPAMConfig', 'DNSNames'):
        drift = copy.deepcopy(after['containers'][cid])
        if change in ('OomKillDisable', 'Memory'):
            drift['HostConfig'][change] = True
        else:
            endpoints(drift)[NETWORKS[0]][change] = 'drift'
        try:
            verify_candidate(created, drift, running=False)
        except RuntimeError:
            continue
        raise RuntimeError('Accepted static drift: '+change)
    host.write(out/(label+'-observations.json'), {'before': before, 'live': live, 'after': after}, 0o644)
    return {'cid': cid, 'createdStartedStopped': True, 'ackWithheld': withhold_ack,
            'startRequests': 1, 'fullPeerChecks': True, 'negativeChecks': 6}


def compensate_fixture(out, cids, networks):
    host.STATE['stage'] = 'stopped-topology-rollback'
    name = 'synthetic-lifecycle-temporary'
    cid = cids[0]
    before = snapshot(cids, networks)
    nid = api('POST', '/networks/create', {'Name': name, 'Driver': 'bridge', 'Internal': False,
              'IPAM': {'Driver': 'default', 'Options': None, 'Config': [{'Subnet': '198.18.144.0/29'}]},
              'Labels': {'purpose': 'lifecycle-compensation'}})['Id']
    path = '/networks/'+nid
    try:
        network_request('POST', path+'/connect', 200, {'Container': cid, 'EndpointConfig': {
            'GwPriority': 1, 'IPAMConfig': {'IPv4Address': '198.18.144.2'}}})
        attached = host.inspect(cid)
        endpoint = endpoints(attached)[name]
        host.require(endpoint['NetworkID'] == nid and endpoint['GwPriority'] == 1 and
                     endpoint['IPAMConfig']['IPv4Address'] == '198.18.144.2' and attached['State']['Running'] is False and
                     endpoint['Aliases'] is None and
                     {k: v for k, v in endpoints(attached).items() if k != name} == endpoints(before['containers'][cid]),
                     'Unexpected temporary attachment')
        write_intent(out/'rollback-intent.json', {'phase': 'ROLLBACK', 'cid': cid, 'networkId': nid})
        # Entry through an error path, after the extra attachment exists.
        raise InterruptedError('Synthetic channel loss after attachment')
    except InterruptedError:
        network_request('POST', path+'/disconnect', 200, {'Container': cid, 'Force': False})
        host.require(host.network_snapshot(nid)['Containers'] == {} and canonical(host.inspect(cid)) == before['containers'][cid],
                     'Exact original endpoint readback required before deletion')
        network_request('DELETE', path, 204)
    after = snapshot(cids, networks)
    host.require(after == before and nid not in host.docker('network', 'ls', '--no-trunc', '-q').stdout.splitlines(),
                 'Full rollback of stopped topology failed')
    return {'disconnects': 1, 'deletes': 1, 'allPeerAttachmentsExact': True}


def scenario(out):
    engine = host.start_engine()
    host.require(engine['ServerVersion'] == '29.1.3' and engine['CgroupVersion'] == '2' and not engine['LiveRestoreEnabled'],
                 'Unexpected Engine')
    host.docker('pull', '--platform=linux/amd64', host.IMAGE, timeout=180)
    image = json.loads(host.docker('image', 'inspect', host.IMAGE).stdout)[0]['Id']
    mounts = host.HOME_DIR/'synthetic-mounts'
    mounts.mkdir(mode=0o700)
    os.chown(mounts, host.UID, host.UID)
    for label in ('one', 'two'):
        fixture = mounts/label
        fixture.mkdir(mode=0o700)
        os.chown(fixture, host.UID, host.UID)
    networks = {}
    for name in NETWORKS:
        nid = api('POST', '/networks/create', {'Name': name, 'Driver': 'bridge', 'Internal': True,
                  'IPAM': {'Driver': 'default', 'Options': None, 'Config': []}})['Id']
        host.require(host.network_snapshot(name)['IPAM']['Options'] is None, 'Expected retained default IPAM options shape')
        networks[name] = {'NetworkID': nid, 'IPAMConfig': None, 'Links': None, 'Aliases': ['synthetic-api'],
                          'DriverOpts': None, 'GwPriority': 0}
    peers = [create(image, 'synthetic-peer-'+str(i), networks) for i in range(6)]
    cases = []
    for label, withhold in (('normal', False), ('lost-ack', True)):
        cid = create(image, 'synthetic-candidate-'+label, networks)
        cases.append(cycle(out, label, [*peers, cid], networks, withhold_ack=withhold))
        host.docker('rm', cid)
        host.require(cid not in host.docker('ps', '-aq', '--no-trunc').stdout.split(), 'Removed fixture still exists')
        host.STATE['containerIds'].remove(cid)
    host.require(set(host.docker('ps', '-aq', '--no-trunc').stdout.split()) == set(peers), 'Synthetic candidates remain')
    rollback = compensate_fixture(out, peers, networks)
    return {'status': 'PASS', 'dockerVersion': engine['ServerVersion'], 'cases': cases, 'fixtureOnly': True,
            'retainedPeersAtEachStart': 6, 'scenarioPulls': 0, 'setupPulls': 1, 'engineStarts': 1, 'rollback': rollback}


def main():
    os.umask(0o077)
    out = host.preflight()
    result = {'status': 'FAIL', 'sourceHead': os.environ['REVIEW_HEAD_SHA']}
    signal.signal(signal.SIGALRM, host.deadline)
    signal.signal(signal.SIGTERM, host.deadline)
    signal.alarm(650)
    try:
        host.setup()
        result.update(scenario(out))
    except BaseException as exc:
        result.update(status='FAIL', error=str(exc), errorType=type(exc).__name__, failedStage=host.STATE['stage'],
                      commandFailure=host.STATE.get('commandFailure'))
    finally:
        signal.alarm(0)
        try:
            cleanup = host.cleanup()
        except BaseException as exc:
            cleanup = {'status': 'FAIL', 'error': str(exc)}
        result['cleanup'] = cleanup
        if cleanup['status'] != 'PASS':
            result['status'] = 'FAIL'
        host.write(out/'result.json', result, 0o644)
        print(json.dumps(result, sort_keys=True))
    return int(result['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
