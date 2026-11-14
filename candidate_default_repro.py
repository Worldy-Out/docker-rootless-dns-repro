#!/usr/bin/env python3
"""Synthetic create-time default test; reuses setup only, never the DNS scenario."""
import copy
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import native_repro as n


def api(method, path, body=None):
    c = http.client.HTTPConnection('docker', timeout=20)
    c.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.sock.settimeout(20)
    try:
        c.sock.connect(str(n.RUNTIME / 'docker.sock'))
        c.request(method, '/v1.52' + path, None if body is None else json.dumps(body), {'Content-Type':'application/json'})
        r = c.getresponse(); data = r.read(2000001)
        n.require(r.status == (201 if method == 'POST' else 200) and len(data) <= 2000000, 'Unexpected API result')
        return json.loads(data)
    finally:c.close()


def protected(row):
    return {k: copy.deepcopy(row[k]) for k in ('Config','HostConfig','Mounts','Image')}


def check_candidate(source, candidate):
    target = protected(source)
    n.require(target['HostConfig']['OomKillDisable'] is None or target['HostConfig']['OomKillDisable'] is False,
              'Synthetic source outside null/false cases')
    target['HostConfig']['OomKillDisable'] = False
    n.require(protected(candidate) == target, 'Unexpected protected metadata difference')
    n.require(candidate['NetworkSettings']['Networks'] == source['NetworkSettings']['Networks'], 'Full attachments changed')
    s = candidate['State']
    n.require(s['Status'] == 'created' and s['Running'] is False and s['Pid'] == 0 and
              s['StartedAt'] == s['FinishedAt'] == '0001-01-01T00:00:00Z', 'Fixture was started')
    n.require(candidate['HostConfig']['PortBindings'] in (None,{}) and candidate['HostConfig']['RestartPolicy']['Name'] == 'no',
              'Port publication/restart forbidden')


def scenario(out):
    n.STATE['stage'] = 'native_create_default'
    info = n.start_engine()
    n.docker('pull', '--platform=linux/amd64', n.IMAGE, timeout=180)
    image = json.loads(n.docker('image','inspect',n.IMAGE).stdout)[0]['Id']
    networks = {}
    for name in ('synthetic-left','synthetic-right'):
        nid = n.docker('network','create','--internal',name).stdout.strip()
        networks[name] = {'NetworkID':nid,'IPAMConfig':None,'Links':None,'Aliases':['synthetic-api'], 'DriverOpts':None,'GwPriority':0}
    body = {'Image':image,'Hostname':'synthetic-host','Cmd':['/bin/true'],
            'HostConfig':{'NetworkMode':'synthetic-left','RestartPolicy':{'Name':'no'},'OomKillDisable':None,
                          'CapDrop':['ALL'],'ReadonlyRootfs':True,'SecurityOpt':['no-new-privileges']},
            'NetworkingConfig':{'EndpointsConfig':networks}}
    first = api('POST','/containers/create?name=synthetic-original',body)
    n.require(not first.get('Warnings'), 'Original create warnings')
    n.STATE['containerIds'].append(first['Id'])
    original = api('GET','/containers/'+first['Id']+'/json')
    n.require(original['HostConfig']['OomKillDisable'] is False, 'Create did not default null to false')
    network_before = [n.network_snapshot(k) for k in sorted(networks)]
    n.write(out/'synthetic-source.json',{'request':body,'readback':original,'networks':network_before},0o644)
    cases=[]
    for label,value in (('null',None),('false',False)):
        source=copy.deepcopy(original);source['HostConfig']['OomKillDisable']=value
        request=copy.deepcopy(source['Config']);request['HostConfig']=copy.deepcopy(source['HostConfig'])
        request['NetworkingConfig']={'EndpointsConfig':networks}
        response=api('POST','/containers/create?name=synthetic-candidate-'+label,request)
        n.require(not response.get('Warnings'),'Candidate create warnings')
        n.STATE['containerIds'].append(response['Id'])
        observed=api('GET','/containers/'+response['Id']+'/json')
        n.write(out/('synthetic-case-'+label+'.json'),{'request':request,'readback':observed},0o644)
        check_candidate(source,observed)
        n.require(api('GET','/containers/'+original['Id']+'/json')==original,'Original changed')
        n.require([n.network_snapshot(k)for k in sorted(networks)]==network_before,'Networks changed')
        cases.append({'requestOomKillDisable':value,'observedOomKillDisable':False,'completeProtectedReadback':True,
                      'completeAttachmentsExact':True,'originalAndNetworksExact':True,'containerStarted':False})
    return {'status':'PASS','engine':info['ServerVersion'],'engineStarts':1,'containerStarts':0,'pulls':1,'cases':cases,
            'fixtureOnly':True,'oldDnsScenarioRepeated':False,'limitation':'Synthetic create-only BusyBox on hosted Ubuntu24; not full application acceptance'}


def main():
    os.umask(0o077);out=n.preflight();result={'status':'FAIL','sourceHead':os.environ['REVIEW_HEAD_SHA']}
    signal.signal(signal.SIGALRM,n.deadline);signal.signal(signal.SIGTERM,n.deadline);signal.alarm(600)
    try:n.setup();result.update(scenario(out))
    except BaseException as e:result.update(status='FAIL',error=type(e).__name__+': '+str(e),stage=n.STATE['stage'])
    finally:
        signal.alarm(0)
        try:final=n.cleanup()
        except BaseException as e:final={'status':'FAIL','error':str(e)}
        result['cleanup']=final
        if final['status']!='PASS':result['status']='FAIL'
        n.write(out/'result.json',result,0o644);print(json.dumps(result,sort_keys=True))
    return 0 if result['status']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
