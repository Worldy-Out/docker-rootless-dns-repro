"""Synthetic adapters for the native systemd/kernel acceptance run only."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time

import broker
import network_policy as network
import root_helper
import standby_service as service
from standby_window import Window


ROOT = Path('/run/standby-native-root')
HOME = Path('/srv/uzel/operational')
EPOCH = 'c'*32
POLICY = network.validate({'schema':1,'scope':'CP_DP_A_CLOSED_OPERATIONAL','role':'dp-a','epoch':EPOCH,
    'sourceIPv4s':['11.77.0.2'],'egress':[],'leaseSeconds':30,'publicPorts':[443],'dnsResolver':'127.0.0.53',
    'testWindowMaxSeconds':3600,'standbyService':network.STANDBY_SERVICE,'wireguardPublicKey':'A'*43+'=',
    'wireguardPeerPublicKey':'B'*43+'=','runtimeUnitSha256':'0'*64})


class KernelFixture(root_helper.Helper):
    def check_host(self):
        root_helper.require(os.geteuid()==0 and root_helper.command(['ip','link','show','dev','cienp0']).returncode==0,
                            'Isolated kernel fixture required')

    def verify_interface(self):
        self.check_host()

    def management_handshake(self):
        return None

    def stop(self):
        self.check_host();self.verify_table()
        if (self.state.get('testWindow') or {}).get('active'):
            self.lease(False)
        root_helper.command(['nft','delete','table','inet',network.TABLE])
        self.save('CLOSED',stopAttempted=True)
        return {'status':'CLOSED_ENGINE_STOPPED_OWN_NETWORK_REMOVED'}


class Evidence:
    def __init__(self):
        self.path = HOME/'service.ndjson'

    def save(self, label, value):
        with self.path.open('ab') as out:
            out.write(service.encode({'label':label,'value':value}));out.flush();os.fsync(out.fileno())


class Actor:
    def __init__(self, evidence):
        self.evidence = evidence
        self.listener = None
        self.terminal = False
        self.running = False
        self.window = Window(self,evidence,900)
        self.fixture = None
        self.published = False

    def status(self):
        return {'status':self.window.state,'fixture':self.fixture is not None,'running':self.running}

    def validate(self, action, data):
        if action=='window-open':
            self.window.validate_open(data,900)
        elif action=='window-close' and self.window.state!='TEST_WINDOW':
            raise service.Rejected('Window is not open')
        elif action=='start' and self.running:
            raise service.Rejected('Already started')
        elif action not in ('start','window-close','safe-stop'):
            raise service.Rejected('Unknown action')

    def command(self,action,data):
        if action=='start':
            subprocess.run(['/usr/bin/systemctl','--user','show','-p','SystemState'],check=True,timeout=5,
                           stdout=subprocess.DEVNULL)
            self.running = True
            return {'status':'STANDBY'}
        if action=='window-open':
            return self.window.open(data)
        if action=='window-close':
            return self.window.close()
        return self.stop()

    def tick(self):
        if self.running:
            self.window.tick()

    def stop(self):
        if self.window.state=='TEST_WINDOW':
            self.window.close()
        self.running = False
        self.terminal = True
        return {'status':'STOPPED'}

    def fail(self,error):
        if self.window.state in ('PROVISIONING','TEST_WINDOW'):
            self.window.close()
        self.running = False
        self.terminal = True

    @staticmethod
    def call(action, *args, **kwargs):
        return broker.call(action,'dp-a',EPOCH,*args,**kwargs)

    def gate(self):
        return self.call('window_status')

    def seed(self, window):
        service.require(self.fixture is None,'Fixture already exists')
        self.fixture = window['id']
        return {'syntheticFixture':window['id']}

    def publish(self, window):
        service.require(self.fixture==window['id'] and not self.published,'Fixture/mapping mismatch')
        self.published = True

    def current_authority(self,window):
        service.require(not (HOME/'unknown').exists() and self.fixture==window['id'] and self.published,
                        'Synthetic current authority disappeared')
        self.call('heartbeat')
        return {'time':time.monotonic_ns(),'ownedFixture':self.fixture}

    def renew(self, window, revision, proof, *, deadline_monotonic_ms):
        return self.call('renew',revision,proof,window=window,deadline_monotonic_ms=deadline_monotonic_ms)

    def close_gate(self):
        return self.call('close')

    def unpublish(self, window):
        service.require(not self.gate()['leaseOpen'],'Unpublish while gate is live')
        self.published = False

    def revoke_and_verify(self,window):
        service.require(self.fixture==window['id'] and not self.published,'Unexpected fixture at revoke')
        self.fixture = None
        return {'fixtureInactive':True}

    def standby(self):
        service.require(self.fixture is None and not self.published and not self.gate()['leaseOpen'],'Standby was not closed')
        self.call('heartbeat')

    def finalize(self,window_id,revision,proof):
        return self.call('window_finalize',revision,proof,window_id=window_id)


def run():
    root_helper.STATE = ROOT
    root_helper.Helper = KernelFixture
    root_helper.load_release = lambda:(POLICY,network)
    sys.argv = [sys.argv[0],sys.argv[1]]
    try:
        root_helper.main()
    except Exception as error:
        print(json.dumps({'error':str(error),'type':type(error).__name__}),file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':
    raise SystemExit(run())
