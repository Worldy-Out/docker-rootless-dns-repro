"""Test window lifecycle shared by the DP-A service and the native kernel test."""

import secrets
import time

from standby_service import Rejected, digest, require

STOPPING_MARGIN = 75


class Window:
    def __init__(self, io, evidence, limit, *, clock=time.monotonic, wall=lambda:time.time_ns()//1_000_000):
        require(type(limit) is int and 120<=limit<=3600, 'Invalid approved window bound')
        self.io,self.evidence,self.limit = io,evidence,limit
        self.clock,self.wall = clock,wall
        self.state = 'STANDBY'
        self.current = self.deadline = None
        self.close_attempted = False

    def remaining(self):
        return min(self.deadline-self.clock(),(self.current['endUtcMs']-self.wall())/1000)

    def validate_open(self, seconds, budget):
        if self.state!='STANDBY' or type(seconds) is not int or not 120<=seconds<=self.limit or seconds>budget:
            raise Rejected('Previous cleanup, approved duration or runtime reserve missing')

    def open(self, seconds):
        self.validate_open(seconds,self.limit)
        prior = self.io.gate()
        require(prior['phase']=='ACTIVE' and prior['bootMatches'] and not prior['leaseOpen'] and
                not prior['windowActive'] and (prior['window'] is None or prior['cleanupSha256'] is not None),
                'Unresolved broker state prevents opening')
        now = self.wall()
        end = now+1000*seconds
        self.current = {'id':secrets.token_hex(16),'readyAtUtcMs':now,'endUtcMs':end,'fixtureEndsUtcMs':end}
        self.deadline = self.clock()+seconds
        self.close_attempted = False
        self.state = 'PROVISIONING'
        self.evidence.save('window-intent',self.current)
        credential = self.io.seed(self.current)
        self.io.publish(self.current)
        observed = self.renew(prior,initial=True)
        self.state = 'TEST_WINDOW'
        self.evidence.save('window-open',{'window':self.current,'leaseRevision':observed['leaseRevision']})
        return {'status':self.state,'window':self.current,'gate':observed,'privateCredential':credential}

    def renew(self, prior, *, initial=False):
        require(self.remaining()>=STOPPING_MARGIN, 'Insufficient immutable window time')
        require((not prior['leaseOpen'] and not prior['windowActive']) if initial else
                prior['leaseOpen'] and prior['windowActive'] and prior['window']==self.current,
                'Current lease identity or live kernel element lost')
        proof = self.io.current_authority(self.current)
        require(self.remaining()>=STOPPING_MARGIN and self.io.gate()['leaseRevision']==prior['leaseRevision'],
                'Window or broker revision changed during authority readback')
        sha = digest({'window':self.current,'authority':proof,'priorRevision':prior['leaseRevision']})
        self.evidence.save('window-lease-intent',{'id':self.current['id'],'proofSha256':sha,'revision':prior['leaseRevision']})
        self.io.renew(self.current,prior['leaseRevision'],sha)
        result = self.io.gate()
        require(result['window']==self.current and result['windowActive'] and result['leaseOpen'] and
                result['lastProofSha256']==sha and result['leaseRevision']==prior['leaseRevision']+1 and
                0<result['remainingMilliseconds']<=min(120000,self.remaining()*1000), 'Kernel lease commit unconfirmed')
        self.evidence.save('window-lease-readback',result)
        return result

    def tick(self):
        if self.state=='STANDBY':
            self.io.standby()
            return
        require(self.state=='TEST_WINDOW', 'Prior window outcome unresolved')
        gate = self.io.gate()
        if self.remaining()<STOPPING_MARGIN or not gate['leaseOpen']:
            self.close()
        else:
            self.renew(gate)

    def close(self):
        require(self.current is not None and self.state in ('PROVISIONING','TEST_WINDOW') and not self.close_attempted,
                'No uniquely owned outstanding window to close')
        self.close_attempted = True
        self.state = 'CLOSING'
        self.evidence.save('window-close-intent',self.current)
        before = self.io.gate()
        owns = before['window']==self.current
        require((owns or not before['windowActive']) and (owns or not before['leaseOpen']), 'Foreign lease at closure')
        if owns and before['windowActive']:
            try:
                self.io.close_gate()
            except (OSError,RuntimeError):
                pass  # Read the exact revision before attributing a lost ACK.
        after = self.io.gate()
        require(not after['leaseOpen'] and not after['windowActive'] and
                after['window']==before['window'] and
                after['leaseRevision']==before['leaseRevision']+int(owns and before['windowActive']),
                'Kernel gate close unconfirmed; stop renewing')
        self.io.unpublish(self.current)
        receipt = self.io.revoke_and_verify(self.current)
        self.io.standby()
        if owns:
            proof = digest({'closedGate':after,'cleanup':receipt,'window':self.current})
            self.io.finalize(self.current['id'],after['leaseRevision'],proof)
            final = self.io.gate()
            require(final['window']==self.current and final['cleanupSha256']==proof and not final['windowActive'] and
                    final['leaseRevision']==after['leaseRevision'] and not final['leaseOpen'], 'Window cleanup commit unconfirmed')
        self.evidence.save('window-closed',{'window':self.current,'cleanup':receipt,'leaseRevision':after['leaseRevision']})
        self.state = 'STANDBY'
        self.current = self.deadline = None
        return {'status':'STANDBY','cleanup':receipt}
