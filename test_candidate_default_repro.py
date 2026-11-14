import copy
import unittest
from candidate_default_repro import check_candidate


def fixture():
    return {'Config':{'Hostname':'synthetic'},'HostConfig':{'OomKillDisable':None,'PortBindings':{},'RestartPolicy':{'Name':'no'}},
            'Mounts':[],'Image':'synthetic','NetworkSettings':{'Networks':{}},
            'State':{'Status':'created','Running':False,'Pid':0,'StartedAt':'0001-01-01T00:00:00Z','FinishedAt':'0001-01-01T00:00:00Z'}}


class Tests(unittest.TestCase):
    def test_null_false_exact_and_no_source_rewrite(self):
        a=fixture();b=copy.deepcopy(a);b['HostConfig']['OomKillDisable']=False
        check_candidate(a,b);self.assertIsNone(a['HostConfig']['OomKillDisable'])
    def test_false_false(self):
        a=fixture();a['HostConfig']['OomKillDisable']=False;check_candidate(a,a)
    def test_true_rejected(self):
        a=fixture();b=copy.deepcopy(a);b['HostConfig']['OomKillDisable']=True
        with self.assertRaises(RuntimeError):check_candidate(a,b)
    def test_other_field_rejected(self):
        a=fixture();b=copy.deepcopy(a);b['HostConfig']['OomKillDisable']=False;b['Config']['Hostname']='drift'
        with self.assertRaises(RuntimeError):check_candidate(a,b)
    def test_unknown_endpoint_rejected(self):
        a=fixture();b=copy.deepcopy(a);b['HostConfig']['OomKillDisable']=False;b['NetworkSettings']['Networks']['extra']={}
        with self.assertRaises(RuntimeError):check_candidate(a,b)
