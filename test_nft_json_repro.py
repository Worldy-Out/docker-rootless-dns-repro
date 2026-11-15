import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('nft_json_repro', Path(__file__).with_name('nft_json_repro.py'))
m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def snapshot():
    return {'nftables': [
        {'metainfo': {'version': '1.1.6'}},
        {'table': {'family': 'inet', 'name': m.TABLE, 'comment': m.MARKER, 'handle': 7}},
        {'set': {'family': 'inet', 'table': m.TABLE, 'name': 'lease_sources', 'type': 'ipv4_addr',
                 'flags': ['timeout'], 'timeout': m.TIMEOUT, 'handle': 1}},
        {'chain': {'family': 'inet', 'table': m.TABLE, 'name': 'observations', 'handle': 2}},
        *[{'rule': {'family': 'inet', 'table': m.TABLE, 'chain': 'observations', 'handle': 10+i,
                   'expr': value}} for i, value in enumerate([
            [{'match': {'right': {'set': m.PORTS}}}, {'counter': {'packets': 0, 'bytes': 0}}, {'accept': None}],
            [{'match': {'right': {'set': m.PORTS[:2]}}}, {'drop': None}],
            [{'limit': {'rate': 1, 'rate_unit': 'mbytes'}}, {'counter': {'packets': 0, 'bytes': 0}}, {'accept': None}],
        ])],
    ]}


class ShapeTests(unittest.TestCase):
    def test_named_object_and_anonymous_arrays_are_different_nodes(self):
        value = snapshot();before = copy.deepcopy(value)
        self.assertFalse(m.validate_snapshot(value)['everySetValueIsObject'])
        m.stable_snapshot(value)
        self.assertEqual(value, before)

    def test_live_then_expired_normalizes_only_validated_finite_element(self):
        empty = snapshot();live = copy.deepcopy(empty)
        live['nftables'][2]['set']['elem'] = [{'elem': {'val': m.LEASE, 'expires': 1}}]
        self.assertEqual(m.stable_snapshot(empty), m.stable_snapshot(live))
        live['nftables'][2]['set']['elem'][0]['elem']['timeout'] = m.TIMEOUT
        self.assertEqual(m.stable_snapshot(empty), m.stable_snapshot(live))

    def test_invalid_named_set_does_not_become_expression(self):
        for key, bad in [('timeout', 2000), ('timeout', True), ('flags', None), ('flags', []),
                         ('flags', ['timeout', 'interval']), ('type', 'ipv6_addr'), ('table', 'foreign')]:
            with self.subTest(key=key, bad=bad):
                v = snapshot();v['nftables'][2]['set'][key] = bad
                with self.assertRaises(RuntimeError):m.validate_snapshot(v)
        v = snapshot();v['nftables'][2]['set'] = [1, 2]
        with self.assertRaises(RuntimeError):m.validate_snapshot(v)

    def test_source_expiry_and_duplicate_elements_fail_closed(self):
        for element in [{'val': '192.0.2.56', 'expires': 1}, {'val': m.LEASE},
                        {'val': m.LEASE, 'expires': 3}, {'val': m.LEASE, 'expires': True},
                        {'val': m.LEASE, 'expires': 0, 'timeout': 0}]:
            with self.subTest(element=element):
                v=snapshot();v['nftables'][2]['set']['elem']=[{'elem':element}]
                with self.assertRaises(RuntimeError):m.validate_snapshot(v)
        v=snapshot();v['nftables'][2]['set']['elem']=[{'elem':{'val':m.LEASE,'expires':1}}]*2
        with self.assertRaises(RuntimeError):m.validate_snapshot(v)

    def test_port_members_order_and_type_are_not_normalized(self):
        for ports in [[18881,18880,18882], [18880,18881,18883], {'x':18880}]:
            v=snapshot();v['nftables'][4]['rule']['expr'][0]['match']['right']['set']=ports
            with self.subTest(ports=ports),self.assertRaises(RuntimeError):m.validate_snapshot(v)

    def test_only_counter_expression_values_are_normalized(self):
        v=snapshot();changed=copy.deepcopy(v)
        changed['nftables'][4]['rule']['expr'][1]['counter']={'bytes':42,'packets':1}
        self.assertEqual(m.stable_snapshot(v),m.stable_snapshot(changed))
        changed['nftables'][6]['rule']['expr'][0]['limit']['rate']=2
        self.assertNotEqual(m.stable_snapshot(v),m.stable_snapshot(changed))

    def test_static_whole_snapshot_drift_never_compares_equal(self):
        original=snapshot()
        for kind in ['verdict','handle','chain','set-property']:
            changed=copy.deepcopy(original)
            if kind=='verdict':changed['nftables'][5]['rule']['expr'][1]={'accept':None}
            elif kind=='handle':changed['nftables'][4]['rule']['handle']+=1
            elif kind=='chain':changed['nftables'][3]['chain']['comment']='unexpected'
            else:changed['nftables'][2]['set']['size']=128
            with self.subTest(kind=kind):
                self.assertNotEqual(m.stable_snapshot(original),m.stable_snapshot(changed))

    def test_hook_or_foreign_objects_rejected(self):
        v=snapshot();v['nftables'][3]['chain']['hook']='input'
        with self.assertRaises(RuntimeError):m.validate_snapshot(v)
        v=snapshot();v['nftables'].append({'map':{}})
        with self.assertRaises(RuntimeError):m.validate_snapshot(v)

    def test_outer_timeout_kills_owned_group_and_native_leaf_stays_inside_it(self):
        for command, grouped in [(['/usr/bin/unshare'], True), (['/usr/sbin/nft'], False)]:
            process=Mock(pid=123, returncode=-9)
            process.communicate.side_effect=[TimeoutError('synthetic deadline'), (b'', b'')]
            with self.subTest(command=command),patch.object(m.subprocess,'Popen',return_value=process)as start,patch.object(m.os,'killpg')as kill:
                with self.assertRaises(TimeoutError):m.run(command)
                self.assertEqual(start.call_args.kwargs['start_new_session'],grouped)
                if grouped:
                    kill.assert_called_once_with(123,m.signal.SIGKILL);process.kill.assert_not_called()
                else:
                    kill.assert_not_called();process.kill.assert_called_once_with()

    def test_direct_child_host_namespace_is_rejected_before_nft(self):
        with patch.object(m,'require_runner',return_value={}),patch.object(m,'namespace_identity',return_value=[1,2]),patch.object(m,'json_ruleset')as nft:
            with self.assertRaisesRegex(RuntimeError,'independent ephemeral'):
                m.child({'parentPid':123,'parentNamespace':[1,2]})
            nft.assert_not_called()

    def test_cleanup_deletes_only_verified_table_handle_once(self):
        with patch.object(m,'run')as execute:
            self.assertEqual(m.delete_owned_table(snapshot(),snapshot()),7)
            execute.assert_called_once_with(['/usr/sbin/nft','delete','table','inet','handle','7'])
        for handle in [None,False,0,-1,'7']:
            value=snapshot();value['nftables'][1]['table']['handle']=handle
            with self.subTest(handle=handle),patch.object(m,'run')as execute:
                with self.assertRaises(RuntimeError):m.delete_owned_table(value,snapshot())
                execute.assert_not_called()

    def test_cleanup_requires_full_baseline_and_exact_static_snapshot(self):
        for kind in ['missing-baseline','verdict','handle','limit','chain']:
            value=snapshot();baseline=snapshot()
            if kind=='missing-baseline':baseline=None
            elif kind=='verdict':value['nftables'][5]['rule']['expr'][1]={'accept':None}
            elif kind=='handle':value['nftables'][1]['table']['handle']+=1
            elif kind=='limit':value['nftables'][6]['rule']['expr'][0]['limit']['rate']=2
            else:value['nftables'][3]['chain']['comment']='unexpected'
            with self.subTest(kind=kind),patch.object(m,'run')as execute:
                with self.assertRaises(RuntimeError):m.delete_owned_table(value,baseline)
                execute.assert_not_called()

    def test_cleanup_unknown_ack_never_falls_back_to_name_or_retries(self):
        with patch.object(m,'run',side_effect=RuntimeError('unknown acknowledgement'))as execute:
            with self.assertRaises(RuntimeError):m.delete_owned_table(snapshot(),snapshot())
            execute.assert_called_once_with(['/usr/sbin/nft','delete','table','inet','handle','7'])


if __name__ == '__main__':
    unittest.main()
