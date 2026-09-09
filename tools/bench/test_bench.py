import json
import math
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from bench import Engine, Sampler, dump, paired_orders, config_files, env_for, scenarios
from linux_metrics import keyed, proc_stat, snapshot
from report import paired_ratio, plateau, render


class StatisticsTests(unittest.TestCase):
    def test_ratio_direction(self):
        self.assertEqual(paired_ratio([10]*4,[5]*4)[0],2)
        self.assertEqual(paired_ratio([5]*4,[10]*4,True)[0],2)
    def test_bootstrap_pairing(self):
        est,lo,hi=paired_ratio([1,100,10000],[.5,50,5000])
        self.assertAlmostEqual(est,2);self.assertAlmostEqual(lo,2);self.assertAlmostEqual(hi,2)
    def test_bad_measurements_are_not_zero(self):
        for xs in [[],[None],[0],[float('nan')],[float('inf')]]:
            with self.assertRaises(ValueError):paired_ratio(xs,xs)
    def test_ci_not_invented_from_one_trial(self):
        self.assertEqual(paired_ratio([2],[1]),(2,None,None))
    def test_balanced_order(self):
        orders=paired_orders(6,1,99)
        self.assertEqual(orders,paired_orders(6,1,99))
        measured=[order[0] for _,discard,order in orders if not discard]
        self.assertEqual(measured.count('official'),3)
    def test_plateau_missing(self):
        self.assertIsNone(plateau([], 'idle','pss_bytes'))
    def test_plateau_uses_late_half_not_minimum(self):
        rows=[dict(phase='idle',complete=True,pss_bytes=n) for n in [1,2,30,40]]
        self.assertEqual(plateau(rows,'idle','pss_bytes'),35)


class SafetyTests(unittest.TestCase):
    def test_credentials_and_tuning_not_inherited(self):
        old=os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
        os.environ['GOOGLE_APPLICATION_CREDENTIALS']='/secret';os.environ['JAVA_TOOL_OPTIONS']='-Xmx16m'
        try:
            e=env_for(Path('/tmp/home'),Path('/tmp/cache'))
            self.assertNotIn('GOOGLE_APPLICATION_CREDENTIALS',e)
            self.assertNotIn('JAVA_TOOL_OPTIONS',e)
            self.assertNotIn('GITHUB_TOKEN',e)
        finally:
            os.environ.pop('JAVA_TOOL_OPTIONS',None)
            if old is None:os.environ.pop('GOOGLE_APPLICATION_CREDENTIALS',None)
            else:os.environ['GOOGLE_APPLICATION_CREDENTIALS']=old
    def test_config_same_rules_indexes_and_profile(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);config_files(p,[8080,4400,9150,9099,9199],'strict')
            f=json.loads((p/'fireemu.json').read_text());g=json.loads((p/'firebase.json').read_text())
            self.assertEqual(f['profile'],'strict');self.assertFalse(g['emulators']['ui']['enabled'])
            self.assertEqual(g['emulators']['firestore']['host'],'127.0.0.1')
            self.assertNotIn('clockStart',f.get('daemon',{}))
    def test_proc_stat_with_spaces(self):
        real=Path(f'/proc/{os.getpid()}/stat').read_text()
        changed=real[:real.index('(')+1]+'name with (brackets)'+real[real.rfind(')'):]
        self.assertEqual(proc_stat(real)['start_ticks'],proc_stat(changed)['start_ticks'])
    def test_keyed_units(self):
        self.assertEqual(keyed('Pss: 3 kB\nusage_usec 71\n'),{'Pss':3,'usage_usec':71})
    def test_missing_cgroup_metrics_are_not_pass(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'cgroup.procs').write_text('')
            s=snapshot(p);self.assertFalse(s['complete']);self.assertIsNone(s['cgroup_memory_peak_bytes'])
    def test_process_group_lifecycle(self):
        # Real stand-in process only: this is NOT a fireemu/Firebase benchmark.
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            code='import time; x=bytearray(8*1024*1024); time.sleep(60)'
            e=Engine([sys.executable,'-c',code],p,{'PATH':os.environ['PATH']},'process')
            if os.geteuid()==0:
                data=json.loads(e.launch.read_text());data['allow_root_for_selftest']=True;dump(e.launch,data)
            try:
                e.start();time.sleep(.1)
                s=e.sample();self.assertTrue(s['complete'],s['errors']);self.assertGreater(s['pss_bytes'],0)
                sampler=Sampler(e,p/'samples.jsonl',.05);sampler.start();time.sleep(.12);sampler.stop()
                self.assertGreater(len((p/'samples.jsonl').read_text().splitlines()),0)
            finally:
                result=e.stop();self.assertEqual(result['remaining_pids'],[])


class ReportingTests(unittest.TestCase):
    def create(self,p,failed=False):
        dump(p/'manifest.json',{'commit':'a'*40,'profile':'firebase','tier':'smoke','supervisor':'systemd','config':{'pairs':1}})
        dump(p/'run-status.json',{'failures':int(failed),'asset_hashes_unchanged':True})
        for name in ['official','fireemu']:
            q=p/f'block-00-{name}';q.mkdir()
            dump(q/'trial.json',dict(block=0,engine=name,discard=False,profile='firebase',ok=not(failed and name=='fireemu'),
                 usable_ready_ms=10 if name=='official' else 5,cases=[],phases=[],pre_stop={}))
            (q/'samples.jsonl').write_text('')
    def test_valid_pair(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);self.create(p);self.assertTrue(render(p))
            rows=json.loads((p/'summary.json').read_text())['rows']
            x=next(r for r in rows if r['metric']=='startup/sdk-usable-ms')
            self.assertEqual(x['benefit_ratio'],2)
    def test_failed_trial_suppresses_claim(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);self.create(p,True);self.assertFalse(render(p))
            rows=json.loads((p/'summary.json').read_text())['rows']
            self.assertTrue(all(r['benefit_ratio'] is None for r in rows))
    def test_missing_trial_is_not_filtered_into_success(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);self.create(p);(p/'block-00-fireemu/trial.json').unlink()
            self.assertFalse(render(p))
    def test_process_fallback_cannot_publish_comparison(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);self.create(p)
            m=json.loads((p/'manifest.json').read_text());m['supervisor']='process';dump(p/'manifest.json',m)
            self.assertFalse(render(p))


if __name__=='__main__':unittest.main()
