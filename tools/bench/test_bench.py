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
    def test_profile_mismatch_suppresses_claim(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);self.create(p)
            path=p/'block-00-fireemu/trial.json'
            value=json.loads(path.read_text());value['profile']='strict';dump(path,value)
            self.assertFalse(render(p))
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

class ComparisonTests(unittest.TestCase):
    def test_explicit_comparison_order_preserves_pairing(self):
        order=paired_orders(4,1,99,('baseline-fireemu','candidate-fireemu'))
        self.assertEqual({x for _,_,pair in order for x in pair},{'baseline-fireemu','candidate-fireemu'})
        self.assertEqual(sum(pair[0]=='baseline-fireemu' for _,discard,pair in order if not discard),2)
    def test_duplicate_roles_rejected(self):
        with self.assertRaises(ValueError):paired_orders(1,0,99,('fireemu','fireemu'))


class MixedConfigurationTests(unittest.TestCase):
    def test_services_are_enabled_only_on_opt_in(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);config_files(p,[8080,4400,9150,9099,9199],'emulator',mixed=True)
            config=json.loads((p/'firebase.json').read_text())
            self.assertEqual(config['emulators']['storage']['port'],9199)
            self.assertEqual(config['emulators']['auth']['port'],9099)
            self.assertTrue((p/'storage.rules').exists())

class BenchmarkWorkflowTests(unittest.TestCase):
    def step(self,name):
        workflow=(Path(__file__).resolve().parents[2]/'.github/workflows/benchmark.yml').read_text()
        self.assertIn('      - name: '+name+'\n',workflow)
        section=workflow.split('      - name: '+name+'\n',1)[1].split('\n      - ',1)[0]
        self.assertIn('        run: |\n',section)
        result=[]
        for line in section.split('        run: |\n',1)[1].splitlines():
            if line and not line.startswith('          '):break
            result.append(line[10:])
        return '\n'.join(result)+'\n'

    def shell(self,script,cwd,**variables):
        import subprocess
        env=os.environ.copy();env.update(variables)
        return subprocess.run(['bash','-e','-o','pipefail','-c',script],cwd=cwd,env=env,
                              stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)

    def test_baseline_ref_guard_executes_against_real_git_history(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            cwd=Path(directory)
            def git(*argv):return subprocess.check_output(['git','-c','user.name=Benchmark Test','-c','user.email=bench@example.test','-c','commit.gpgsign=false',*argv],cwd=cwd,stderr=subprocess.DEVNULL,text=True).strip()
            git('init');git('commit','--allow-empty','-m','baseline');baseline=git('rev-parse','HEAD')
            git('commit','--allow-empty','-m','candidate');candidate=git('rev-parse','HEAD');git('tag','--no-sign','-a','-m','tag','annotated',baseline);tag=git('rev-parse','annotated')
            git('checkout','--orphan','unrelated');git('commit','--allow-empty','-m','unrelated');unrelated=git('rev-parse','HEAD');git('checkout','--detach',candidate)
            script=self.step('Validate baseline source pin')
            for value,expected in [('',True),(baseline,True),(candidate,True),('a'*40,False),(tag,False),(unrelated,False),(baseline[:12],False),(baseline+'^{commit}',False),('main',False),('$(touch injected)',False),('a'*39,False)]:
                with self.subTest(value=value):
                    result=self.shell(script,cwd,BASELINE_COMMIT=value,GITHUB_SHA=candidate)
                    self.assertEqual(result.returncode==0,expected,result.stdout);self.assertFalse((cwd/'injected').exists())
            self.assertNotEqual(self.shell(script,cwd,BASELINE_COMMIT=baseline,GITHUB_SHA=baseline).returncode,0)

    def test_artifact_verification_checks_both_source_pins_and_all_bytes(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            cwd=Path(directory);candidate='a'*40;baseline='b'*40
            for folder,commit in [('bench-bin',candidate),('bench-baseline',baseline)]:
                path=cwd/folder;path.mkdir();(path/'fireemu').write_text('synthetic binary fixture\n');(path/'commit.txt').write_text(commit+'\n');(path/'toolchain.txt').write_text('identical pinned toolchain fixture\n');(path/'build.txt').write_text(f'source_commit={commit}\ntarget=x86_64-unknown-linux-musl\nprofile=release\n')
                (path/'SHA256SUMS').write_text(''.join(hashlib.sha256((path/name).read_bytes()).hexdigest()+'  '+name+'\n' for name in ['fireemu','commit.txt','toolchain.txt','build.txt']))
            script=self.step('Verify source-bound benchmark binaries')
            def run(value=baseline):return self.shell(script,cwd,BASELINE_COMMIT=value,GITHUB_SHA=candidate)
            self.assertEqual(run().returncode,0);self.assertEqual(run('').returncode,0);self.assertNotEqual(run('c'*40).returncode,0)
            self.assertNotEqual(self.shell(script,cwd,BASELINE_COMMIT=baseline,GITHUB_SHA='c'*40).returncode,0)
            for name in ['fireemu','commit.txt','toolchain.txt','build.txt']:
                with self.subTest(name=name):
                    path=cwd/'bench-baseline'/name;original=path.read_bytes();path.write_bytes(original+b'tampered\n');self.assertNotEqual(run().returncode,0);path.write_bytes(original)
            for name,value in [('commit.txt','c'*40+'\n'),('build.txt',f'source_commit={baseline}\ntarget=wrong-target\nprofile=debug\n')]:
                path=cwd/'bench-baseline'/name;sums=cwd/'bench-baseline/SHA256SUMS';original=path.read_bytes();old_sums=sums.read_text();path.write_text(value);sums.write_text(old_sums.replace(hashlib.sha256(original).hexdigest(),hashlib.sha256(path.read_bytes()).hexdigest()));self.assertNotEqual(run().returncode,0);path.write_bytes(original);sums.write_text(old_sums)
            path=cwd/'bench-baseline/toolchain.txt';path.write_text('different compiler\n');sums=cwd/'bench-baseline/SHA256SUMS';text=sums.read_text().replace(hashlib.sha256(b'identical pinned toolchain fixture\n').hexdigest(),hashlib.sha256(path.read_bytes()).hexdigest());sums.write_text(text);self.assertNotEqual(run().returncode,0)

    def test_default_and_selected_measurement_argv_and_workflow_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            cwd=Path(directory);record=cwd/'argv';stub=cwd/'python3';stub.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$RECORDED_ARGS"\n');stub.chmod(0o755)
            script=self.step('Paired measurements, sequential on this single runner')
            for selected in ['', 'a'*40]:
                result=self.shell(script,cwd,PATH=str(cwd)+os.pathsep+os.environ['PATH'],RECORDED_ARGS=str(record),BASELINE_COMMIT=selected,TIER='standard',PROFILE='emulator',STARTUP_ONLY='false',MIXED_SERVICES='true',FIXTURE_SHAPE='wide-map');self.assertEqual(result.returncode,0,result.stdout)
                argv=record.read_text().splitlines();self.assertEqual('--baseline-fireemu' in argv,bool(selected))
                if selected:self.assertEqual(argv[argv.index('--baseline-fireemu')+1],str(cwd.resolve()/'bench-baseline/fireemu'))
                self.assertIn('--mixed-services',argv);self.assertEqual(argv[argv.index('--fixture-shape')+1],'wide-map')
            workflow=(Path(__file__).resolve().parents[2]/'.github/workflows/benchmark.yml').read_text();self.assertIn('fetch-depth: 0',workflow);self.assertIn('name: benchmark-baseline-binary',workflow);self.assertIn("${{ matrix.role == 'baseline'",workflow);self.assertIn('sha256sum fireemu commit.txt toolchain.txt build.txt',workflow)
            for line in workflow.splitlines():
                if 'uses:' in line:self.assertRegex(line,r'@[0-9a-f]{40}(?:\s|$)')
            self.assertNotIn('persist-credentials: true',workflow)
            self.assertIn("RUSTUP_TOOLCHAIN: '1.94.0'",workflow)
            self.assertIn("role: ${{ fromJSON(inputs.baseline_commit != '' && '[\"candidate\",\"baseline\"]' || '[\"candidate\"]') }}",workflow)
            for step in ['Validate baseline source pin','Verify source-bound benchmark binaries','Build release-equivalent UI assets and optimized daemon (not timed)','Paired measurements, sequential on this single runner']:
                self.assertNotIn('${{',self.step(step))
