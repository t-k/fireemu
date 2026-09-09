"""Report-only tests: no Firebase or network, no claimed benchmark results."""
from __future__ import annotations
import csv
import json
import math
import tempfile
import unittest
from pathlib import Path

from report import (aggregate_metric, append_job_summary, convert_unit, main, md,
                    number, paired_ratio, percent, percentages, render)


def fixture(root, pairs=3):
    def dump(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) + '\n', encoding='utf-8')
    dump(root/'manifest.json', dict(commit='a'*40, profile='emulator', tier='example',
        supervisor='systemd', synthetic=True, config=dict(pairs=pairs)))
    dump(root/'run-status.json', dict(failures=0, asset_hashes_unchanged=True))
    for block in range(pairs):
        for engine in ('official','fireemu'):
            factor=1+block/10
            official=engine=='official'
            case=dict(spec=dict(id='get-c16'), ok=True,
                p50_ms=(5 if official else 2)*factor,
                p95_ms=(10 if official else 4)*factor,
                p99_ms=(20 if official else 8)*factor,
                throughput_rps=(1000 if official else 2500)*factor,
                latency_ms=[1.0]*1000)
            location=root/f'block-{block:02}-{engine}'
            dump(location/'trial.json', dict(block=block, engine=engine, discard=False,
                profile='emulator', ok=True, usable_ready_ms=(2000 if official else 200)*factor,
                tcp_ready_ms=(1800 if official else 180)*factor, stop_ms=(100 if official else 50)*factor,
                pre_stop=dict(cgroup_memory_peak_bytes=(512 if official else 64)*1024**2*factor),
                phases=[dict(name='seed-and-verify', data=dict(dataset_sha256='same-fixture'))],
                cases=[case]))
            samples=[dict(phase='idle-loaded', complete=True,
                pss_bytes=(512 if official else 64)*1024**2*factor) for _ in range(4)]
            (location/'samples.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in samples))


class UnitTests(unittest.TestCase):
    def test_ns_us_ms_s_normalize_to_ms(self):
        for source,value in [('ns',1000000),('us',1000),('µs',1000),('ms',1),('s',.001)]:
            self.assertAlmostEqual(convert_unit(value,source,'ms'),1)
    def test_mib_is_binary_not_mb(self):
        self.assertEqual(convert_unit(1048576,'bytes','MiB'),1)
        self.assertNotEqual(convert_unit(1000000,'bytes','MiB'),1)
    def test_tiny_time_is_not_displayed_as_zero(self):
        tiny=convert_unit(1,'ns','ms')
        self.assertNotEqual(number(tiny),'0.000')
        self.assertAlmostEqual(float(number(tiny)),1e-6)
    def test_no_dimension_or_unit_guessing(self):
        for source,target in [('bytes','ms'),('GB','MiB'),('ops/s','req/s')]:
            with self.assertRaises(ValueError):convert_unit(1,source,target)
    def test_nonfinite_unit_values_rejected(self):
        for value in [None,True,float('nan'),float('inf')]:
            with self.assertRaises(ValueError):convert_unit(value,'ms','ms')
    def test_mixed_time_units_are_converted_before_ratio(self):
        blocks={0:{'official':({}, {'metric':(10000000,False,'ns')}),
                   'fireemu':({}, {'metric':(5,False,'ms')})}}
        row=aggregate_metric('metric',blocks,1,True)
        self.assertEqual(row['unit'],'ms'); self.assertEqual(row['official_median'],10)
        self.assertAlmostEqual(row['relative_percent'],50)
    def test_unit_mismatch_suppresses_percent(self):
        blocks={0:{'official':({}, {'metric':(10,False,'ms')}),
                   'fireemu':({}, {'metric':(5,False,'bytes')})}}
        row=aggregate_metric('metric',blocks,1,True)
        self.assertIsNone(row['relative_percent'])
        self.assertEqual(row['reason'],'incompatible-unit-or-direction')


class PercentageTests(unittest.TestCase):
    def test_half_latency_is_50_percent_less_not_100(self):
        p=percentages(2,1.5,2.5,False)
        self.assertEqual(p['relative_percent'],50)
        self.assertEqual(p['change_percent'],-50)
        self.assertEqual(p['improvement_percent'],50)
        self.assertAlmostEqual(p['relative_ci95_low'],40)
        self.assertAlmostEqual(p['relative_ci95_high'],100/1.5)
    def test_double_throughput_is_100_percent_more(self):
        p=percentages(2,1.5,2.5,True)
        self.assertEqual(p['relative_percent'],200)
        self.assertEqual(p['change_percent'],100)
        self.assertEqual(p['improvement_percent'],100)
    def test_regressions_are_negative_improvements(self):
        self.assertEqual(percentages(.5,None,None,False)['improvement_percent'],-100)
        self.assertEqual(percentages(.5,None,None,True)['improvement_percent'],-50)
    def test_equal_results_are_100_percent_and_zero_delta(self):
        p=percentages(1,1,1,False)
        self.assertEqual(p['relative_percent'],100)
        self.assertEqual(percent(p['change_percent'],signed=True),'0.0%')
    def test_ci_endpoints_contain_point_estimate(self):
        for higher in (False,True):
            p=percentages(1.25,.8,2,higher)
            for stem in ('relative','change','improvement'):
                self.assertLessEqual(p[f'{stem}_ci95_low'],p[f'{stem}_percent'])
                self.assertGreaterEqual(p[f'{stem}_ci95_high'],p[f'{stem}_percent'])
    def test_missing_benefit_never_produces_zero_percent(self):
        self.assertTrue(all(x is None for x in percentages(None,None,None,False).values()))
        self.assertEqual(percent(None),'N/A')
    def test_zero_baseline_has_no_percentage(self):
        blocks={0:{'official':({}, {'metric':(0,False,'ms')}),
                   'fireemu':({}, {'metric':(1,False,'ms')})}}
        row=aggregate_metric('metric',blocks,1,True)
        self.assertEqual(row['official_median'],0)
        self.assertIsNone(row['relative_percent'])
    def test_delta_uses_paired_estimator_not_ratio_of_medians(self):
        official=[1,2,100]; fireemu=[1,4,50]
        b,lo,hi=paired_ratio(official,fireemu)
        p=percentages(b,lo,hi,False)
        self.assertAlmostEqual(p['relative_percent'],100)
        # Ratio of medians is 4/2 = 200%; never mix that with this paired CI.
        self.assertNotEqual(p['relative_percent'],200)
    def test_signed_small_percent_and_no_negative_zero(self):
        self.assertEqual(percent(-0.0,signed=True),'0.0%')
        self.assertEqual(percent(50,signed=True),'+50.0%')
        self.assertEqual(percent(-.01,signed=True),'−0.01%')


class OutputTests(unittest.TestCase):
    def test_markdown_units_directions_percentages_and_alignment(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);fixture(root);self.assertTrue(render(root))
            text=(root/'summary.md').read_text()
            for s in ['Lower is better','Higher is better','Official = 100%','Δ vs Official',
                      'ms','MiB','req/s','10.0%','−90.0%','+150.0%','SYNTHETIC EXAMPLE']:
                self.assertIn(s,text)
            for line in text.splitlines():
                if line.startswith('|') and ('Lower is better' in line or 'Higher is better' in line):
                    self.assertEqual(line.count('|'),9)
            self.assertNotIn('536,870,912.000',text)
    def test_json_csv_keep_raw_and_display_units(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);fixture(root);render(root)
            data=json.loads((root/'summary.json').read_text())
            self.assertEqual(data['schema_version'],2)
            row=next(r for r in data['rows'] if r['metric']=='idle-loaded/pss_bytes')
            self.assertEqual(row['unit'],'bytes'); self.assertEqual(row['display_unit'],'MiB')
            self.assertEqual(row['official_median']/1024**2,row['official_display_median'])
            self.assertAlmostEqual(row['relative_percent'],12.5)
            with (root/'summary.csv').open() as f:
                csvrow=next(r for r in csv.DictReader(f) if r['metric']=='idle-loaded/pss_bytes')
            self.assertEqual(csvrow['display_unit'],'MiB')
            self.assertAlmostEqual(float(csvrow['improvement_percent']),87.5)
    def test_failure_withholds_all_ratios_and_percentages(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);fixture(root)
            p=root/'block-00-fireemu/trial.json';data=json.loads(p.read_text());data.update(ok=False,error='failure | <script>\nnext')
            p.write_text(json.dumps(data));self.assertFalse(render(root))
            rows=json.loads((root/'summary.json').read_text())['rows']
            self.assertTrue(all(r['relative_percent'] is None and r['benefit_ratio'] is None for r in rows))
            text=(root/'summary.md').read_text()
            self.assertIn('&#124;',text);self.assertNotIn('<script>',text)
    def test_missing_pair_withholds_claim_but_preserves_other_values(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);fixture(root,1);(root/'block-00-fireemu/trial.json').unlink()
            self.assertFalse(render(root))
            row=next(r for r in json.loads((root/'summary.json').read_text())['rows'] if r['metric']=='startup/sdk-usable-ms')
            self.assertEqual(row['official_median'],2000);self.assertIsNone(row['fireemu_median'])
            self.assertIsNone(row['relative_percent'])
    def test_p99_needs_minimum_samples_in_every_pair(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);fixture(root)
            p=root/'block-00-fireemu/trial.json';data=json.loads(p.read_text());data['cases'][0]['latency_ms']=[1]*999;p.write_text(json.dumps(data))
            render(root);row=next(r for r in json.loads((root/'summary.json').read_text())['rows'] if r['metric']=='get-c16/p99_ms')
            self.assertIsNone(row['relative_percent'])
            self.assertEqual(row['reason'],'p99-needs-1000-samples-per-trial')
    def test_small_pair_count_no_invented_ci(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);fixture(root,2);render(root)
            self.assertIn('CI unavailable (<3 pairs)',(root/'summary.md').read_text())
    def test_asset_change_disables_claim(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);fixture(root)
            (root/'run-status.json').write_text(json.dumps(dict(failures=0,asset_hashes_unchanged=False)))
            self.assertFalse(render(root))
    def test_summary_append_and_size_limit(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);p=root/'summary.md';dest=root/'github-summary';p.write_text('hello\n')
            append_job_summary(p,dest);self.assertEqual(dest.read_text(),'hello\n')
            p.write_text('x'*10000);append_job_summary(p,dest,max_bytes=1024)
            self.assertIn('size limit',dest.read_text());self.assertLess(dest.stat().st_size,1024)
    def test_corrupt_input_still_publishes_failure_summary(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'manifest.json').write_text('{bad')
            dest=root/'github-summary'
            self.assertEqual(main([str(root),'--github-summary',str(dest)]),1)
            self.assertIn('NOT COMPARABLE',dest.read_text())
    def test_missing_manifest_is_readable(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);dest=root/'github-summary'
            self.assertEqual(main([str(root),'--github-summary',str(dest)]),0)
            self.assertIn('did not reach preflight',dest.read_text())
    def test_markdown_escape(self):
        self.assertEqual(md('a|b\n<script>'), 'a&#124;b<br>&lt;script&gt;')


if __name__=='__main__':unittest.main()
