#!/usr/bin/env python3
"""Paired Firebase-emulator/fireemu benchmark. Linux only, no Python dependencies.
Canonical runs use systemd transient services and per-engine cgroup v2 accounting.
Process-group mode is ONLY for harness development, not a substitute memory metric.
"""
from __future__ import annotations
import argparse
import errno
import hashlib
import json
import os
import platform
import queue
import random
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from linux_metrics import members, snapshot

HERE = Path(__file__).resolve().parent
ACTIVE = set()

def ensure_launcher():
    source=HERE/'exec_engine.c'
    binary=HERE/'exec_engine'
    if not binary.exists() or binary.stat().st_mtime_ns < source.stat().st_mtime_ns:
        subprocess.run(['cc','-O2','-std=c11','-Wall','-Wextra','-Werror',str(source),'-o',str(binary)],check=True,timeout=30)
    return binary


def dump(path, data):
    path = Path(path)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + '\n')
    tmp.replace(path)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(1024*1024), b''): h.update(b)
    return h.hexdigest()


def capture(argv, cwd=None):
    p = subprocess.run(argv, cwd=cwd, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=30)
    if p.returncode: raise RuntimeError(f'{argv[0]} failed: {p.stdout[:1000]}')
    return p.stdout.strip()


def env_for(home, cache):
    # No GITHUB_TOKEN, Firebase login credentials, GAC, proxy, inherited JVM/Rust flags.
    e = {k: os.environ[k] for k in ['PATH','JAVA_HOME','LANG','LC_ALL','TZ'] if k in os.environ}
    e.update(HOME=str(home), XDG_CONFIG_HOME=str(home/'config'), CLOUDSDK_CONFIG=str(home/'gcloud'),
             FIREBASE_EMULATORS_PATH=str(cache), CI='true', NO_COLOR='1',
             FIREBASE_CLI_DISABLE_UPDATE_CHECK='1', GCE_METADATA_HOST='127.0.0.1:9')
    return e


def reserve_ports(count=5):
    sockets=[]
    try:
        for _ in range(count):
            s=socket.socket();s.bind(('127.0.0.1',0));sockets.append(s)
        return [s.getsockname()[1] for s in sockets]
    finally:
        for s in sockets:s.close()


def paired_orders(pairs, discard, seed):
    rng=random.Random(seed); first=rng.randrange(2)
    return [(i, i < discard, ['official','fireemu'] if (i+first)%2==0
             else ['fireemu','official']) for i in range(pairs+discard)]


def scenarios(c, tier):
    if tier=='smoke':
        return [dict(id='get-c1',kind='get',ops=c['pointOps'],concurrency=1),
                dict(id='range-c1',kind='query-range',ops=3,concurrency=1),
                dict(id='scan-c1',kind='scan',ops=1,concurrency=1)]
    out=[]
    for concurrency in [1,16]:
        for kind in ['get','get-all','set','merge']:
            out.append(dict(id=f'{kind}-c{concurrency}',kind=kind,ops=c['pointOps'],concurrency=concurrency))
    for kind in ['query-eq','query-range','query-offset','query-cursor','count','sum']:
        out.append(dict(id=kind,kind=kind,ops=c['queryOps'],concurrency=1))
    for kind in ['scan','projection']:
        out.append(dict(id=kind,kind=kind,ops=c['scanOps'],concurrency=1))
    out += [dict(id='batch100',kind='batch',ops=10,concurrency=1),
            dict(id='transaction-c8',kind='transaction',ops=c['transactionOps'],concurrency=8),
            dict(id='transaction-hot-c4',kind='transaction-hot',ops=20,concurrency=4),
            dict(id='rules-allow',kind='rules-allow',ops=100,concurrency=1),
            dict(id='rules-deny',kind='rules-deny',ops=100,concurrency=1),
            dict(id='listen-fanout10',kind='listen',ops=20,concurrency=1,fanout=10)]
    return out


class Client:
    def __init__(self, config, cwd, env, worker=HERE/'client.mjs'):
        self.lines=queue.Queue();self.counter=0
        self.log=(cwd/'client.stderr.log').open('w')
        e=env.copy(); e['BENCH_CLIENT_CONFIG']=json.dumps(config)
        self.p=subprocess.Popen([shutil.which('node'),str(worker)],stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,stderr=self.log,text=True,bufsize=1,
                                env=e,start_new_session=True)
        def read():
            for line in self.p.stdout:
                try:self.lines.put(json.loads(line))
                except json.JSONDecodeError:self.lines.put({'fatal':line[:1000]})
            self.lines.put({'fatal':'client EOF'})
        threading.Thread(target=read,daemon=True).start()
        try:
            boot=self.lines.get(timeout=60)
            if boot.get('type')!='boot':raise RuntimeError(f'client boot: {boot}')
            self.metadata=boot.get('metadata',{})
        except BaseException:
            try:os.killpg(self.p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            self.p.wait(timeout=10);self.log.close()
            raise
    def call(self,action,timeout=300,**kwargs):
        self.counter+=1
        self.p.stdin.write(json.dumps(dict(id=self.counter,action=action,**kwargs))+'\n');self.p.stdin.flush()
        try:r=self.lines.get(timeout=timeout)
        except queue.Empty:raise TimeoutError(f'Client timed out in {action}; trial must be discarded, not retried')
        if r.get('id')!=self.counter or not r.get('ok'):
            raise RuntimeError(f'Client failure in {action}: {r}')
        return r['data']
    def stop(self):
        result={'forced_kill':False}
        if self.p.poll() is None:
            try:self.call('close',timeout=15);self.p.wait(timeout=10)
            except Exception:
                result['forced_kill']=True
                try:os.killpg(self.p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                self.p.wait(timeout=10)
        result['exit_code']=self.p.returncode
        self.log.close()
        return result


class Engine:
    def __init__(self,argv,cwd,env,supervisor):
        self.unit='fireemu-bench-'+uuid.uuid4().hex+'.service'
        self.cwd=cwd;self.mode=supervisor;self.p=None;self.cgroup=None;self.pgid=None
        self.argv=argv;self.env=env;self.launcher=ensure_launcher()
        self.launch=cwd/'launch.json'; self.stamp=cwd/'exec-stamp.json'
        self.gate=cwd/'exec-gate.fifo';os.mkfifo(self.gate,0o600)
        dump(self.launch,dict(argv=argv,cwd=str(cwd),env=env,stamp=str(self.stamp)))
    def start(self):
        ACTIVE.add(self)
        self.before=time.monotonic_ns()
        data=json.loads(self.launch.read_text())
        env=dict(self.env)
        if data.get('allow_root_for_selftest'):env['BENCH_ALLOW_ROOT_SELFTEST']='1'
        executable=['/usr/bin/env','-i',*[f'{k}={v}' for k,v in env.items()],
                    str(self.launcher),str(self.stamp),str(self.cwd),str(self.gate),*self.argv]
        if self.mode=='systemd':
            command=['sudo','-n','systemd-run','--quiet','--unit='+self.unit,
                     '--property=Type=exec','--property=User='+str(os.getuid()),
                     '--property=Group='+str(os.getgid()),'--property=WorkingDirectory='+str(self.cwd),
                     '--property=MemoryAccounting=yes','--property=CPUAccounting=yes',
                     '--property=KillMode=control-group','--property=KillSignal=SIGINT',
                     '--property=TimeoutStopSec=15s','--property=RemainAfterExit=yes',
                     '--property=StandardOutput=append:'+str(self.cwd/'engine.log'),
                     '--property=StandardError=append:'+str(self.cwd/'engine.log'),
                     *executable]
            subprocess.run(command,check=True,timeout=30)
            path=capture(['systemctl','show',self.unit,'--property=ControlGroup','--value'])
            if not path.startswith('/') or '..' in Path(path).parts:raise RuntimeError('Unsafe cgroup path')
            self.cgroup=Path('/sys/fs/cgroup')/path.lstrip('/')
            if not (self.cgroup/'memory.current').exists():raise RuntimeError('cgroup v2 memory accounting unavailable')
        else:
            self.log=(self.cwd/'engine.log').open('w')
            self.p=subprocess.Popen(executable,
                                    stdout=self.log,stderr=subprocess.STDOUT,start_new_session=True)
            self.pgid=self.p.pid
        deadline=time.monotonic()+30
        # The engine has not executed yet. First finish supervisor/cgroup discovery,
        # then release the tiny helper, which stamps CLOCK_MONOTONIC and execs.
        while True:
            try:
                gate_fd=os.open(self.gate,os.O_WRONLY|os.O_NONBLOCK)
                break
            except OSError as exc:
                if exc.errno!=errno.ENXIO:raise
                if time.monotonic()>deadline:raise TimeoutError('Engine exec gate reader absent')
                time.sleep(.001)
        try:os.write(gate_fd,b'1')
        finally:os.close(gate_fd);self.gate.unlink(missing_ok=True)
        while True:
            try:
                stamp=json.loads(self.stamp.read_text())
                break
            except (FileNotFoundError,json.JSONDecodeError):
                if time.monotonic()>deadline:raise TimeoutError('Engine exec stamp absent')
                time.sleep(.001)
        self.t0=stamp['exec_monotonic_ns'];self.pid=stamp['pid']
        return {'orchestration_to_exec_ms':(self.t0-self.before)/1e6,'unit':self.unit,'pid':self.pid}
    def sample(self):return snapshot(self.cgroup,self.pgid)
    def stop(self):
        if self not in ACTIVE:return {}
        result={}
        if self.mode=='systemd':
            try:
                subprocess.run(['sudo','-n','systemctl','stop',self.unit],check=True,timeout=40)
                try:
                    result['systemd_result']=capture(['systemctl','show',self.unit,'--property=Result','--value'])
                except RuntimeError:
                    # Inactive successful transient units can already be garbage-collected.
                    result['systemd_result']='not-retained-after-stop'
                result['remaining_pids']=members(self.cgroup)
            finally:
                subprocess.run(['sudo','-n','systemctl','reset-failed',self.unit],capture_output=True,timeout=10)
        else:
            try:os.killpg(self.pgid,signal.SIGINT)
            except ProcessLookupError:pass
            try:self.p.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(self.pgid,signal.SIGKILL);self.p.wait(timeout=5)
                result['forced_kill']=True
            remaining=members(None,self.pgid)
            if remaining:
                os.killpg(self.pgid,signal.SIGKILL);time.sleep(.1)
            result['remaining_pids']=members(None,self.pgid)
            self.log.close()
        ACTIVE.discard(self)
        return result


class Sampler:
    def __init__(self,engine,path,interval):
        self.e=engine;self.path=path;self.interval=interval;self.phase='startup';self.stop_event=threading.Event()
        self.count=0;self.failures=0;self.overhead_ms=0
    def start(self):
        def loop():
            with self.path.open('w') as file:
                while not self.stop_event.is_set():
                    try:s=self.e.sample()
                    except Exception as exc:s={'complete':False,'errors':[str(exc)],'monotonic_ns':time.monotonic_ns()}
                    s['phase']=self.phase
                    file.write(json.dumps(s,allow_nan=False)+'\n');file.flush()
                    self.count+=1;self.failures+=int(not s['complete']);self.overhead_ms+=s.get('sampler_wall_ms',0)
                    self.stop_event.wait(self.interval)
        self.thread=threading.Thread(target=loop,daemon=True);self.thread.start()
    def stop(self):
        self.stop_event.set();self.thread.join(timeout=10)
        return dict(samples=self.count,incomplete_samples=self.failures,sampler_wall_ms=self.overhead_ms,
                    interval_ms=self.interval*1000)


def phase(sampler,name,client=None,action=None,seconds=0,**kwargs):
    sampler.phase=name
    start=sampler.e.sample();begin=time.monotonic_ns()
    data=client.call(action,**kwargs) if action else None
    if seconds:time.sleep(seconds)
    end=sampler.e.sample()
    return dict(name=name,start_ns=begin,end_ns=time.monotonic_ns(),before=start,after=end,data=data)


def config_files(cwd,ports,profile):
    firestore,hub,websocket,http,storage=ports
    # The same server-side Rules are loaded by both. Admin trials bypass Rules;
    # the explicitly named Web SDK cases exercise allow and deny checks.
    (cwd/'firestore.rules').write_text('''rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{doc=**} {
      allow read: if request.auth != null && request.auth.uid == 'bench-user'
                  && resource.data.owner == request.auth.uid;
      allow write: if false;
    }
  }
}
''')
    indexes={'indexes':[{'collectionGroup':'bench_items','queryScope':'COLLECTION','fields':[
             {'fieldPath':'bucket','order':'ASCENDING'},{'fieldPath':'score','order':'DESCENDING'}]}],
             'fieldOverrides':[{'collectionGroup':'bench_items','fieldPath':'payload','indexes':[]}]}
    dump(cwd/'firestore.indexes.json',indexes)
    firebase={'firestore':{'rules':'firestore.rules','indexes':'firestore.indexes.json'},
              'emulators':{'firestore':{'host':'127.0.0.1','port':firestore,'websocketPort':websocket},
                           'hub':{'host':'127.0.0.1','port':hub},'ui':{'enabled':False},
                           'singleProjectMode':True}}
    dump(cwd/'firebase.json',firebase)
    dump(cwd/'fireemu.json',{'schemaVersion':1,'profile':profile,'firebaseJson':'firebase.json',
         'bind':'127.0.0.1','projects':{'requireDemoPrefix':True},
         'firestore':{'edition':'standard','apiMode':'native'},'rules':{'executionMode':'native'}})


def run_trial(args,c,block,discard,engine_name,case_order,cache,out):
    cwd=out/f'block-{block:02d}-{engine_name}';cwd.mkdir()
    home=cwd/'home';home.mkdir()
    ports=reserve_ports();config_files(cwd,ports,args.profile)
    project=f'demo-bench-{block:02d}'
    env=env_for(home,cache)
    if engine_name=='official':
        argv=[shutil.which('node'),args.firebase_cli,'emulators:start','--only','firestore',
              '--project',project,'--config',str(cwd/'firebase.json'),'--non-interactive','--log-verbosity','QUIET']
    else:
        argv=[args.fireemu,'up','--config',str(cwd/'fireemu.json'),'--only','firestore','--project',project,
              '--firestore-port',str(ports[0]),'--hub-port',str(ports[1]),'--http-port',str(ports[3]),
              '--storage-port',str(ports[4]),'--ui-port','0','--logging-port','0','--log-verbosity','quiet']
    client=engine=sampler=None
    trial=dict(engine=engine_name,block=block,discard=discard,profile=args.profile,ok=False,
               command=argv,project=project,ports=ports,phases=[],cases=[])
    try:
        client=Client(dict(project=project,host=f'127.0.0.1:{ports[0]}',nonce=uuid.uuid4().hex,
                           sdkRoot=args.sdk_root,documents=c['documents'],payloadBytes=c['payloadBytes']),cwd,env)
        trial['client_metadata']=client.metadata
        engine=Engine(argv,cwd,env,args.supervisor);trial['launch']=engine.start()
        sampler=Sampler(engine,cwd/'samples.jsonl',args.sample_ms/1000);sampler.start()
        deadline=time.monotonic()+args.start_timeout
        # TCP is diagnostic only. Startup ends only after SDK write + read-back + delete.
        while True:
            try:
                with socket.create_connection(('127.0.0.1',ports[0]),timeout=.1):break
            except OSError:
                if time.monotonic()>deadline:raise TimeoutError('TCP readiness deadline')
                time.sleep(.01)
        trial['tcp_ready_ms']=(time.monotonic_ns()-engine.t0)/1e6
        client.call('ready',timeout=max(1,deadline-time.monotonic()))
        trial['usable_ready_ms']=(time.monotonic_ns()-engine.t0)/1e6
        trial['phases'].append(phase(sampler,'idle-empty',seconds=c['idleSeconds']))
        if not args.startup_only:
            trial['phases'].append(phase(sampler,'seed-and-verify',client,'seed',timeout=900))
            trial['phases'].append(phase(sampler,'idle-loaded',seconds=c['idleSeconds']))
            for j,spec in enumerate(case_order):
                warm={**spec,'ops':min(spec['ops'], 200 if not spec['kind'].startswith('transaction') else 5)}
                if spec['kind'] in ['scan','projection','listen','batch']:warm['ops']=1
                warm_phase=phase(sampler,'warmup:'+spec['id'],client,'run',spec=warm,namespace=f'w{j}')
                trial['phases'].append(warm_phase)
                if not warm_phase['data']['ok']:raise RuntimeError('warmup validation failed: '+spec['id'])
                measured=phase(sampler,'measure:'+spec['id'],client,'run',spec=spec,namespace=f'm{j}')
                trial['phases'].append(measured)
                trial['cases'].append(measured['data'])
                if not measured['data']['ok']:raise RuntimeError('workload validation failed: '+spec['id'])
            trial['phases'].append(phase(sampler,'before-release',seconds=c['idleSeconds']))
            trial['phases'].append(phase(sampler,'delete-via-sdk',client,'clear',timeout=900))
            trial['phases'].append(phase(sampler,'idle-after-delete',seconds=c['idleSeconds']))
            # A fixed observation window, not forced GC or engine-specific clock advancement.
            trial['phases'].append(phase(sampler,'idle-after-delete-long',seconds=args.recovery_seconds))
        for observed in trial['phases']:
            if not observed['before']['complete'] or not observed['after']['complete']:
                raise RuntimeError('Incomplete phase boundary measurement: '+observed['name'])
        trial['pre_stop']=engine.sample()
        if not trial['pre_stop']['complete']:raise RuntimeError('Incomplete memory/CPU measurement')
        if not trial['pre_stop'].get('process_count'):raise RuntimeError('Engine vanished before cleanup')
        events=trial['pre_stop'].get('memory_events') or {}
        if any(events.get(k,0)>0 for k in ['oom','oom_kill']):
            raise RuntimeError('Engine cgroup encountered OOM')
        trial['ok']=True
    except Exception as exc:
        trial['error']=f'{type(exc).__name__}: {exc}'
    finally:
        if client:
            try:
                trial['client_cleanup']=client.stop()
                if trial['client_cleanup']['forced_kill'] or trial['client_cleanup']['exit_code']:
                    trial['ok']=False
            except Exception as exc:trial['client_cleanup_error']=str(exc);trial['ok']=False
        if sampler:
            trial['sampling']=sampler.stop()
            if trial['sampling']['incomplete_samples']:
                trial['ok']=False
                trial.setdefault('error','Sampler could not read one or more required metrics')
        if engine:
            t=time.monotonic()
            try:
                trial['cleanup']=engine.stop();trial['stop_ms']=(time.monotonic()-t)*1000
                if trial['cleanup'].get('remaining_pids') or trial['cleanup'].get('forced_kill') or \
                   trial['cleanup'].get('systemd_result')=='timeout':trial['ok']=False
            except Exception as exc:trial['cleanup_error']=str(exc);trial['ok']=False
        # launch.json contains no credentials, but do not publish even ephemeral environments.
        (cwd/'launch.json').unlink(missing_ok=True)
        dump(cwd/'trial.json',trial)
    return trial


def metadata(args,c):
    root=Path(args.repo)
    git=lambda *a:capture(['git','-C',str(root),*a])
    data={'schemaVersion':1,'createdAt':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
          'commit':git('rev-parse','HEAD'),'dirty_tracked':bool(git('status','--porcelain','--untracked-files=no')),
          'tier':args.tier,'config':c,'profile':args.profile,'startup_only':args.startup_only,
          'excluded_by_plan':([] if args.profile=='firebase' else [
              {'cases':['rules-allow','rules-deny'], 'reason':'strict requires verified tokens; these cases use EmulatorMock and are not comparable without an Auth fixture'}]),
          'supervisor':args.supervisor,'cache_state':'assets-preinstalled; process-cold, OS-cache-uncontrolled',
          'node':capture([shutil.which('node'),'--version']), 'java':capture(['java','-version']),
          'python':sys.version,'kernel':platform.release(),'architecture':platform.machine(),
          'cpu_count':os.cpu_count(),'cpu_affinity':sorted(os.sched_getaffinity(0)),
          'cpuinfo':Path('/proc/cpuinfo').read_text(),'meminfo':Path('/proc/meminfo').read_text(),
          'runner':{k:os.environ.get(k) for k in ['RUNNER_OS','RUNNER_ARCH','ImageOS','ImageVersion','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT']},
          'binary_kind':'caller-supplied; workflow default: release x86_64-unknown-linux-musl with UI embedded',
          'binary_sha256':sha(args.fireemu),'binary_version':capture([args.fireemu,'--version']),
          'firebase_version':capture([shutil.which('node'),args.firebase_cli,'--version']),
          'conformance_lock_sha256':sha(root/'conformance/pnpm-lock.yaml'),
          'cargo_lock_sha256':sha(root/'Cargo.lock'),
          'harness_sha256':{str(p.relative_to(HERE)):sha(p) for p in sorted(HERE.glob('*')) if p.suffix in ['.py','.mjs','.json','.c']},
          'exec_helper_sha256':sha(ensure_launcher()),'exec_helper_accounting':'included in cgroup peak, no persistent supervisor in engine cgroup',
          'sampling_interval_ms':args.sample_ms,'recovery_seconds':args.recovery_seconds}
    for file in ['cpu','memory','io']:
        p=Path('/proc/pressure')/file;data['pressure_'+file]=p.read_text() if p.exists() else None
    return data


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo',default='.');p.add_argument('--fireemu',required=True)
    p.add_argument('--sdk-root',default='conformance');p.add_argument('--firebase-cli')
    p.add_argument('--tier',choices=['smoke','standard','extended'],default='standard')
    p.add_argument('--profile',choices=['firebase','strict'],default='firebase')
    p.add_argument('--out',default='.bench-output');p.add_argument('--supervisor',choices=['systemd','process'],default='systemd')
    p.add_argument('--sample-ms',type=int,default=250);p.add_argument('--start-timeout',type=int,default=180)
    p.add_argument('--recovery-seconds',type=int,default=15);p.add_argument('--startup-only',action='store_true')
    p.add_argument('--pairs',type=int);p.add_argument('--offered-rate',type=int,default=0)
    args=p.parse_args()
    if platform.system()!='Linux':p.error('Linux only: do not compare different memory metrics across platforms')
    if os.geteuid()==0:p.error('Run as the ordinary runner user; sudo is scoped to systemd operations')
    if args.sample_ms<50:p.error('sample-ms must be >= 50')
    args.repo=str(Path(args.repo).resolve());args.sdk_root=str(Path(args.sdk_root).resolve())
    args.fireemu=str(Path(args.fireemu).resolve())
    if not os.access(args.fireemu,os.X_OK):p.error('fireemu binary is missing/not executable')
    if not args.firebase_cli:
        args.firebase_cli=capture(['node','-e',"const r=require('module').createRequire(process.argv[1]);console.log(r.resolve('firebase-tools/lib/bin/firebase.js'));",str(Path(args.sdk_root)/'package.json')])
    else:args.firebase_cli=str(Path(args.firebase_cli).resolve())
    plan=json.loads((HERE/'plan.json').read_text());c=plan['tiers'][args.tier].copy()
    if args.pairs is not None:
        if not 1<=args.pairs<=50:p.error('pairs must be 1..50')
        c['pairs']=args.pairs
    if args.startup_only and args.pairs is None:c['pairs']=12
    out=Path(args.out).resolve();out.mkdir(parents=True,exist_ok=True)
    if (out/'manifest.json').exists():p.error('Use an empty output directory for each run')
    cache=Path(os.environ.get('FIREBASE_EMULATORS_PATH',str(Path.home()/'.cache/firebase/emulators'))).resolve()
    jars=sorted(cache.glob('*firestore*.jar'))
    if not jars:p.error('Pre-download the pinned Firestore emulator with setup:emulators:firestore')
    meta=metadata(args,c);meta['jars']={p.name:sha(p) for p in jars};dump(out/'manifest.json',meta)
    failures=0
    for block,discard,order in paired_orders(c['pairs'],c['discardPairs'],plan['seed']):
        cases=scenarios(c,args.tier)
        if args.profile=='strict':cases=[s for s in cases if not s['kind'].startswith('rules')]
        if args.offered_rate:
            cases.append(dict(id='get-open-loop',kind='get',ops=c['pointOps'],concurrency=64,offeredRate=args.offered_rate))
        random.Random(plan['seed']+block).shuffle(cases)  # identical ordering inside each pair
        for name in order:
            print(f'block={block} discard={discard} engine={name}',flush=True)
            trial=run_trial(args,c,block,discard,name,cases,cache,out)
            if not trial['ok']:failures+=1
            # A dirty stop can contaminate every later sample; stop the experiment.
            if trial.get('cleanup_error') or trial.get('cleanup',{}).get('remaining_pids'):
                raise RuntimeError('Engine cleanup failed; refusing further measurements')
            time.sleep(1)
    after={p.name:sha(p) for p in jars}
    if after!=meta['jars']:failures+=1
    dump(out/'run-status.json',{'failures':failures,'asset_hashes_unchanged':after==meta['jars']})
    return int(failures>0)


def interrupted(signum,frame):
    raise KeyboardInterrupt(f'signal {signum}')


if __name__=='__main__':
    signal.signal(signal.SIGTERM,interrupted)
    try:sys.exit(main())
    finally:
        for e in list(ACTIVE):
            try:e.stop()
            except Exception:pass
