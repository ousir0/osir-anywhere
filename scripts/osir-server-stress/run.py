#!/usr/bin/env python3
"""Reviewed, disposable GitHub Linux Docker/cgroup-v2 harness. Never builds.

fetch: scoped signed GET secrets -> exact SHA/length archive -> docker load.
run: fixed immutable image IDs, synthetic isolated PG18/Redis/API workload.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import signal
import statistics
import subprocess
import time
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
BINDINGS = json.loads((HERE / 'bindings.json').read_text())
MIB = 1024**2
LABEL = 'osir-isolated-stress-owner'
LIMITS = {'api':(75000,384,512,128), 'pg':(25000,192,256,128),
          'redis':(25000,96,128,128), 'driver':(50000,256,256,128)}
CHILD_ENV = {'PATH':'/usr/bin:/bin', 'HOME':'/tmp', 'LANG':'C', 'LC_ALL':'C'}


class Refused(Exception):
    pass


def require(ok, message):
    if not ok:
        raise Refused(message)


def call(*args, timeout=20):
    p = subprocess.run(args, env=CHILD_ENV, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=timeout)
    require(p.returncode == 0, 'bounded command failed: ' + args[0].split('/')[-1])
    return p.stdout.decode().strip()


def docker(*args, **kw):
    return call('/usr/bin/docker', '--host=unix:///var/run/docker.sock', *args, **kw)


def inspect(ref):
    return json.loads(docker('inspect', ref))[0]


def dump(path, data):
    with path.open('x') as f:
        os.chmod(path, 0o600)
        json.dump(data, f, indent=2, sort_keys=True)


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(MIB), b''):
            h.update(block)
    return h.hexdigest()


def transfer_spec(raw):
    spec=json.loads(raw)
    require(set(spec)=={'host','prefix','archives'}, 'transfer metadata keys')
    require(re.fullmatch(r'[a-z0-9][a-z0-9.-]+', spec['host']) is not None and
            '.' in spec['host'] and not spec['host'].endswith('.local'), 'reviewed HTTPS object host required')
    require(re.fullmatch(r'release-tests/osir-server/[a-z0-9-]{12,80}/',spec['prefix']) is not None,
            'unique test-only object prefix required')
    require(set(spec['archives'])=={'api','pg','redis'}, 'three exact original images required')
    for role,a in spec['archives'].items():
        require(set(a)=={'sha256','bytes','cipher_sha256','cipher_bytes'} and re.fullmatch('[0-9a-f]{64}',a['sha256']) is not None
                and isinstance(a['bytes'],int) and 0<a['bytes']<2*1024**3,
                'archive SHA/length must be sealed after export')
        require(re.fullmatch('[0-9a-f]{64}',a['cipher_sha256']) is not None
                and isinstance(a['cipher_bytes'],int)
                and a['cipher_bytes']==16+16*(a['bytes']//16+1),
                'AES CBC ciphertext SHA/length must be sealed after encryption')
    return spec


def get_url(secret_url, spec, role):
    u=urllib.parse.urlsplit(secret_url)
    require(u.scheme=='https' and u.hostname==spec['host'] and u.port in (None,443)
            and not u.username and not u.password and not u.fragment and
            u.path=='/'+spec['prefix']+role+'.docker.tar.enc', 'scoped signed GET identity refused')
    return secret_url


def image_identity(role):
    expected=BINDINGS['images'][role]
    o=json.loads(docker('image','inspect',expected['id']))[0]
    require(o['Id']==expected['id'] and o['Architecture']=='amd64' and o['Os']=='linux',
            'original image config ID/platform mismatch')
    require(o['RootFS']['Layers']==expected['layers'], 'original uncompressed layer identity mismatch')
    keys=sorted(v.split('=',1)[0] for v in o.get('Config',{}).get('Env',[]))
    require(keys==sorted(expected['env_keys']), 'unexpected inherited image environment')
    return {'id':o['Id'], 'layers':o['RootFS']['Layers'], 'architecture':o['Architecture']}


def decrypt_archive(cipher, plain, expected):
    # Both trusted digests are required; CBC alone does not authenticate data.
    require(cipher.stat().st_size==expected['cipher_bytes'] and
            sha(cipher)==expected['cipher_sha256'], 'ciphertext integrity mismatch')
    with cipher.open('rb') as f:
        require(f.read(8)==b'Salted__', 'salted OpenSSL archive required')
    password=os.environ.get('OSIR_ARCHIVE_PASSWORD','')
    require(re.fullmatch('[0-9a-f]{64}',password) is not None,
            'short-lived random 256-bit archive password required')
    child=dict(CHILD_ENV,OSIR_ARCHIVE_PASSWORD=password)
    args=['/usr/bin/openssl','enc','-d','-aes-256-cbc','-pbkdf2',
          '-iter','200000','-md','sha256','-pass','env:OSIR_ARCHIVE_PASSWORD',
          '-in',str(cipher)]
    # 1.1.1/3.0 use an 8-byte salt; newer releases expose saltlen.
    help_result=subprocess.run(['/usr/bin/openssl','enc','-help'],env=CHILD_ENV,
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
    if b'-saltlen' in help_result.stdout+help_result.stderr:args+=['-saltlen','8']
    created=False
    try:
        with plain.open('xb') as f:
            created=True
            os.chmod(plain,0o600)
            result=subprocess.run(args,env=child,stdout=f,stderr=subprocess.DEVNULL,timeout=300)
        require(result.returncode==0, 'archive decryption failed; details suppressed')
        require(plain.stat().st_size==expected['bytes'] and sha(plain)==expected['sha256'],
                'plaintext archive integrity mismatch')
    except Exception:
        if created and plain.exists():plain.unlink()
        raise Refused('archive decryption or plaintext integrity failed') from None
    finally:
        child.pop('OSIR_ARCHIVE_PASSWORD',None)


def fetch(root):
    spec=transfer_spec(os.environ['OSIR_ARCHIVES_JSON'])
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise Refused('object redirect refused')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    receipt={}
    for role in ('api','pg','redis'):
        url=get_url(os.environ['OSIR_'+role.upper()+'_GET_URL'],spec,role)
        cipher=root/(role+'.docker.tar.enc');path=root/(role+'.docker.tar')
        expected=spec['archives'][role];count=0
        try:
            with opener.open(url,timeout=30) as response, cipher.open('xb') as f:
                os.chmod(cipher,0o600)
                require(response.status==200, 'object download status')
                started=time.monotonic()
                while True:
                    chunk=response.read(MIB)
                    if not chunk:break
                    count+=len(chunk)
                    require(count<=expected['cipher_bytes'] and time.monotonic()-started<900,
                            'bounded object download length/time')
                    f.write(chunk)
        except Refused:
            raise
        except Exception:
            raise Refused('object download failed; URL and credentials suppressed') from None
        decrypt_archive(cipher,path,expected)
        docker('load','--input',str(path),timeout=180)
        receipt[role]={'archive_sha256':expected['sha256'], 'archive_bytes':expected['bytes'],
                       'cipher_sha256':expected['cipher_sha256'],'cipher_bytes':count,
                       'image':image_identity(role)}
    dump(root/'fetch-receipt.json',receipt)


def environment(owner):
    # Import helper only, never product app. RUN_ID must precede module import.
    os.environ['OSIR_ISOLATED_RUN_ID']=owner
    import probe
    return dict(probe.ENV, OSIR_ISOLATED_RUN_ID=owner)


def kernel_paths(pid):
    require(isinstance(pid,int) and pid>0, 'running PID required')
    rows=Path('/proc/%d/cgroup'%pid).read_text().splitlines()
    require(len(rows)==1 and rows[0].startswith('0::/'), 'actual unified cgroup v2 required')
    relative=rows[0].split(':',2)[2]
    require('..' not in Path(relative).parts, 'cgroup traversal refused')
    mount=Path('/sys/fs/cgroup');p=mount/relative.lstrip('/')
    require(p.resolve()==p and mount in p.parents, 'cgroup outside unified mount')
    return p


def kernel_sample(path, role):
    def num(name):return int((path/name).read_text().strip())
    def kv(name):return {a:int(b) for a,b in (x.split() for x in (path/name).read_text().splitlines())}
    quota,mem,total,pids=LIMITS[role]
    limits={'memory.max':num('memory.max'), 'memory.swap.max':num('memory.swap.max'),
            'cpu.max':(path/'cpu.max').read_text().strip(), 'pids.max':num('pids.max')}
    require(limits=={'memory.max':mem*MIB,'memory.swap.max':(total-mem)*MIB,
                     'cpu.max':str(quota)+' 100000','pids.max':pids}, 'actual kernel v2 limits mismatch')
    return dict(limits, **{'memory.current':num('memory.current'), 'memory.peak':num('memory.peak'),
                          'memory.events':kv('memory.events'), 'memory.swap.current':num('memory.swap.current'),
                          'cpu.stat':kv('cpu.stat'), 'pids.current':num('pids.current')})


def ownership(o,owner,cid,role):
    require(re.fullmatch('osir-pg18-test-[0-9a-f]{12}',owner) is not None and
            re.fullmatch('[0-9a-f]{64}',cid) is not None, 'ownership syntax')
    require(o['Id']==cid and o['Name'].lstrip('/')==owner+'-'+role and
            o['Config'].get('Labels',{}).get(LABEL)==owner, 'owned container identity mismatch')


RUNTIME_CODE = '''import json,hashlib,importlib.metadata as m,sys
from pathlib import Path
b=json.loads(%r)
root=Path('/app/server')
files={p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in b['source_sha256']}
actual=set()
for folder in ['agent_server','migrations']:
 for p in (root/folder).rglob('*'):
  if p.is_file() and p.suffix in ('.py','.mako'): actual.add(str(p.relative_to(root)))
actual.add('alembic.ini')
print(json.dumps({'files_sha256':files,'file_set':sorted(actual),'requirements_sha256':hashlib.sha256(Path('/app/requirements.txt').read_bytes()).hexdigest(),'distributions':{d.metadata['Name'].lower().replace('_','-'):d.version for d in m.distributions()},'python':sys.version}))
'''


class Experiment:
    def __init__(self, root):
        self.owner='osir-pg18-test-'+secrets.token_hex(6)
        self.work=root/self.owner;self.work.mkdir(mode=0o700)
        self.ids={};self.paths={};self.network=self.owner+'-net';self.netid=None
        self.env=environment(self.owner);self.samples=[]
        self.report={'passed':False,'owner':self.owner,'cgroup_version':2,
                     'production_cgroup_version':1,'not_production_v1_evidence':True,
                     'scope':BINDINGS['scope'],'images':{},'cleanup':{}}
        self.stream=(self.work/'kernel-samples.jsonl').open('x');os.chmod(self.work/'kernel-samples.jsonl',0o600)

    def check(self,role):
        cid=self.ids[role];o=inspect(cid);ownership(o,self.owner,cid,role)
        require(o['Image']==BINDINGS['images']['api' if role=='driver' else role]['id'], 'container image drift')
        require(set(o['NetworkSettings']['Networks'])=={self.network} and
                not o['HostConfig'].get('PortBindings'), 'only isolated internal network allowed')
        expected=[(str(self.work/'probe.py'),'/opt/probe.py',False)] if role in ('api','driver') else [
            (str(self.work/(role+'-data')), '/var/lib/postgresql' if role=='pg' else '/data',True)]
        mounts=o.get('Mounts',[])
        require([(m['Source'],m['Destination'],m['RW']) for m in mounts if m['Type']=='bind']==expected,
                'exact test bind mounts required')
        require(all(m['Type']=='bind' or (role in ('api','driver') and m['Type']=='tmpfs' and m['Destination']=='/tmp')
                    for m in mounts),'unexpected volume/mount')
        if role in ('api','driver'):
            env=dict(x.split('=',1) for x in o['Config']['Env'])
            require(all(env.get(k)==v for k,v in self.env.items()) and
                    not any(k.startswith('AGENT_SERVER_') and k not in self.env for k in env),
                    'synthetic environment whitelist')
        return o

    def create(self,role):
        q,m,s,p=LIMITS[role]
        name=self.owner+'-'+role
        args=['create','--pull=never','--name',name,'--hostname',name,'--network',self.network,
              '--network-alias',role,'--label',LABEL+'='+self.owner,'--cpu-period=100000','--cpu-quota='+str(q),
              '--memory='+str(m)+'m','--memory-swap='+str(s)+'m','--pids-limit='+str(p),
              '--cap-drop=ALL','--security-opt=no-new-privileges','--log-driver=local',
              '--log-opt=max-size=2m','--log-opt=max-file=2']
        if role in ('pg','redis'):
            data=self.work/(role+'-data');data.mkdir(mode=0o700);os.chown(data,70 if role=='pg' else 999,70 if role=='pg' else 999)
            args+=['--user='+('70:70' if role=='pg' else '999:999'),'--volume',str(data)+(':/var/lib/postgresql' if role=='pg' else ':/data')]
            if role=='pg':
                args+=['--env=POSTGRES_USER=capacity_test','--env=POSTGRES_DB=osir_pg18_test_'+self.owner.rsplit('-',1)[-1],
                       '--env=POSTGRES_HOST_AUTH_METHOD=trust',BINDINGS['images']['pg']['id'],'postgres',
                       '-c','shared_buffers=32MB','-c','max_connections=20','-c','work_mem=2MB',
                       '-c','maintenance_work_mem=32MB','-c','max_wal_size=256MB']
            else:args+=[BINDINGS['images']['redis']['id'],'redis-server','--save','','--appendonly','yes',
                        '--appendfsync','everysec','--maxmemory','48mb','--maxmemory-policy','noeviction']
        else:
            args+=['--user=10001:10001','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=32m',
                   '--volume',str(self.work/'probe.py')+':/opt/probe.py:ro','--entrypoint=python']
            for k,v in self.env.items():args+=['--env',k+'='+v]
            args+=[BINDINGS['images']['api']['id'],'-B','/opt/probe.py','--serve' if role=='api' else '--driver']
        dump(self.work/('intent-'+role+'.json'),{'name':name,'owner':self.owner})
        try:
            cid=docker(*args,timeout=30)
            require(re.fullmatch('[0-9a-f]{64}',cid) is not None,'create ID required')
        except BaseException:
            try:
                o=inspect(name);ownership(o,self.owner,o['Id'],role);self.ids[role]=o['Id']
                dump(self.work/('owned-'+role+'.json'),{'id':o['Id'],'owner':self.owner})
            except Exception:self.report['uncertain_create_role']=role
            raise
        self.ids[role]=cid;dump(self.work/('owned-'+role+'.json'),{'id':cid,'owner':self.owner})
        self.check(role);docker('start',cid)
        o=self.check(role);require(o['State']['Running'],'test exited at startup')
        self.paths[role]=kernel_paths(o['State']['Pid']);self.sample()

    def sample(self, phase='load'):
        row={'monotonic':time.monotonic(),'phase':phase,'containers':{}}
        for role,path in self.paths.items():
            o=self.check(role)
            require(o['State']['Running'] and not o['State'].get('OOMKilled'),'test exited/OOM')
            value=kernel_sample(path,role);row['containers'][role]=value
            # Persist the failure sample before evaluating OOM events.
        self.samples.append(row);self.stream.write(json.dumps(row)+'\n');self.stream.flush()
        for value in row['containers'].values():
            require(value['memory.events'].get('oom',0)==0 and value['memory.events'].get('oom_kill',0)==0,
                    'actual kernel OOM event')

    def wait_ready(self,role):
        end=time.monotonic()+90
        while time.monotonic()<end:
            self.sample('startup')
            try:
                if role=='pg':docker('exec',self.ids[role],'pg_isready','-U','capacity_test',timeout=4)
                elif role=='redis':require(docker('exec',self.ids[role],'redis-cli','ping')=='PONG','redis readiness')
                else:docker('exec',self.ids[role],'python','-B','-c',"import urllib.request;assert urllib.request.urlopen('http://127.0.0.1:8000/api/v2/health/ready',timeout=2).status==200",timeout=4)
                return
            except Refused:time.sleep(1)
        raise Refused('isolated service readiness deadline')

    def execute(self):
        self.report['images']={role:image_identity(role) for role in BINDINGS['images']}
        self.report['runner']={'kernel':platform.release(),'machine':platform.machine(),
            'docker_server':json.loads(docker('version','--format','{{json .Server}}')),
            'swap':{x.split(':')[0]:x.split(':',1)[1].strip() for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith(('SwapTotal:','SwapFree:'))}}
        # No build/installation. Original image bytes provide runtime and dependencies.
        code=RUNTIME_CODE%json.dumps(BINDINGS,sort_keys=True)
        fingerprint=json.loads(docker('run','--rm','--pull=never','--network=none','--read-only',
            '--name',self.owner+'-runtime','--label',LABEL+'='+self.owner,'--cpu-period=100000','--cpu-quota=25000',
            '--user=10001:10001','--memory=128m','--memory-swap=128m','--pids-limit=64',
            '--cap-drop=ALL','--security-opt=no-new-privileges','--entrypoint=python',
            BINDINGS['images']['api']['id'],'-B','-c',code,timeout=30))
        dump(self.work/'runtime-fingerprint.json',fingerprint)
        normalize=lambda d:{k.lower().replace('_','-'):v for k,v in d.items()}
        require(fingerprint['files_sha256']==BINDINGS['source_sha256'] and
                fingerprint['file_set']==sorted(BINDINGS['source_sha256']) and
                fingerprint['requirements_sha256']==BINDINGS['requirements_sha256'] and
                normalize(fingerprint['distributions'])==normalize(BINDINGS['distributions']),
                'original runtime/source/dependency fingerprint mismatch')
        target=self.work/'probe.py';target.write_bytes((HERE/'probe.py').read_bytes());os.chmod(target,0o644)
        self.netid=docker('network','create','--internal','--label',LABEL+'='+self.owner,self.network)
        net=json.loads(docker('network','inspect',self.netid))[0]
        require(net['Id']==self.netid and net['Internal'] and net['Labels'].get(LABEL)==self.owner,
                'isolated network identity')
        dump(self.work/'network.json',{'id':self.netid,'owner':self.owner})
        for role in ('pg','redis','api'):
            self.create(role);self.wait_ready(role)
        self.create('driver');end=time.monotonic()+240
        while time.monotonic()<end:
            self.sample()
            exists=docker('exec',self.ids['driver'],'python','-B','-c',
                          "from pathlib import Path;print(int(Path('/tmp/capacity-driver-result.json').is_file()))",timeout=5)
            if exists=='1':break
            time.sleep(1)
        else:raise Refused('fixed driver 240s deadline')
        docker('cp',self.ids['driver']+':/tmp/capacity-driver-result.json',str(self.work/'driver-result.json'))
        result=json.loads((self.work/'driver-result.json').read_text())
        require(result.get('passed') is True and result.get('schema_revision')=='v2_44' and
                'PostgreSQL 18' in result.get('postgres_version',''),'fixed original workload/PG18 failed')
        self.report['driver_summary']={k:result.get(k) for k in ('passed','sent','received','projection','history_http','passive_convergence')}
        idle=[];start=time.monotonic()
        code="import urllib.request,json;d=json.load(urllib.request.urlopen('http://api:8000/__capacity/metrics',timeout=3));print(json.dumps({'current':d['current'],'last':d['samples'][-1] if d['samples'] else {}}))"
        while time.monotonic()-start<120:
            self.sample('idle')
            m=json.loads(docker('exec',self.ids['driver'],'python','-B','-c',code,timeout=5))
            idle.append({'monotonic':time.monotonic(),'metrics':m})
            time.sleep(2)
        dump(self.work/'idle-metrics.json',idle)
        keys=('event_pending','event_pending_bytes','subscriber_queue','connector_pending','connector_pending_bytes')
        require(all(all(x['metrics']['current'].get(k)==0 for k in keys) and
                    x['metrics']['last'].get('dirty_sessions')==0 and
                    x['metrics']['last'].get('pending_items')==0 for x in idle[-5:]),'idle queue did not remain zero')
        rows=[x for x in self.samples if x['phase']=='idle']
        early=[r['containers']['api']['memory.current'] for r in rows if r['monotonic']-rows[0]['monotonic']<=30]
        late=[r['containers']['api']['memory.current'] for r in rows if rows[-1]['monotonic']-r['monotonic']<=30]
        self.report['idle_plateau']={'seconds':time.monotonic()-start,'first_30s_median_bytes':statistics.median(early),
            'last_30s_median_bytes':statistics.median(late),'median_delta_bytes':statistics.median(late)-statistics.median(early),
            'last_30s_min_bytes':min(late),'last_30s_max_bytes':max(late),'queue_zero_tail_samples':5,
            'interpretation':'raw drift for review; no new arbitrary plateau threshold; only 120s observation'}
        self.report['peaks_bytes']={role:max(x['containers'].get(role,{}).get('memory.peak',0) for x in self.samples) for role in self.ids}
        self.report['passed']=True

    def finish(self):
        for role in ('driver','api','redis','pg'):
            if role not in self.ids:continue
            try:
                o=inspect(self.ids[role]);ownership(o,self.owner,self.ids[role],role)
                if o['State']['Running']:docker('stop','--time=10',self.ids[role],timeout=20)
                o=inspect(self.ids[role]);ownership(o,self.owner,self.ids[role],role)
                require(not o['State']['Running'] and o['State'].get('Pid',0)==0,'owned test not stopped')
                self.report['cleanup'][role]={'id':self.ids[role],'state':'stopped; disposable runner retains until job end'}
            except Exception as exc:
                self.report['passed']=False;self.report['cleanup'][role]={'attention_type':type(exc).__name__}
        self.stream.close();dump(self.work/'result.json',self.report)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('fetch','run'))
    parser.add_argument('--root',type=Path,required=True)
    args=parser.parse_args()
    require(os.environ.get('GITHUB_ACTIONS')=='true' and platform.system()=='Linux' and
            platform.machine()=='x86_64' and Path('/sys/fs/cgroup/cgroup.controllers').is_file(),
            'disposable GitHub Linux/amd64 actual cgroup2 required')
    info=json.loads(docker('info','--format','{{json .}}'))
    require(info.get('OSType')=='linux' and info.get('CgroupVersion')=='2','Docker Linux cgroup2 required')
    root=args.root.resolve();root.mkdir(mode=0o700,exist_ok=True)
    if args.mode=='fetch':fetch(root);return 0
    require(os.geteuid()==0,'root host observer required to read actual container cgroup files')
    require((root/'fetch-receipt.json').is_file(),'sealed original archives must be loaded first')
    exp=Experiment(root)
    def interrupted(_sig,_frame):raise Refused('isolated job interrupted/deadline')
    for sig in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT,signal.SIGALRM):signal.signal(sig,interrupted)
    signal.alarm(900)
    try:exp.execute()
    except BaseException as exc:
        exp.report['failure_type']=type(exc).__name__
        if isinstance(exc,Refused):exp.report['failure']=str(exc)
    finally:
        signal.alarm(0)
        for sig in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT):signal.signal(sig,signal.SIG_IGN)
        exp.finish()
    print(json.dumps({'passed':exp.report['passed'],'owner':exp.owner,'work':str(exp.work),
                      'failure':exp.report.get('failure'),'cgroup_version':2}))
    return 0 if exp.report['passed'] else 1


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as exc:
        # Never render signed URLs, environment or arbitrary Docker errors.
        raise SystemExit('stress harness failed: '+type(exc).__name__) from None
