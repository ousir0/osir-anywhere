"""No Docker, network, secrets or product imports. Safety contract tests."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('stress_run',Path(__file__).with_name('run.py'))
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)


def transfer():
    return {'host':'test-bucket.oss-cn-hangzhou.aliyuncs.com',
            'prefix':'release-tests/osir-server/review-20261114-a1b2c3/',
            'archives':{k:{'sha256':'a'*64,'bytes':1234,'cipher_sha256':'b'*64,'cipher_bytes':1264} for k in ('api','pg','redis')}}


class Safety(unittest.TestCase):
    def test_transfer_metadata_all_images_sealed(self):
        r.transfer_spec(json.dumps(transfer()))
        for change in ('host','prefix','missing','nullhash','size'):
            v=transfer()
            if change=='host':v['host']='localhost'
            if change=='prefix':v['prefix']='production/'
            if change=='missing':del v['archives']['pg']
            if change=='nullhash':v['archives']['api']['sha256']=None
            if change=='size':v['archives']['api']['bytes']=3*1024**3
            with self.subTest(change=change),self.assertRaises((r.Refused,TypeError)):
                r.transfer_spec(json.dumps(v))

    def test_signed_url_scope_and_no_redirect_target(self):
        s=transfer();url='https://'+s['host']+'/'+s['prefix']+'api.docker.tar.enc?signature=synthetic'
        self.assertEqual(r.get_url(url,s,'api'),url)
        for u in (url.replace('https:','http:'),url.replace(s['host'],'evil.example'),
                  url.replace('api.docker.tar.enc','pg.docker.tar.enc'),url.replace(s['prefix'],'production/'),
                  url+'#fragment',url.replace('https://','https://user:pass@')):
            with self.subTest(url_kind=u.split('?')[0]),self.assertRaises(r.Refused):r.get_url(u,s,'api')

    def test_exact_original_image_and_layers(self):
        binding=r.BINDINGS['images']['api']
        image={'Id':binding['id'],'Architecture':'amd64','Os':'linux',
               'RootFS':{'Layers':binding['layers']},
               'Config':{'Env':[k+'=synthetic' for k in binding['env_keys']]}}
        with mock.patch.object(r,'docker',return_value=json.dumps([image])):r.image_identity('api')
        for change in ('id','layer','arch','env'):
            x=copy.deepcopy(image)
            if change=='id':x['Id']='sha256:'+'f'*64
            if change=='layer':x['RootFS']['Layers']=[]
            if change=='arch':x['Architecture']='arm64'
            if change=='env':x['Config']['Env'].append('AGENT_SERVER_DB_URL=synthetic-forbidden')
            with mock.patch.object(r,'docker',return_value=json.dumps([x])),self.subTest(change=change),self.assertRaises(r.Refused):
                r.image_identity('api')

    def test_actual_v2_memory_swap_cpu_pids(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            values={'memory.max':'402653184','memory.swap.max':'134217728','cpu.max':'75000 100000','pids.max':'128',
                    'memory.current':'1048576','memory.peak':'2097152','memory.events':'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n',
                    'memory.swap.current':'0','cpu.stat':'usage_usec 123\nnr_throttled 0\n','pids.current':'2'}
            for k,v in values.items():(p/k).write_text(v)
            self.assertEqual(r.kernel_sample(p,'api')['memory.peak'],2097152)
            for name,bad in [('memory.max','536870912'),('memory.swap.max','536870912'),('cpu.max','max 100000'),('pids.max','256')]:
                (p/name).write_text(bad)
                with self.subTest(name=name),self.assertRaises(r.Refused):r.kernel_sample(p,'api')
                (p/name).write_text(values[name])

    def test_cleanup_refuses_foreign_container(self):
        owner='osir-pg18-test-123456abcdef';cid='a'*64
        good={'Id':cid,'Name':'/'+owner+'-api','Config':{'Labels':{r.LABEL:owner}}}
        r.ownership(good,owner,cid,'api')
        for change in ('label','id','name'):
            o=copy.deepcopy(good)
            if change=='label':o['Config']['Labels']={}
            if change=='id':o['Id']='b'*64
            if change=='name':o['Name']='production-api'
            with self.subTest(change=change),self.assertRaises(r.Refused):r.ownership(o,owner,cid,'api')

    def test_no_target_or_workload_override_in_cli(self):
        with mock.patch('sys.argv',['run.py','run','--root','/tmp/test','--target','production']),self.assertRaises(SystemExit):
            r.main()

    def test_exact_source_binding_count_and_api384(self):
        self.assertEqual(len(r.BINDINGS['source_sha256']),194)
        self.assertEqual(r.LIMITS['api'],(75000,384,512,128))
        self.assertEqual(r.BINDINGS['images']['api']['id'],'sha256:d60cfb3b6028fb232f26084b1001c767b904adc86a9add93c900294aea3f817a')
        self.assertTrue(all('..' not in Path(k).parts and not Path(k).is_absolute() for k in r.BINDINGS['source_sha256']))


class EncryptionSafety(unittest.TestCase):
    def fixture(self,d):
        p=Path(d);cipher=p/'api.docker.tar.enc';plain=p/'api.docker.tar'
        cipher.write_bytes(b'Salted__'+b'01234567'+b'0'*16)
        expected={'cipher_bytes':32,'cipher_sha256':r.sha(cipher),
                  'bytes':7,'sha256':r.hashlib.sha256(b'fixture').hexdigest()}
        return cipher,plain,expected

    def test_cipher_sha_before_decrypt(self):
        with tempfile.TemporaryDirectory() as d:
            c,p,e=self.fixture(d);e['cipher_sha256']='f'*64
            with mock.patch.object(r.subprocess,'run') as run,self.assertRaises(r.Refused):r.decrypt_archive(c,p,e)
            run.assert_not_called();self.assertFalse(p.exists())

    def test_secret_only_child_environment_plain_sha_before_load(self):
        with tempfile.TemporaryDirectory() as d:
            c,p,e=self.fixture(d);password='a'*64;seen=[]
            def fake(args,**kw):
                if '-help' in args:return r.subprocess.CompletedProcess(args,0,b'',b'-saltlen')
                seen.append(args)
                self.assertNotIn(password,' '.join(args))
                self.assertEqual(kw['env']['OSIR_ARCHIVE_PASSWORD'],password)
                self.assertNotIn('OSIR_API_GET_URL',kw['env'])
                self.assertEqual(args[-2:],['-saltlen','8'])
                kw['stdout'].write(b'fixture')
                return r.subprocess.CompletedProcess(args,0)
            with mock.patch.dict(r.os.environ,{'OSIR_ARCHIVE_PASSWORD':password,'OSIR_API_GET_URL':'synthetic-secret-url'},clear=True),mock.patch.object(r.subprocess,'run',side_effect=fake):
                r.decrypt_archive(c,p,e)
            self.assertEqual(p.read_bytes(),b'fixture');self.assertEqual(len(seen),1)
            self.assertNotIn('OSIR_ARCHIVE_PASSWORD',r.CHILD_ENV)

    def test_plain_sha_failure_removes_own_plaintext(self):
        with tempfile.TemporaryDirectory() as d:
            c,p,e=self.fixture(d);e['sha256']='f'*64
            def fake(args,**kw):
                if '-help' in args:return r.subprocess.CompletedProcess(args,0,b'',b'')
                kw['stdout'].write(b'fixture');return r.subprocess.CompletedProcess(args,0)
            with mock.patch.dict(r.os.environ,{'OSIR_ARCHIVE_PASSWORD':'a'*64}),mock.patch.object(r.subprocess,'run',side_effect=fake),self.assertRaises(r.Refused):r.decrypt_archive(c,p,e)
            self.assertFalse(p.exists())

    def test_decrypt_nonzero_removes_partial(self):
        with tempfile.TemporaryDirectory() as d:
            c,p,e=self.fixture(d)
            def fake(args,**kw):
                if '-help' in args:return r.subprocess.CompletedProcess(args,0,b'',b'')
                return r.subprocess.CompletedProcess(args,1)
            with mock.patch.dict(r.os.environ,{'OSIR_ARCHIVE_PASSWORD':'a'*64}),mock.patch.object(r.subprocess,'run',side_effect=fake),self.assertRaises(r.Refused):r.decrypt_archive(c,p,e)
            self.assertFalse(p.exists())

    def test_password_missing_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            c,p,e=self.fixture(d)
            with mock.patch.dict(r.os.environ,{},clear=True),self.assertRaises(r.Refused):r.decrypt_archive(c,p,e)
            self.assertFalse(p.exists())

    def test_existing_plaintext_is_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            c,p,e=self.fixture(d);p.write_bytes(b'pre-existing')
            help_result=r.subprocess.CompletedProcess([],0,b'',b'')
            with mock.patch.dict(r.os.environ,{'OSIR_ARCHIVE_PASSWORD':'a'*64}),mock.patch.object(r.subprocess,'run',return_value=help_result),self.assertRaises(r.Refused):r.decrypt_archive(c,p,e)
            self.assertEqual(p.read_bytes(),b'pre-existing')

    def test_plain_url_and_unsealed_cipher_refuse(self):
        s=transfer();url='https://'+s['host']+'/'+s['prefix']+'api.docker.tar'
        with self.assertRaises(r.Refused):r.get_url(url,s,'api')
        del s['archives']['api']['cipher_sha256']
        with self.assertRaises(r.Refused):r.transfer_spec(json.dumps(s))


class DriverTmpfsEvidence(unittest.TestCase):
    def test_live_owned_driver_exec_reads_tmpfs_and_retains_result(self):
        with tempfile.TemporaryDirectory() as d:
            e=r.Experiment.__new__(r.Experiment)
            e.ids={'driver':'a'*64};e.work=Path(d);e.report={}
            payload={'passed':False,'synthetic_error':'preserved'}
            with mock.patch.object(e,'check') as check,mock.patch.object(r,'docker',return_value=json.dumps(payload)) as docker:
                self.assertEqual(e.collect_driver_result(),payload)
            check.assert_called_once_with('driver')
            self.assertEqual(docker.call_count,1)
            self.assertEqual(docker.call_args.args[:5],('exec','a'*64,'python','-B','-c'))
            self.assertIn('/tmp/capacity-driver-result.json',docker.call_args.args[5])
            self.assertEqual(docker.call_args.kwargs['timeout'],20)
            self.assertEqual(json.loads((e.work/'driver-result.json').read_text()),payload)
            self.assertEqual(e.report['phase'],'driver_result_validate')

    def test_foreign_driver_refused_before_result_read(self):
        e=r.Experiment.__new__(r.Experiment);e.report={}
        with mock.patch.object(e,'check',side_effect=r.Refused('foreign')),mock.patch.object(r,'docker') as docker,self.assertRaises(r.Refused):
            e.collect_driver_result()
        docker.assert_not_called()

    def test_invalid_result_never_becomes_success_evidence(self):
        for payload in ('not json','[]'):
            with tempfile.TemporaryDirectory() as d:
                e=r.Experiment.__new__(r.Experiment);e.ids={'driver':'a'*64};e.work=Path(d);e.report={}
                with mock.patch.object(e,'check'),mock.patch.object(r,'docker',return_value=payload),self.assertRaises((ValueError,r.Refused)):
                    e.collect_driver_result()
                self.assertFalse((e.work/'driver-result.json').exists())


class CommandDiagnostics(unittest.TestCase):
    def test_nonzero_is_role_operation_returncode_without_secrets(self):
        secret=b'postgresql://user:password@host/private?token=sentinel'
        error=b'Error: container is not running '+secret
        with mock.patch.object(r.subprocess,'run',return_value=r.subprocess.CompletedProcess([],1,b'',error)):
            with self.assertRaises(r.CommandFailure) as raised:
                r.docker('exec','synthetic-id','python','secret-argv',role='driver',operation='driver-result-poll',timeout=5)
        e=raised.exception.evidence
        self.assertEqual(e['role'],'driver');self.assertEqual(e['operation'],'driver-result-poll')
        self.assertEqual(e['returncode'],1);self.assertFalse(e['timed_out'])
        self.assertEqual(e['stderr_tags'],['container_not_running'])
        self.assertNotIn('sentinel',json.dumps(e));self.assertNotIn('secret-argv',json.dumps(e))

    def test_timeout_is_distinct_and_stderr_prefix_bounded(self):
        error=b'permission denied '+b'x'*5000+b'postgresql://private-token'
        with mock.patch.object(r.subprocess,'run',side_effect=r.subprocess.TimeoutExpired(['secret-argv'],5,stderr=error)):
            with self.assertRaises(r.CommandFailure) as raised:
                r.docker('exec','id',role='driver',operation='idle-metrics',timeout=5)
        e=raised.exception.evidence
        self.assertIsNone(e['returncode']);self.assertTrue(e['timed_out'])
        self.assertEqual(e['timeout_seconds'],5);self.assertEqual(e['stderr_prefix_bytes_scanned'],4096)
        self.assertEqual(e['stderr_tags'],['permission_denied'])
        self.assertNotIn('private-token',json.dumps(e));self.assertNotIn('secret-argv',str(raised.exception))

    def test_arbitrary_diagnostic_strings_refused(self):
        for kw in ({'role':'secret-dsn'},{'operation':'secret-url'}):
            with mock.patch.object(r.subprocess,'run') as run,self.assertRaises(r.Refused):r.docker('exec',**kw)
            run.assert_not_called()


if __name__=='__main__':unittest.main()
