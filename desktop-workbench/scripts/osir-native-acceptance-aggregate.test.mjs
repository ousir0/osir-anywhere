import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { aggregateAcceptance, validateNativeReport } from './osir-native-acceptance-aggregate.mjs';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const expected = { sourceSha256: 'a'.repeat(64), configSha256: 'b'.repeat(64), target: 'darwin-universal', artifactSha256: 'c'.repeat(64), systemSignatureReportSha256: 'd'.repeat(64) };
const base = (machine, scope) => ({ schemaVersion: 1, ...expected, scope, evidenceMode: 'native', result: 'passed', nativeMachines: [machine], checks: Object.fromEntries(['installer','launch','connector','python','uv','upgradeDataPreserved','updateDiscovery'].map(key => [key,true])), evidence: [{ path: 'raw.log', size: 3, sha256: hash('raw') }] });
test('native aggregate rejects synthetic, partial, wrong artifact and missing runtime evidence', () => {
  for (const change of [{ evidenceMode:'synthetic' }, { result:'simulated' }, { result:'failed' }, { artifactSha256:'e'.repeat(64) }, { nativeMachines:['darwin-arm64','darwin-x64'] }, { checks:{installer:true} }]) assert.throws(() => validateNativeReport({...base('darwin-arm64','native-smoke'),...change},expected,'native-smoke'));
});
test('each hardware architecture requires independently bound smoke and upgrade evidence', async () => {
  const root=await mkdtemp(join(tmpdir(),'osir-aggregate-test-'));
  const receipt=join(root,'build.json');
  await writeFile(receipt,JSON.stringify({schemaVersion:1,plan:{sourceSha256:expected.sourceSha256,configSha256:expected.configSha256,target:expected.target},artifact:{sha256:expected.artifactSha256},systemSignatureReportSha256:expected.systemSignatureReportSha256}));
  const spec={schemaVersion:1,buildReceiptPath:receipt,smokeReports:[],upgradeReports:[]};
  for (const scope of ['native-smoke','native-upgrade-acceptance']) for (const machine of ['darwin-arm64','darwin-x64']) {
    const dir=join(root,`${scope}-${machine}`);await mkdir(dir);await writeFile(join(dir,'raw.log'),'raw');
    const path=join(dir,'report.json'), raw=JSON.stringify(base(machine,scope));await writeFile(path,raw);
    spec[scope==='native-smoke'?'smokeReports':'upgradeReports'].push({path,sha256:hash(raw)});
  }
  const report=await aggregateAcceptance(spec,join(root,'ok'));
  assert.deepEqual(report.nativeMachines,['darwin-arm64','darwin-x64']);assert.equal(report.checks.upgradeDataPreserved,true);assert.equal(report.evidence.length,9);
  await assert.rejects(aggregateAcceptance({...spec,upgradeReports:spec.upgradeReports.slice(0,1)},join(root,'missing')));
  await writeFile(join(root,'native-smoke-darwin-x64','raw.log'),'tampered');
  await assert.rejects(aggregateAcceptance(spec,join(root,'tampered')));
  assert.equal(JSON.parse(await readFile(join(root,'ok','acceptance.json'),'utf8')).result,'passed');
});
