// Aggregate reviewed native reports for the SAME final installer. No test or
// partial report is promoted to native acceptance, and every architecture must
// independently cover every gate. This does not verify CI provenance online.
import { copyFile, mkdir, readFile, realpath } from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { SHA, check, cli, immutableFile, inspect, isMain, json, matches, within, bytes } from './osir-anywhere-release-common.mjs';

const SMOKE = ['installer', 'launch', 'connector', 'python', 'uv'];
const UPGRADE = ['upgradeDataPreserved', 'updateDiscovery'];
const BINDINGS = ['sourceSha256', 'configSha256', 'target', 'artifactSha256', 'systemSignatureReportSha256'];
const machinesFor = target => target === 'darwin-universal' ? ['darwin-arm64', 'darwin-x64'] :
  ['win32-x64', 'win32-arm64'].includes(target) ? [target] : [];

export function validateNativeReport(report, expected, scope) {
  check(report.schemaVersion === 1 && report.scope === scope && report.evidenceMode === 'native' && report.result === 'passed', 'Only passed native reports may be aggregated');
  check(BINDINGS.every(key => report[key] === expected[key]), 'Report is bound to different final bytes/source/signature');
  check(Array.isArray(report.nativeMachines) && report.nativeMachines.length === 1 && machinesFor(expected.target).includes(report.nativeMachines[0]), 'Each report must identify exactly one required native machine');
  const required = scope === 'native-smoke' ? SMOKE : UPGRADE;
  check(required.every(key => report.checks?.[key] === true), 'Native report has incomplete checks');
  check(Array.isArray(report.evidence) && report.evidence.length > 0, 'Raw native evidence required');
  return report.nativeMachines[0];
}

export async function aggregateAcceptance(spec, output) {
  check(spec.schemaVersion === 1 && isAbsolute(spec.buildReceiptPath ?? '') && isAbsolute(output), 'Absolute build receipt and new output required');
  const receipt = await json(spec.buildReceiptPath), p = receipt.plan, a = receipt.artifact;
  check(receipt.schemaVersion === 1 && p && a && SHA.test(p.sourceSha256) && SHA.test(p.configSha256) && SHA.test(a.sha256) && SHA.test(receipt.systemSignatureReportSha256), 'Invalid final build receipt');
  const expected = { sourceSha256: p.sourceSha256, configSha256: p.configSha256, target: p.target, artifactSha256: a.sha256, systemSignatureReportSha256: receipt.systemSignatureReportSha256 };
  const requiredMachines = machinesFor(p.target);
  check(requiredMachines.length > 0, 'Unsupported acceptance target');
  const groups = [['native-smoke', spec.smokeReports], ['native-upgrade-acceptance', spec.upgradeReports]];
  const reviewed = [];
  for (const [scope, entries] of groups) {
    check(Array.isArray(entries) && entries.length === requiredMachines.length, 'All native architectures require smoke AND upgrade reports');
    const seen = new Set();
    for (const entry of entries) {
      check(isAbsolute(entry.path ?? '') && SHA.test(entry.sha256), 'Reviewed raw report path and digest required');
      check((await inspect(entry.path)).sha256 === entry.sha256, 'Report changed after review');
      const report = await json(entry.path);
      const machine = validateNativeReport(report, expected, scope);
      check(!seen.has(machine), 'Duplicate native architecture report'); seen.add(machine);
      const evidence = [];
      for (const item of report.evidence) {
        check(typeof item.path === 'string' && !isAbsolute(item.path) && item.path.split(/[\\/]/).every(part => part && part !== '.' && part !== '..') && SHA.test(item.sha256) && Number.isSafeInteger(item.size) && item.size > 0, 'Invalid native evidence record');
        const file = join(dirname(entry.path), item.path);
        check(within(await realpath(dirname(entry.path)), await realpath(file)), 'Native evidence escaped report directory');
        await matches(file, item); evidence.push({ file, identity: item });
      }
      reviewed.push({ entry, report, machine, scope, evidence });
    }
    check(requiredMachines.every(machine => seen.has(machine)), 'Native architecture coverage missing');
  }
  for (const { entry } of reviewed) check(!within(output, entry.path) && !within(dirname(entry.path), output), 'Aggregate output must be independent of raw reports');
  await mkdir(output, { mode: 0o700 });
  const evidence = [];
  async function preserve(source, name, identity) {
    const target = join(output, name);
    await copyFile(source, target, constants.COPYFILE_EXCL);
    await matches(target, identity);
    evidence.push({ path: name, size: identity.size, sha256: identity.sha256 });
  }
  await preserve(spec.buildReceiptPath, 'build-receipt.json', await inspect(spec.buildReceiptPath));
  for (const [index, item] of reviewed.entries()) {
    const prefix = `${item.machine}-${item.scope}-${index}`;
    await preserve(item.entry.path, `${prefix}.json`, await inspect(item.entry.path));
    for (const [n, raw] of item.evidence.entries()) await preserve(raw.file, `${prefix}-${n}.bin`, raw.identity);
  }
  const report = {
    schemaVersion: 1, ...expected, result: 'passed', evidenceMode: 'native', scope: 'aggregate-native-acceptance',
    nativeMachines: requiredMachines, checks: Object.fromEntries([...SMOKE, ...UPGRADE].map(key => [key, true])), evidence,
    boundaries: ['CI provenance must be independently verified by the release coordinator.',
      'Controlled baseline installer retention and packaged native service discovery retain the exact limitations stated in their raw reports.',
      'This aggregate does not certify real-account OAuth, production models, or interactive OS confirmation.'],
    inputs: reviewed.map(item => ({ machine: item.machine, scope: item.scope, sha256: item.entry.sha256 })),
    createdAt: new Date().toISOString(),
  };
  await immutableFile(join(output, 'acceptance.json'), bytes(report));
  return report;
}

if (isMain(import.meta.url)) await cli(async () => {
  const [spec, output, ...extra] = process.argv.slice(2);
  check(isAbsolute(spec ?? '') && isAbsolute(output ?? '') && extra.length === 0, 'Usage: osir-native-acceptance-aggregate.mjs /absolute/reviewed-spec.json /absolute/new-output');
  const result = await aggregateAcceptance(await json(spec), resolve(output));
  console.log(JSON.stringify({ path: join(output, 'acceptance.json'), nativeMachines: result.nativeMachines, ...await inspect(join(output, 'acceptance.json')) }));
});
