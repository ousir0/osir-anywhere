import test from 'node:test';
import assert from 'node:assert/strict';
import { systemSignature } from './osir-anywhere-system-signature.mjs';

test('unsigned Windows differs from bad/untrusted/revoked Authenticode; no boolean can bypass native result', () => {
  const report = { schemaVersion: 1, platform: 'win32', artifactSha256: 'a'.repeat(64), probes: { authenticode: { tool: 'powershell.exe', status: 0, stdout: 'NotSigned' } } };
  assert.equal(systemSignature(report), 'unsigned');
  report.probes.authenticode.stdout = 'Valid'; assert.equal(systemSignature(report), 'authenticode');
  for (const value of ['HashMismatch', 'NotTrusted', 'UnknownError', 'true', 'Revoked']) {
    report.probes.authenticode.stdout = value; assert.throws(() => systemSignature(report), /invalid or untrusted/);
  }
});
test('Mac unsigned/ad-hoc differs from damaged and Developer ID requires notarization+Gatekeeper', () => {
  const report = { schemaVersion: 1, platform: 'darwin', artifactSha256: 'a'.repeat(64), probes: {
    image: { tool: 'hdiutil', status: 0 }, identity: { tool: 'codesign', status: 1, stdout: '', stderr: 'code object is not signed at all' }, verify: { tool: 'codesign', status: 1 } } };
  assert.equal(systemSignature(report), 'unsigned');
  report.probes.identity = { tool: 'codesign', status: 0, stdout: '', stderr: 'Signature=adhoc' };
  assert.throws(() => systemSignature(report), /damaged/); report.probes.verify.status = 0; assert.equal(systemSignature(report), 'unsigned');
  report.probes.identity.stderr = 'Authority=Developer ID Application: Example';
  assert.throws(() => systemSignature(report), /not verified notarized/);
  report.probes.stapler = { tool: 'xcrun', status: 0 }; report.probes.gatekeeper = { tool: 'spctl', status: 0 };
  assert.equal(systemSignature(report), 'developer-id-notarized');
});
