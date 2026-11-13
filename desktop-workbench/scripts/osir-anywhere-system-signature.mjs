import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { mkdtemp, readdir, rmdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { check } from './osir-anywhere-release-common.mjs';

function probe(tool, args, env) {
  const r = spawnSync(tool, args, { env, encoding: 'utf8', maxBuffer: 256 * 1024, timeout: 120_000, windowsHide: true });
  check(!r.error && r.status !== null, 'Native signature inspection could not complete');
  return { tool, args, status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}
export function systemSignature(report) {
  check(report.schemaVersion === 1 && report.artifactSha256 && report.probes, 'Native signature report missing');
  if (report.platform === 'win32') {
    const p = report.probes.authenticode;
    check(p?.tool === 'powershell.exe' && p.status === 0, 'Authenticode probe did not complete');
    const status = p.stdout.trim();
    check(['Valid', 'NotSigned'].includes(status), 'Installer has an invalid or untrusted system signature');
    return status === 'Valid' ? 'authenticode' : 'unsigned';
  }
  check(report.platform === 'darwin', 'Unsupported system signature platform');
  const { identity, verify, stapler, gatekeeper, image } = report.probes;
  check(image?.tool === 'hdiutil' && image.status === 0 && identity?.tool === 'codesign', 'Final DMG/app signature probes missing');
  const text = `${identity.stdout}\n${identity.stderr}`;
  const adhoc = identity.status === 0 && /Signature=adhoc/.test(text);
  const absent = identity.status !== 0 && /code object is not signed at all/.test(text);
  if (adhoc || absent) {
    // A broken ad-hoc signature is not treated as a normal unsigned app.
    if (adhoc) check(verify?.tool === 'codesign' && verify.status === 0, 'Ad-hoc signature is damaged');
    return 'unsigned';
  }
  check(identity.status === 0 && /Authority=Developer ID Application:/.test(text) && verify?.status === 0 && verify.tool === 'codesign', 'App has an invalid or unsupported system signature');
  check(stapler?.tool === 'xcrun' && stapler.status === 0 && gatekeeper?.tool === 'spctl' && gatekeeper.status === 0,
    'Developer ID app is not verified notarized; cannot label as unsigned or notarized');
  return 'developer-id-notarized';
}
export async function inspectSystemSignature(platform, installer, artifactSha256, env) {
  let probes;
  if (platform === 'win32') {
    const args = ['-NoProfile', '-NonInteractive', '-Command', '(Get-AuthenticodeSignature -LiteralPath $env:OSIR_FINAL_INSTALLER).Status.ToString()'];
    probes = { authenticode: probe('powershell.exe', args, { ...env, OSIR_FINAL_INSTALLER: installer }) };
  } else {
    probes = { image: probe('hdiutil', ['verify', installer], env) };
    check(probes.image.status === 0, 'Final installer image verification failed');
    const mount = await mkdtemp(join(tmpdir(), 'osir-signature-mount-'));
    let attached = false;
    try {
      probes.mount = probe('hdiutil', ['attach', '-readonly', '-nobrowse', '-noautoopen', '-mountpoint', mount, installer], env);
      check(probes.mount.status === 0, 'Final installer could not be mounted read-only'); attached = true;
      const apps = (await readdir(mount)).filter(name => name.endsWith('.app'));
      check(apps.length === 1, 'Expected one app inside final installer');
      const app = join(mount, apps[0]);
      probes.identity = probe('codesign', ['-dv', '--verbose=4', app], env);
      probes.verify = probe('codesign', ['--verify', '--deep', '--strict', app], env);
      const identity = `${probes.identity.stdout}\n${probes.identity.stderr}`;
      if (/Authority=Developer ID Application:/.test(identity)) {
        probes.stapler = probe('xcrun', ['stapler', 'validate', installer], env);
        probes.gatekeeper = probe('spctl', ['--assess', '--type', 'execute', '--verbose=4', app], env);
      }
    } finally {
      if (attached) {
        const detach = probe('hdiutil', ['detach', mount], env);
        check(detach.status === 0, 'Temporary signature mount requires manual detach');
      }
      await rmdir(mount).catch(error => { if (error.code !== 'ENOENT') throw error; });
    }
  }
  const report = { schemaVersion: 1, platform, artifactSha256, probes };
  return { ...report, systemSignature: systemSignature(report) };
}
