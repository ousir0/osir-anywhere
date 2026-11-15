import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { DesktopSessionManager, DesktopSessionStore, parseDesktopSession, type DesktopSessionPayload } from "./desktop-session";
import { resolveDesktopServer } from "./desktop-server";

const server = resolveDesktopServer("https://anywhere.example");
const payload = (refreshToken = "r".repeat(43)): DesktopSessionPayload => ({
  accessToken: "synthetic-access", expiresIn: 300, tokenType: "Bearer", refreshToken, refreshExpiresIn: 604800,
  identity: { issuer: "https://osirclaw.com", subject: "123", userId: "synthetic-user" },
});
function fixture(t: test.TestContext) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "osir-desktop-session-test-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, "session.enc");
  const key = randomBytes(32);
  const safe = {
    isEncryptionAvailable: () => true,
    getSelectedStorageBackend: () => "keychain",
    encryptString(value: string) {
      const iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", key, iv);
      const data = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
      return Buffer.concat([iv, cipher.getAuthTag(), data]);
    },
    decryptString(value: Buffer) {
      const cipher = createDecipheriv("aes-256-gcm", key, value.subarray(0, 12));
      cipher.setAuthTag(value.subarray(12, 28));
      return Buffer.concat([cipher.update(value.subarray(28)), cipher.final()]).toString("utf8");
    },
  };
  return { dir, file, safe, store: new DesktopSessionStore(file, safe) };
}

test("safeStorage ciphertext persists refresh only, with private permissions and no plaintext fallback", t => {
  const f = fixture(t);
  const manager = new DesktopSessionManager(f.store, async () => assert.fail("no network on accept"));
  const publicSession = manager.accept(payload(), server);
  assert.equal("refreshToken" in publicSession, false);
  const raw = fs.readFileSync(f.file);
  assert.equal(raw.includes(payload().refreshToken), false);
  assert.equal(raw.includes(payload().accessToken), false);
  assert.equal(fs.statSync(f.file).mode & 0o777, 0o600);
  assert.equal(f.store.read()?.refreshToken, payload().refreshToken);
  assert.deepEqual(fs.readdirSync(f.dir), ["session.enc"]);
  f.safe.isEncryptionAvailable = () => false;
  assert.throws(() => manager.accept(payload(), server), /Secure system storage/);
  f.safe.isEncryptionAvailable = () => true;
  f.safe.getSelectedStorageBackend = () => "basic_text";
  assert.throws(() => f.store.read(), /Secure system storage/);
});

test("restart refresh coalesces concurrent callers and exposes only public access", async t => {
  const f = fixture(t);
  new DesktopSessionManager(f.store, fetch).accept(payload(), server);
  let calls = 0;
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const manager = new DesktopSessionManager(f.store, async (url, init) => {
    calls++;
    assert.equal(String(url), server.serverUrl + "/api/v2/auth/osir/desktop/refresh");
    assert.deepEqual(JSON.parse(String(init?.body)), { refreshToken: payload().refreshToken });
    assert.equal(init?.credentials, "omit"); assert.equal(init?.redirect, "error");
    await gate;
    return Response.json(payload("s".repeat(43)));
  });
  const first = manager.refresh(server), second = manager.refresh(server);
  release();
  const results = await Promise.all([first, second]);
  assert.equal(calls, 1);
  assert.deepEqual(results[0], results[1]);
  assert.equal(JSON.stringify(results).includes("refreshToken"), false);
  assert.equal(f.store.read()?.refreshToken, "s".repeat(43));
});

test("logout invalidates an in-flight refresh and cannot resurrect the encrypted record", async t => {
  const f = fixture(t);
  let release!: (response: Response) => void;
  const gate = new Promise<Response>(resolve => { release = resolve; });
  const calls: string[] = [];
  let entered!: () => void;
  const started = new Promise<void>(resolve => { entered = resolve; });
  const manager = new DesktopSessionManager(f.store, async url => {
    calls.push(String(url));
    if (String(url).endsWith("/logout")) return new Response(null, { status: 204 });
    entered();
    return gate;
  });
  manager.accept(payload(), server);
  const restoring = manager.refresh(server);
  const rejected = assert.rejects(restoring, /Desktop session unavailable/);
  await started;
  assert.deepEqual(await manager.logout(), { pending: false });
  release(Response.json(payload("s".repeat(43))));
  await rejected;
  assert.equal(f.store.read(), null);
  assert.equal(calls.length, 2);
});

test("offline logout persists a tombstone and retries revocation before any next login", async t => {
  const f = fixture(t);
  const manager = new DesktopSessionManager(f.store, async () => { throw new Error("synthetic-secret-upstream"); });
  manager.accept(payload(), server);
  assert.deepEqual(await manager.logout(), { pending: true });
  assert.equal(f.store.read()?.pendingLogout, true);
  assert.throws(() => manager.accept(payload(), server), /sign-out is pending/);
  const calls: string[] = [];
  const restarted = new DesktopSessionManager(f.store, async url => { calls.push(String(url)); return new Response(null, { status: 204 }); });
  assert.equal(await restarted.refresh(server), null);
  assert.equal(calls.length, 1);
  assert.ok(calls[0].endsWith("/logout"));
  assert.equal(f.store.read(), null);
});

test("wrong origin, corrupt storage, invalid responses and upstream errors never leak credentials", async t => {
  const f = fixture(t);
  let calls = 0;
  const manager = new DesktopSessionManager(f.store, async () => { calls++; throw new Error("synthetic-secret-upstream"); });
  manager.accept(payload(), server);
  await assert.rejects(manager.refresh(resolveDesktopServer("https://other.example")), /Desktop session unavailable/);
  assert.equal(calls, 0);
  await assert.rejects(manager.refresh(server), e => e instanceof Error && !e.message.includes("synthetic"));
  fs.writeFileSync(f.file, "synthetic-corrupt-secret");
  assert.throws(() => f.store.read(), e => e instanceof Error && !e.message.includes("synthetic"));
  for (const value of [null, { ...payload(), refreshToken: "invalid" }, { ...payload(), refreshExpiresIn: 604801 }, { ...payload(), expiresIn: 3600 }, { ...payload(), identity: { ...payload().identity, issuer: "https://untrusted.example" } }]) {
    assert.throws(() => parseDesktopSession(value), /Desktop session unavailable/);
  }
});

test("revoked/disabled refresh clears local active session, transient network failure keeps encrypted recovery", async t => {
  const f = fixture(t);
  for (const status of [401, 403]) {
    const manager = new DesktopSessionManager(f.store, async () => Response.json({ detail: "synthetic-secret" }, { status }));
    manager.accept(payload(), server);
    await assert.rejects(manager.refresh(server), /Desktop session unavailable/);
    assert.equal(f.store.read(), null);
  }
  const offline = new DesktopSessionManager(f.store, async () => { throw new Error(); });
  offline.accept(payload(), server);
  await assert.rejects(offline.refresh(server));
  assert.ok(f.store.read());
});

test("logout still removes local recovery and revokes when system encryption becomes unavailable", async t => {
  const f = fixture(t);
  let revoked = false;
  const manager = new DesktopSessionManager(f.store, async () => { revoked = true; return new Response(null, { status: 204 }); });
  manager.accept(payload(), server);
  f.safe.isEncryptionAvailable = () => false;
  assert.deepEqual(await manager.logout(), { pending: false });
  assert.equal(fs.existsSync(f.file), false);
  assert.equal(revoked, true);
});


test("unaccepted grants retain encrypted revocation independently of an existing login and original origin", async t => {
  const f = fixture(t);
  let online = false;
  const calls: string[] = [];
  const manager = new DesktopSessionManager(f.store, async url => {
    calls.push(String(url));
    if (!online) throw new Error("synthetic-upstream-secret");
    return new Response(null, { status: 204 });
  });
  const other = resolveDesktopServer("https://other.example");
  manager.accept(payload(), server);
  await manager.reject(payload("s".repeat(43)), other);
  assert.equal(f.store.read()?.refreshToken, payload().refreshToken);
  assert.equal(f.store.readRevocations().length, 1);
  const file = f.file + ".revocations";
  assert.equal(fs.readFileSync(file).includes("s".repeat(43)), false);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.throws(() => manager.accept(payload("t".repeat(43)), other), /pending/);
  await assert.rejects(manager.prepareLogin(), e => e instanceof Error && /pending/.test(e.message) && !e.message.includes("synthetic"));
  assert.equal(f.store.readRevocations().length, 1);
  online = true;
  const restarted = new DesktopSessionManager(f.store, async url => { calls.push(String(url)); return new Response(null, { status: 204 }); });
  await restarted.prepareLogin();
  assert.equal(f.store.readRevocations().length, 0);
  assert.equal(f.store.read()?.refreshToken, payload().refreshToken);
  assert.ok(calls.every(url => url === other.serverUrl + "/api/v2/auth/osir/desktop/logout"));
});

test("discard of an accepted but unpublished session logs it out; unavailable encryption still attempts revocation", async t => {
  const f = fixture(t);
  let calls = 0;
  const manager = new DesktopSessionManager(f.store, async () => { calls++; return new Response(null, { status: 204 }); });
  manager.accept(payload(), server);
  await manager.reject(payload(), server);
  assert.equal(f.store.read(), null);
  f.safe.isEncryptionAvailable = () => false;
  await manager.reject(payload("s".repeat(43)), server);
  assert.equal(calls, 2);
});

test("unaccepted grant revocation has an independent 10-second bound and retains retry ciphertext", async t => {
  const f = fixture(t);
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const manager = new DesktopSessionManager(f.store, async (_url, init) => {
    assert.equal(init?.signal?.aborted, false);
    return new Promise<Response>((_resolve, reject) => {
      init!.signal!.addEventListener("abort", () => reject(new Error("synthetic-upstream-secret")), { once: true });
    });
  });
  const rejected = manager.reject(payload(), server);
  assert.equal(f.store.readRevocations().length, 1, "record before attempting the network request");
  t.mock.timers.tick(10000);
  await rejected;
  assert.equal(f.store.readRevocations().length, 1);
  assert.equal(fs.readFileSync(f.file + ".revocations").includes(payload().refreshToken), false);
});

test("unavailable encryption plus offline cleanup keeps memory retry and never writes plaintext", async t => {
  const f = fixture(t);
  let online = false;
  const manager = new DesktopSessionManager(f.store, async () => {
    if (!online) throw new Error("synthetic-upstream-secret");
    return new Response(null, { status: 204 });
  });
  f.safe.isEncryptionAvailable = () => false;
  await assert.rejects(manager.reject(payload(), server), e => e instanceof Error && /securely/.test(e.message) && !e.message.includes("synthetic"));
  assert.deepEqual(fs.readdirSync(f.dir), []);
  f.safe.isEncryptionAvailable = () => true;
  assert.throws(() => manager.accept(payload(), server), /pending/);
  online = true;
  await manager.prepareLogin();
  assert.deepEqual(f.store.readRevocations(), []);
  manager.accept(payload("s".repeat(43)), server);
  assert.equal(f.store.read()?.refreshToken, "s".repeat(43));
});


test("accepted-session cleanup with encryption and network unavailable retains memory for retry", async t => {
  const f = fixture(t);
  let online = false;
  const manager = new DesktopSessionManager(f.store, async () => {
    if (!online) throw new Error("synthetic-upstream-secret");
    return new Response(null, { status: 204 });
  });
  manager.accept(payload(), server);
  f.safe.isEncryptionAvailable = () => false;
  await assert.rejects(manager.reject(payload(), server), /Desktop session unavailable/);
  assert.deepEqual(fs.readdirSync(f.dir), []);
  f.safe.isEncryptionAvailable = () => true;
  assert.throws(() => manager.accept(payload(), server), /pending/);
  online = true;
  await manager.prepareLogin();
  assert.equal(f.store.read(), null);
  assert.deepEqual(f.store.readRevocations(), []);
});


for (const status of [200, 401, 403, 503]) {
  test(`unacknowledged logout ${status} retains both tombstone and discarded grant until original-origin 204`, async t => {
    const f = fixture(t);
    const other = resolveDesktopServer("https://other.example");
    let responseStatus = status;
    const calls: { url: string; token: string }[] = [];
    const manager = new DesktopSessionManager(f.store, async (url, init) => {
      calls.push({ url: String(url), token: JSON.parse(String(init?.body)).refreshToken });
      return new Response(null, { status: responseStatus });
    });
    manager.accept(payload(), server);
    assert.deepEqual(await manager.logout(), { pending: true });
    assert.equal(f.store.read()?.pendingLogout, true);
    await manager.reject(payload("s".repeat(43)), other);
    assert.equal(f.store.readRevocations().length, 1);
    await assert.rejects(manager.prepareLogin(), /sign-out is pending/);
    assert.equal(f.store.read()?.pendingLogout, true);
    assert.equal(f.store.readRevocations().length, 1);
    // Refresh/restore must not clear a pending logout on gateway rejection either.
    await assert.rejects(manager.refresh(other), /Desktop session unavailable/);
    assert.equal(f.store.read()?.pendingLogout, true);
    responseStatus = 204;
    await manager.prepareLogin();
    assert.equal(f.store.read(), null);
    assert.deepEqual(f.store.readRevocations(), []);
    assert.ok(calls.every(call => call.url === (call.token === payload().refreshToken ? server.serverUrl : other.serverUrl) + "/api/v2/auth/osir/desktop/logout"));
    manager.accept(payload("t".repeat(43)), other);
    assert.equal(f.store.read()?.server.serverUrl, other.serverUrl);
  });
}

test("explicit Client handoff preserves unreadable ciphertext and atomically installs a new safeStorage session", async t => {
  const f = fixture(t);
  new DesktopSessionManager(f.store, fetch).accept(payload(), server);
  const old = fs.readFileSync(f.file);
  const decrypt = f.safe.decryptString;
  f.safe.decryptString = value => { if (value.equals(old)) throw new Error("synthetic-keychain-denied"); return decrypt(value); };
  const manager = new DesktopSessionManager(f.store, async () => assert.fail("no refresh/model request for unreadable session"));
  await assert.rejects(manager.prepareLogin(), /sign-out is pending/);
  await assert.rejects(manager.refresh(server), /Desktop session unavailable/);
  assert.throws(() => manager.accept(payload("s".repeat(43)), server), /Desktop session unavailable/);
  const recovery = await manager.prepareClientHandoffLogin();
  assert.equal(typeof recovery, "string");
  assert.deepEqual(fs.readdirSync(f.dir), ["session.enc"], "preflight never moves or deletes data");
  manager.acceptClientHandoff(payload("s".repeat(43)), server, recovery);
  const backups = fs.readdirSync(f.dir).filter(name => name.includes(".unreadable-"));
  assert.equal(backups.length, 1);
  assert.deepEqual(fs.readFileSync(path.join(f.dir, backups[0])), old);
  assert.equal(fs.statSync(path.join(f.dir, backups[0])).mode & 0o777, 0o600);
  assert.equal(fs.statSync(f.file).mode & 0o777, 0o600);
  assert.equal(f.store.read()?.refreshToken, "s".repeat(43));
  assert.equal(manager.identityForHandoff().identity?.userId, payload().identity.userId);
  for (const name of fs.readdirSync(f.dir)) {
    const bytes = fs.readFileSync(path.join(f.dir, name));
    assert.equal(bytes.includes(payload().refreshToken), false);
    assert.equal(bytes.includes("s".repeat(43)), false);
    assert.equal(bytes.includes(payload().accessToken), false);
  }
});

for (const mode of ["encrypt-denied", "replace-failed", "backup-failed", "record-changed"] as const) {
  test(`handoff recovery ${mode} preserves old record and never activates new identity`, async t => {
    const f = fixture(t);
    new DesktopSessionManager(f.store, fetch).accept(payload(), server);
    const old = fs.readFileSync(f.file);
    f.safe.decryptString = () => { throw new Error("synthetic-keychain-denied"); };
    const manager = new DesktopSessionManager(f.store, async () => assert.fail("no network"));
    const recovery = await manager.prepareClientHandoffLogin();
    let expected = old;
    if (mode === "encrypt-denied") f.safe.encryptString = () => { throw new Error("synthetic-encrypt-denied"); };
    if (mode === "record-changed") { expected = randomBytes(80); fs.writeFileSync(f.file, expected); }
    const rename = fs.renameSync;
    if (mode === "replace-failed" || mode === "backup-failed") {
      t.mock.method(fs, "renameSync", (from: fs.PathLike, to: fs.PathLike) => {
        if (mode === "replace-failed" ? String(to) === f.file : String(to).includes(".unreadable-")) throw new Error("synthetic-disk-failure");
        return rename(from, to);
      });
    }
    assert.throws(() => manager.acceptClientHandoff(payload("s".repeat(43)), server, recovery));
    assert.deepEqual(fs.readFileSync(f.file), expected);
    assert.deepEqual(manager.identityForHandoff(), { generation: 0, identity: null });
    assert.ok(fs.readdirSync(f.dir).every(name => !name.endsWith(".tmp")));
    const backups = fs.readdirSync(f.dir).filter(name => name.includes(".unreadable-"));
    assert.equal(backups.length, mode === "replace-failed" ? 1 : 0);
    if (backups.length) assert.deepEqual(fs.readFileSync(path.join(f.dir, backups[0])), old);
  });
}

test("unreadable revocation queue and known pending logout still block handoff recovery", async t => {
  const f = fixture(t);
  const writer = new DesktopSessionManager(f.store, async () => { throw new Error("offline"); });
  writer.accept(payload(), server);
  await writer.logout();
  const old = fs.readFileSync(f.file);
  const manager = new DesktopSessionManager(f.store, async () => new Response(null, { status: 503 }));
  await assert.rejects(manager.prepareClientHandoffLogin(), /sign-out is pending/);
  assert.deepEqual(fs.readFileSync(f.file), old);
  const decrypt = f.safe.decryptString;
  f.safe.decryptString = () => { throw new Error("synthetic-keychain-denied"); };
  await assert.rejects(writer.prepareClientHandoffLogin(), /sign-out is pending/, "same-process known logout survives keychain denial");
  assert.deepEqual(fs.readFileSync(f.file), old);
  f.safe.decryptString = decrypt;
  fs.writeFileSync(`${f.file}.revocations`, randomBytes(50));
  f.safe.decryptString = () => { throw new Error("synthetic-keychain-denied"); };
  await assert.rejects(manager.prepareClientHandoffLogin(), /sign-out is pending/);
  assert.deepEqual(fs.readFileSync(f.file), old);
  assert.ok(fs.readdirSync(f.dir).every(name => !name.includes(".unreadable-")));
});

test("decrypted invalid session data and unavailable encryption are not handoff recovery permission", async t => {
  const f = fixture(t);
  new DesktopSessionManager(f.store, fetch).accept(payload(), server);
  const manager = new DesktopSessionManager(f.store, async () => assert.fail("no network"));
  f.safe.decryptString = () => "{}";
  await assert.rejects(manager.prepareClientHandoffLogin(), /sign-out is pending/);
  f.safe.isEncryptionAvailable = () => false;
  await assert.rejects(manager.prepareClientHandoffLogin(), /sign-out is pending/);
});


test("accepted cleanup fully drained after encryption/network failure permits the next accept", async t => {
  const f = fixture(t);
  let status: number | null = null;
  let calls = 0;
  const manager = new DesktopSessionManager(f.store, async url => {
    assert.equal(String(url), server.serverUrl + "/api/v2/auth/osir/desktop/logout");
    calls++;
    if (status === null) throw new Error("synthetic-offline");
    return new Response(null, { status });
  });
  manager.accept(payload(), server);
  f.safe.isEncryptionAvailable = () => false;
  await assert.rejects(manager.reject(payload(), server), /Desktop session unavailable/);
  assert.deepEqual(fs.readdirSync(f.dir), []);
  f.safe.isEncryptionAvailable = () => true;
  status = 503;
  await assert.rejects(manager.prepareLogin(), /sign-out is pending/);
  assert.equal(f.store.read(), null);
  assert.equal(f.store.readRevocations().length, 1);
  assert.throws(() => manager.accept(payload("s".repeat(43)), server), /pending/);
  status = 204;
  await manager.prepareLogin();
  assert.equal(f.store.read(), null);
  assert.deepEqual(f.store.readRevocations(), []);
  assert.equal(calls, 3);
  manager.accept(payload("s".repeat(43)), server);
  assert.equal(f.store.read()?.refreshToken, "s".repeat(43));
  assert.equal(calls, 3, "accept needs no network after complete revocation");
});
