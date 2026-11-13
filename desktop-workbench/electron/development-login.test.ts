import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import vm from "node:vm";
import ts from "typescript";

test("legacy development login opens the system browser without any scheme callback receiver", async () => {
  const opened: string[] = [];
  const source = fs.readFileSync(path.resolve(__dirname, "../../electron/development-login.ts"), "utf8");
  const javascript = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
  const exports = {} as { openDevelopmentLoginWindow: (options: { authorizeUrl: string }) => Promise<string> };
  vm.runInNewContext(javascript, { exports, URL, require: (name: string) => {
    assert.equal(name, "electron");
    return { shell: { openExternal: async (url: string) => { opened.push(url); } } };
  } });
  const url = "https://identity.example/auth/desktop/authorize?state=synthetic";
  assert.equal(await exports.openDevelopmentLoginWindow({ authorizeUrl: url }), url);
  assert.deepEqual(opened, [url]);
  await assert.rejects(exports.openDevelopmentLoginWindow({ authorizeUrl: "osir-anywhere://oauth/callback?code=x" }));
  await assert.rejects(exports.openDevelopmentLoginWindow({ authorizeUrl: "https://name:password@identity.example" }));
});
