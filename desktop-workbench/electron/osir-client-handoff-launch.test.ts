import assert from "node:assert/strict";
import test from "node:test";
import { clientHandoffFlowFromArgv, clientHandoffFlowFromSecondInstance, clientHandoffLockData } from "./osir-client-handoff-launch";

const flow = "B".repeat(43);
const original = ["/Applications/OSIR Anywhere.app/Contents/MacOS/OSIR Anywhere", "--osir-client-handoff-flow", flow];
const forwarded = [original[0], original[1], "--allow-file-access-from-files", "--enable-avfoundation", flow];

test("running app receives the launch flow despite native Chromium argv insertion", () => {
  assert.equal(clientHandoffFlowFromArgv(forwarded), null);
  const data = clientHandoffLockData(clientHandoffFlowFromArgv(original));
  assert.equal(clientHandoffFlowFromSecondInstance(forwarded, data), flow);
  assert.deepEqual(data, { osirClientHandoff: { version: 1, flowId: flow } });
});

test("cold launch and equals-form launches preserve explicit intent", () => {
  assert.equal(clientHandoffFlowFromArgv(original), flow);
  const equals = [original[0], `--osir-client-handoff-flow=${flow}`];
  assert.equal(clientHandoffFlowFromArgv(equals), flow);
  assert.equal(clientHandoffFlowFromSecondInstance(equals, {}), flow);
  assert.equal(clientHandoffFlowFromSecondInstance(original, undefined), flow);
  assert.deepEqual(clientHandoffLockData(null), {});
  assert.equal(clientHandoffFlowFromArgv([original[0], "--hidden"]), null);
});

test("malformed or ambiguous metadata cannot start or replace a handoff", () => {
  for (const argv of [[...original, `--osir-client-handoff-flow=${flow}`],
    [original[0], "--osir-client-handoff-flow"], [original[0], "--osir-client-handoff-flow=../bad"]]) {
    assert.equal(clientHandoffFlowFromArgv(argv), null);
  }
  for (const value of [null, [], { version: 2, flowId: flow }, { version: 1, flowId: "bad" },
    { version: 1, flowId: flow, token: "must-not-be-accepted" }]) {
    assert.equal(clientHandoffFlowFromSecondInstance(original, { osirClientHandoff: value }), null);
  }
});
