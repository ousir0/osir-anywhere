import assert from "node:assert/strict";
import { test } from "node:test";
import { desktopOnboardingFromArgv, desktopOnboardingFromUrl, desktopOnboardingRoute } from "./desktop-onboarding";

const FLOW_ID = "abcdefghijklmnopqrstuvwx";

test("plugin entries carry only a validated flow id", () => {
  const entry = desktopOnboardingFromUrl(`osir-anywhere://onboarding?source=dsh-plugin&flowId=${FLOW_ID}`);
  assert.deepEqual(entry, {
    source: "dsh-plugin",
    flowId: FLOW_ID,
    route: `/#/onboarding?source=dsh-plugin&flowId=${FLOW_ID}`,
    key: `dsh-plugin:${FLOW_ID}`,
  });
  assert.equal(desktopOnboardingFromUrl("osir-anywhere://onboarding?source=dsh-plugin")?.route, "/#/onboarding?source=dsh-plugin");
  assert.equal(desktopOnboardingFromUrl(`osir-anywhere://onboarding?flowId=${FLOW_ID}`)?.source, "dsh-plugin");
});

test("malformed or foreign URLs never start a flow", () => {
  for (const value of [
    "osir-anywhere://oauth/callback?code=x&state=y",
    "osir-anywhere://onboarding?flowId=short",
    "osir-anywhere://onboarding?flowId=../../etc/passwd",
    "osir-anywhere://onboarding?flowId=" + "a".repeat(101),
    "https://example.test/onboarding",
    "osir-anywhere-workbench://web/#/onboarding",
    "not a url",
  ]) {
    assert.equal(desktopOnboardingFromUrl(value), null, value);
  }
  assert.equal(desktopOnboardingFromArgv(["electron", ".", "--hidden"]), null);
  assert.equal(desktopOnboardingFromArgv(["electron", ".", `osir-anywhere://onboarding?flowId=${FLOW_ID}`])?.flowId, FLOW_ID);
});

test("OAuth custom-scheme callbacks cannot enter onboarding via argv", () => {
  assert.equal(desktopOnboardingFromArgv(["electron", ".", "osir-anywhere://oauth/callback?code=x&state=y"]), null);
});

test("a user launch builds the same route without a flow id", () => {
  assert.equal(desktopOnboardingRoute({ source: "desktop" }), "/#/onboarding?source=desktop");
  assert.equal(desktopOnboardingRoute({ source: "desktop", flowId: null }), "/#/onboarding?source=desktop");
});
