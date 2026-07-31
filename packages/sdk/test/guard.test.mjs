import assert from "node:assert/strict";
import test from "node:test";

import {
  createGuard,
  GuardBlockedError,
  guardedFetch,
  unscannedDecision,
  validateConfig,
} from "@aiguard/sdk";

test("detects a high-confidence credential without returning the raw match", () => {
  const raw = "AKIAIOSFODNN7EXAMPLE";
  const guard = createGuard({ hmacKey: "0123456789abcdef0123456789abcdef" });
  const decision = guard.scanText(`AWS_ACCESS_KEY_ID=${raw}`);

  assert.equal(decision.action, "block");
  assert.ok(decision.findings.some((finding) => finding.ruleId === "credential.aws_access_key_id"));
  assert.equal(JSON.stringify(decision).includes(raw), false);
});

test("uses a stable placeholder for a repeated value in one scan", () => {
  const guard = createGuard({ hmacKey: "0123456789abcdef0123456789abcdef" });
  const decision = guard.scanText("dev@example.com and dev@example.com", { redact: true });
  const transformed = decision.transformed.segments[0].text;

  assert.equal(
    transformed,
    "[REDACTED:PII:1] and [REDACTED:PII:1]",
  );
});

test("detects Vietnamese identifiers only with the required context", () => {
  const guard = createGuard({ hmacKey: "0123456789abcdef0123456789abcdef" });
  const contextual = guard.scanText("CCCD: 079000000000");
  const order = guard.scanText("Mã đơn hàng 079000000000");

  assert.ok(contextual.findings.some((finding) => finding.ruleId === "pii.vn_cccd"));
  assert.equal(order.findings.some((finding) => finding.ruleId === "pii.vn_cccd"), false);
});

test("guarded fetch blocks before the implementation receives a credential", async () => {
  const guard = createGuard({ hmacKey: "0123456789abcdef0123456789abcdef" });
  let called = false;
  const implementation = async () => {
    called = true;
    return new Response("ok");
  };
  const safeFetch = guardedFetch(guard, implementation);

  await assert.rejects(
    () =>
      safeFetch("https://ai.example.invalid/v1/chat", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ prompt: "AKIAIOSFODNN7EXAMPLE" }),
      }),
    GuardBlockedError,
  );
  assert.equal(called, false);
});

test("enforce mode fails closed for unscanned content", () => {
  assert.equal(unscannedDecision("enforce", "binary").action, "block");
  assert.equal(unscannedDecision("audit", "binary").action, "warn");
});

test("redaction preserves JSON validity for numeric identifiers", () => {
  const guard = createGuard({
    hmacKey: "0123456789abcdef0123456789abcdef",
    config: { actions: { financial: "redact" } },
  });
  const decision = guard.scanText('{"card":4242424242424242}', {
    mediaType: "application/json",
    redact: true,
  });
  const transformed = decision.transformed.segments[0].text;

  assert.doesNotThrow(() => JSON.parse(transformed));
  assert.equal(JSON.parse(transformed).card, "[REDACTED:FINANCIAL:1]");
});

test("a keyed scoped suppression removes a finding without storing its raw value", () => {
  const key = "0123456789abcdef0123456789abcdef";
  const first = createGuard({ hmacKey: key }).scanText("dev@example.com", {
    sourceName: "fixtures/public/contact.txt",
  });
  const fingerprint = first.findings[0].fingerprint;
  const guard = createGuard({
    hmacKey: key,
    config: {
      suppressions: [
        {
          ruleId: "pii.email",
          sourcePattern: "fixtures/public/**",
          fingerprint,
          expiresAt: "2099-01-01T00:00:00.000Z",
          reason: "Synthetic public fixture",
        },
      ],
    },
  });
  const decision = guard.scanText("dev@example.com", {
    sourceName: "fixtures/public/contact.txt",
  });

  assert.equal(decision.findings.length, 0);
  assert.equal(JSON.stringify(guard.config).includes("dev@example.com"), false);
});

test("config validation rejects unknown keys", () => {
  assert.throws(() => validateConfig({ version: 1, telemetry: true }), /unknown key: telemetry/);
});
