import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { createServer } from "node:http";
import test from "node:test";

import { createGuard } from "@aiguard/sdk";
import { startProxy } from "../dist/proxy.js";
import { collectFiles } from "../dist/scanner.js";

const cli = resolve("packages/cli/dist/index.js");

function run(args, input = "") {
  const configHome = mkdtempSync(resolve(tmpdir(), "aiguard-test-"));
  try {
    return spawnSync(process.execPath, [cli, ...args], {
      input,
      encoding: "utf8",
      env: { ...process.env, XDG_CONFIG_HOME: configHome },
    });
  } finally {
    rmSync(configHome, { recursive: true, force: true });
  }
}

test("scan exits one and never prints the raw secret", () => {
  const raw = "AKIAIOSFODNN7EXAMPLE";
  const result = run(["scan", "--stdin", "--format", "json"], raw);

  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.stdout.includes(raw), false);
  assert.match(result.stdout, /credential\.aws_access_key_id/);
});

test("sanitize writes transformed content to stdout", () => {
  const result = run(["sanitize", "--stdin"], "Contact dev@example.com");

  assert.match(result.stdout, /\[REDACTED:PII:1\]/);
  assert.equal(result.stdout.includes("dev@example.com"), false);
});

test("doctor is honest about unsupported surfaces", () => {
  const result = run(["doctor", "--format", "json"]);
  const report = JSON.parse(result.stdout);

  assert.equal(report.checks.find((check) => check.surface === "mcp-gateway").status, "unsupported");
});

test("proxy blocks a credential before it reaches the upstream", async (context) => {
  let upstreamCalled = false;
  const upstream = createServer((_request, response) => {
    upstreamCalled = true;
    response.end("unexpected");
  });
  await new Promise((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  context.after(() => upstream.close());
  const upstreamAddress = upstream.address();
  const upstreamPort = typeof upstreamAddress === "object" ? upstreamAddress.port : 0;

  const proxy = await startProxy({
    guard: createGuard({ hmacKey: "0123456789abcdef0123456789abcdef" }),
    upstream: `http://127.0.0.1:${upstreamPort}`,
    host: "127.0.0.1",
    port: 0,
  });
  context.after(() => proxy.close());
  const proxyAddress = proxy.address();
  const proxyPort = typeof proxyAddress === "object" ? proxyAddress.port : 0;

  const raw = "AKIAIOSFODNN7EXAMPLE";
  const response = await fetch(`http://127.0.0.1:${proxyPort}/v1/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ prompt: raw }),
  });
  const body = await response.text();

  assert.equal(response.status, 400);
  assert.equal(upstreamCalled, false);
  assert.equal(body.includes(raw), false);
});

test("proxy forwards a valid redacted JSON request when policy selects redact", async (context) => {
  let upstreamBody = "";
  const upstream = createServer(async (request, response) => {
    for await (const chunk of request) upstreamBody += chunk;
    response.writeHead(200, { "content-type": "application/json" });
    response.end('{"ok":true}');
  });
  await new Promise((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  context.after(() => upstream.close());
  const upstreamAddress = upstream.address();
  const upstreamPort = typeof upstreamAddress === "object" ? upstreamAddress.port : 0;

  const proxy = await startProxy({
    guard: createGuard({
      hmacKey: "0123456789abcdef0123456789abcdef",
      config: { actions: { credential: "redact" } },
    }),
    upstream: `http://127.0.0.1:${upstreamPort}`,
    host: "127.0.0.1",
    port: 0,
  });
  context.after(() => proxy.close());
  const proxyAddress = proxy.address();
  const proxyPort = typeof proxyAddress === "object" ? proxyAddress.port : 0;

  const response = await fetch(`http://127.0.0.1:${proxyPort}/v1/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ prompt: "AKIAIOSFODNN7EXAMPLE" }),
  });

  assert.equal(response.status, 200);
  assert.doesNotThrow(() => JSON.parse(upstreamBody));
  assert.equal(upstreamBody.includes("AKIAIOSFODNN7EXAMPLE"), false);
  assert.match(upstreamBody, /REDACTED:CREDENTIAL/);
});

test("file collection respects configured exclude globs", () => {
  const root = mkdtempSync(resolve(tmpdir(), "aiguard-files-"));
  try {
    mkdirSync(resolve(root, "fixtures/public"), { recursive: true });
    mkdirSync(resolve(root, "src"), { recursive: true });
    writeFileSync(resolve(root, "fixtures/public/ignored.txt"), "ignore");
    writeFileSync(resolve(root, "src/scanned.txt"), "scan");
    const paths = collectFiles([root], ["**/fixtures/public/**"]);

    assert.equal(paths.some((path) => path.endsWith("ignored.txt")), false);
    assert.equal(paths.some((path) => path.endsWith("scanned.txt")), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
