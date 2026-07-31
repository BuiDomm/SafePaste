import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { userConfigPath } from "@aiguard/sdk";

export function keyPath(): string {
  return join(dirname(userConfigPath()), "hmac.key");
}

export function loadOrCreateHmacKey(): string {
  const path = keyPath();
  if (existsSync(path)) {
    const key = readFileSync(path, "utf8").trim();
    if (key.length < 32) {
      throw new Error(`local HMAC key is invalid: ${path}`);
    }
    return key;
  }
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const key = randomBytes(32).toString("hex");
  writeFileSync(path, `${key}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  if (process.platform !== "win32") {
    chmodSync(path, 0o600);
  }
  return key;
}
