import { existsSync, rmSync, statSync } from "node:fs";
import { resolve } from "node:path";

const generated = resolve("packages/core-wasm/generated");
const wasm = resolve(generated, "aiguard_core_bg.wasm");
const loader = resolve(generated, "aiguard_core.js");

if (!existsSync(wasm) || !existsSync(loader) || statSync(wasm).size === 0) {
  throw new Error("wasm-pack did not produce the expected core artifacts");
}

// wasm-pack intentionally creates a nested .gitignore containing `*`. That is
// useful for a standalone generated package, but it also makes npm omit the
// binary from the parent @aiguard/core-wasm package even when `files` includes
// the directory. The parent repository already ignores generated artifacts.
rmSync(resolve(generated, ".gitignore"), { force: true });
