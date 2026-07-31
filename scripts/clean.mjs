import { rmSync } from "node:fs";

const paths = [
  "target",
  "packages/core-wasm/generated",
  "packages/core-wasm/dist",
  "packages/sdk/dist",
  "packages/cli/dist",
  "packages/rules-base/dist",
  "packages/rules-vi/dist",
  "apps/desktop/dist",
  "apps/desktop/src-tauri/target",
];

for (const path of paths) {
  rmSync(new URL(`../${path}`, import.meta.url), { recursive: true, force: true });
}
