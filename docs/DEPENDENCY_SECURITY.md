# Dependency security

The repository checks JavaScript dependencies with `npm audit` and Rust dependencies with RustSec's `cargo audit`. The audit runs in CI and remains separate from detector tests so dependency failures are visible as supply-chain failures.

## Current inherited warnings

As of 2026-07-31, RustSec reports no known vulnerability advisory in `Cargo.lock`. It does report maintenance warnings inherited from Tauri 2:

- GTK3 bindings and `proc-macro-error` are unmaintained. These packages are target-specific dependencies of Tauri's Linux webview stack, not dependencies of the Rust detection core, WASM, CLI, or Node SDK.
- Several `unic-*` crates are unmaintained through Tauri's `urlpattern` dependency.
- `glib` 0.18 has RUSTSEC-2024-0429, an iterator API soundness warning, through Tauri's Linux GTK3 stack.

The desktop application does not call the affected `glib::VariantStrIter` API directly. This narrows exposure but does not remove inherited risk. Maintainers must review these exceptions whenever Tauri is upgraded and before distributing a Linux desktop build. No advisory is silently ignored in an audit configuration; warnings remain visible in CI output.

Run the same checks locally:

```bash
cargo install cargo-audit --locked
npm run audit
cargo tree --target all -i glib@0.18.5
```
