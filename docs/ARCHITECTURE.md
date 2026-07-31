# Architecture

AI Data Boundary separates a pure decision engine from hosts that have I/O capability.

```text
CLI / SDK / proxy / desktop
          |
       Envelope
          |
normalize -> detect -> validate -> policy -> transform
          |
       Decision
```

## Trust boundaries

The Rust core accepts serialized envelopes, configuration, declarative rules, and an HMAC key. It cannot read files or access the network. Hosts are responsible for collecting content, enforcing the returned action, and avoiding raw-content logging.

The first npm implementation loads the core as WebAssembly. Tauri links the same Rust crate directly. A future native Node backend must implement the same serialized contract and pass the same golden tests.

## Detection pipeline

1. Preserve source offsets while producing a canonical view for obfuscation-resistant matching.
2. Run declarative text and path rules.
3. Validate candidates with checksum, entropy, format, and local context.
4. Deduplicate overlapping findings.
5. Remove active suppressions without exposing their matched value.
6. Resolve policy from confidence, severity, category, mode, and explicit overrides.
7. Optionally replace spans with stable, category-labelled placeholders.

Findings contain masked previews and keyed fingerprints, never raw matches. A decision includes engine, policy, and rule-pack versions so an audit can be reproduced without storing the prompt.

Finding span offsets are UTF-8 byte offsets into the original segment. Hosts that expose editor positions must translate them to the editor's character-index convention without logging the source text.

## Package boundaries

- `aiguard-core`: pure Rust engine and WASM exports.
- `@aiguard/core-wasm`: Node loader for the generated WASM artifact.
- `@aiguard/rules-base` and `@aiguard/rules-vi`: declarative rule packs.
- `@aiguard/sdk`: typed API, config merging, text/file coverage, and fetch adapter.
- `@aiguard/cli`: command-line host, reporters, doctor, and experimental proxy.
- `@aiguard/desktop`: Tauri preview linked directly to the core.

## Compatibility policy

All public objects carry a schema or API version. Before v1.0, breaking changes may occur between minor versions and must be recorded in the changelog. Rule packs declare their minimum engine version and are validated before scanning.
