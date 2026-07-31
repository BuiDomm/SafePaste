# RFC 0001: Pure core and versioned envelope contract

Status: Accepted

## Decision

All detection and policy decisions live in a pure Rust crate. I/O hosts serialize a versioned `Envelope` and receive a versioned `Decision`. Node initially uses WebAssembly; Tauri links Rust directly.

## Consequences

- The same rules and policy produce the same output across supported hosts.
- The core can be tested with network access disabled.
- File discovery, interactive approval, forwarding, persistence, and logging remain host responsibilities.
- A native Node or Python binding can be introduced without changing public behavior.
