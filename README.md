# AI Data Boundary

AI Data Boundary is a local-first safety layer that detects and redacts secrets, personal data, and sensitive developer context before it is sent to an AI model or agent.

> Status: `v0.1.0-alpha`. The working CLI name is `aiguard`; no npm package has been published or reserved yet.

## What works today

- Deterministic Rust detection engine compiled to WebAssembly.
- npm CLI and Node.js SDK for Node 22 and 24.
- Base, developer-secret, and Vietnamese PII rule packs.
- Human, JSON, and SARIF reports that never include the raw matched value.
- Policy modes: `audit`, `interactive`, and `enforce`.
- Redaction with stable placeholders within one scan.
- A configurable local forward proxy for clients that support a custom base URL.
- Metadata-only diagnostics and a `doctor` command that reports actual coverage.
- A Tauri 2 desktop preview for active text and clipboard scans.

AI Data Boundary reduces accidental disclosure. It does not guarantee compliance, detect every sensitive value, inspect applications that bypass it, or protect an already compromised device.

## Quick start from source

Prerequisites: Node.js 22/24, Rust stable, and `wasm-pack`.

```bash
npm install
npm run build
node packages/cli/dist/index.js init
printf 'Contact dev@example.com' | node packages/cli/dist/index.js scan --stdin
```

Sanitize content before sending it elsewhere:

```bash
printf 'email me at dev@example.com' | node packages/cli/dist/index.js sanitize --stdin
```

Use the SDK:

```ts
import { createGuard } from "@aiguard/sdk";

const guard = createGuard();
const decision = guard.scan({
  direction: "to_model",
  source: { kind: "prompt", trust: "trusted" },
  destination: { provider: "example-ai" },
  mediaType: "text/plain",
  segments: [{ id: "prompt", text: "Contact dev@example.com" }],
});
```

## Desktop preview

Build the desktop application on the host platform:

```bash
npm run desktop:build
```

The generated local installer is a development artifact. Public macOS downloads still require Apple Developer signing and notarization; Windows installers must be signed and produced by Windows CI. The app never watches the clipboard in the background: scanning starts only after the user presses the clipboard scan button.

## Security and privacy principles

- The core engine has no network or filesystem capability.
- Raw matches are never returned in findings or written to logs.
- Telemetry is off; the alpha contains no telemetry client.
- Rule packs are declarative data, not executable plugins.
- Unsupported input is reported as `unscanned`, never as clean.

Read [the threat model](docs/THREAT_MODEL.md), [privacy contract](docs/PRIVACY.md), [architecture](docs/ARCHITECTURE.md), and [dependency security notes](docs/DEPENDENCY_SECURITY.md) before integrating the alpha into a high-risk workflow.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Never include a real credential, private prompt, or personally identifiable record in an issue or test fixture.

## License

Code is licensed under Apache-2.0. Synthetic benchmark fixtures are dedicated to the public domain under CC0-1.0; documentation is licensed under CC BY 4.0.
