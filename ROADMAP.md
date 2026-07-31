# Roadmap

Status legend: **implemented** means present in the alpha repository; **planned** still requires implementation and its acceptance gate.

## v0.1 — Developer MVP (implemented alpha)

- Rust/WASM engine, Node SDK, npm CLI.
- Base and Vietnamese rule packs.
- Policy, redaction, config, SARIF, rule tests, and benchmark.
- Experimental OpenAI-compatible local forward proxy and coverage doctor.
- Tauri active-scan preview, delivered early to validate shared-core behavior.

## v0.2 — Runtime protection

- Harden OpenAI-compatible, Anthropic, and Gemini adapters.
- Streaming protocol test matrix and response inspection.
- Pre-commit/CI integrations, scoped baselines, and coverage doctor.

## v0.3 — Agent and MCP guard

- Version-negotiated MCP gateway.
- Tool argument/result inspection, provenance labels, and session taint graph.
- Intent gate and human approval for sensitive or destructive action chains.

## v0.5–v0.6 — Desktop and browser

- Expand the Tauri preview with drag/drop file scanning, proxy controls, and metadata history.
- Signed/notarized installers.
- Permission-minimal Manifest V3 browser extension.

## v1.0

- Stable SDK/policy/plugin contracts, signed rule registry, additional package managers, and Python bindings.
