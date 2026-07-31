# Threat Model

## Assets

- Credentials, private keys, connection strings, and session tokens.
- Personal, financial, health, legal, and proprietary data.
- Source code, internal paths, infrastructure names, and AI conversation context.
- Agent memory, tool arguments/results, and permissions.

## In-scope threats

- A user accidentally pastes sensitive data into an AI request.
- A client automatically attaches a sensitive file or tool result.
- An over-privileged or prompt-injected agent attempts to move sensitive data to an external destination.
- A malformed or malicious rule pack attempts denial of service or misleading detection.
- Logs, diagnostics, or audit exporters accidentally retain raw content.

## Current controls

- High-confidence deterministic detection before egress.
- Local redaction and explainable policy actions.
- Non-backtracking Rust regular-expression engine and declarative rule schema.
- Metadata-only reporting and keyed fingerprints.
- Explicit coverage states and fail-closed enforcement for unscanned content.

## Out of scope

- A device, host process, browser, or agent already controlled by an attacker.
- Traffic that is not passed through the CLI, SDK, configured proxy, or future gateway.
- Preventing a user from deliberately bypassing a local tool.
- Perfect semantic classification or legal/compliance certification.
- TLS interception, malware detection, moderation, OCR, audio, and video.

## Future agent model

The agent gateway will model provenance as data-flow edges and attach `sensitive`, `untrusted`, and `external` labels. The initial high-risk transitions are sensitive-to-external transfer, untrusted-to-privileged execution, and model-generated destructive actions. Tool annotations are treated only as untrusted hints.
