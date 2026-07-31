# Privacy Contract

AI Data Boundary is local-first. The core engine has no network or filesystem APIs, and the project ships no telemetry client in v0.1.

## Data handling

- Prompt and file contents stay in the calling process unless the user explicitly runs the proxy or a guarded fetch that forwards an allowed/transformed request.
- Findings contain only category, severity, confidence, source location, masked preview, explanation, remediation, and keyed fingerprint.
- The CLI writes reports only to the requested output stream. It does not retain prompt content.
- Persistent suppressions use a locally keyed HMAC. A plain hash of a secret is never stored.
- Redaction mappings live for one scan/session and are not sent upstream.

## Diagnostics

Logs may contain command, source type, destination host, action, finding count, rule IDs, timing, and coverage. They must not contain raw segments, transformed segments, HTTP bodies, headers, or full matched values.

Any future crash reporter, telemetry exporter, or team control plane is opt-in and must undergo a privacy review before release.

## Limitations

Automated detection has false negatives and false positives. A clean result means no configured detector found a candidate in scanned content; it is not proof that the content is safe. Partial and unsupported inputs are reported explicitly.
