# Contributing

Contributions are welcome through issues, discussions, RFCs, and pull requests.

## Safety rules

- Use synthetic fixtures only. Never submit a real key, prompt, customer record, or internal hostname.
- Every detector change needs positive, hard-negative, and regression tests.
- A security-sensitive rule should explain its confidence level and false-positive tradeoff.
- Rule packs are declarative JSON. Executable third-party detector code is not accepted in v0.x.

## Development

```bash
npm install
npm run build
npm test
npm run check
```

Use `cargo fmt` for Rust and TypeScript project references for JavaScript packages.

## Developer Certificate of Origin

This project uses the Developer Certificate of Origin 1.1 instead of a CLA. Sign commits with `git commit -s` to certify that you have the right to contribute the work under the project license.
