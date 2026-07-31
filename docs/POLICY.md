# Policy

The project config is `.aiguard.yml`. Precedence is CLI flags, project config, user config, then built-in defaults.

```yaml
version: 1
mode: interactive
profiles:
  - recommended
  - developer
  - vi-VN
actions:
  credential: block
  financial: ask
  pii: warn
  sensitive_file: ask
exclude:
  paths:
    - fixtures/public/**
requiredDetectors:
  - deterministic
suppressions: []
customRules: []
```

Unknown top-level keys are rejected. In `enforce` mode, an invalid config or unavailable required detector prevents startup.

## Modes

- `audit` reports findings and never transforms content.
- `interactive` preserves configured actions so a host can ask the user.
- `enforce` converts `ask` to `block` and fails closed for unscanned content.

## Suppressions

A suppression should be narrow, justified, and temporary. It may constrain rule ID, source glob, destination domain, keyed fingerprint, and expiration time. Expired suppressions are ignored.

## Custom rules

Custom rules use the same declarative schema as packaged rules. They cannot execute code. Each rule needs an ID, category, severity, confidence, action, regex or path pattern, explanation, remediation, and synthetic tests.
