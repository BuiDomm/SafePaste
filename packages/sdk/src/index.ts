export { defaultConfig, findProjectConfig, loadConfig, userConfigPath, validateConfig } from "./config.js";
export { GuardBlockedError, guardedFetch } from "./fetch.js";
export { createGuard, keyedFingerprint, unscannedDecision } from "./guard.js";
export { testRulePacks } from "./rule-test.js";
export type { CreateGuardOptions } from "./guard.js";
export type { RuleTestFailure, RuleTestReport } from "./rule-test.js";
export type {
  Action,
  Confidence,
  Decision,
  Direction,
  Envelope,
  Finding,
  Guard,
  GuardConfig,
  Mode,
  Rule,
  RulePack,
  ScanTextOptions,
  Severity,
  Suppression,
  Trust,
} from "./types.js";
