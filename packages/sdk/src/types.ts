export type Direction =
  | "to_model"
  | "from_model"
  | "tool_call"
  | "tool_result"
  | "memory_write";

export type Trust = "trusted" | "untrusted" | "unknown";
export type Severity = "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type Action = "allow" | "warn" | "ask" | "redact" | "block";
export type Mode = "audit" | "interactive" | "enforce";

export type Envelope = {
  direction: Direction;
  source: { kind: string; name?: string; trust: Trust };
  destination?: { provider?: string; model?: string; domain?: string };
  mediaType: string;
  segments: Array<{ id: string; text: string; jsonPath?: string }>;
};

export type Finding = {
  ruleId: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  location: { segmentId: string; start: number; end: number };
  maskedPreview: string;
  fingerprint: string;
  explanation: string;
  remediation: string;
};

export type Decision = {
  action: Action;
  findings: Finding[];
  transformed?: Envelope;
  coverage: {
    status: "complete" | "partial" | "unscanned";
    degradedDetectors: string[];
  };
  versions: {
    engine: string;
    policy: string;
    rulePacks: Record<string, string>;
  };
};

export type Suppression = {
  ruleId?: string;
  sourcePattern?: string;
  destination?: string;
  fingerprint?: string;
  expiresAt?: string;
  reason: string;
};

export type Rule = {
  id: string;
  kind?: "text" | "path";
  pattern: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  action: Action;
  explanation: string;
  remediation: string;
  validator?: "none" | "luhn" | "iban" | "ipv4" | "vn_cccd" | "vn_tax_id" | "entropy";
  context?: string[];
  negativeContext?: string[];
  requiresContext?: boolean;
  minEntropy?: number;
  fixtures?: { positive?: string[]; negative?: string[] };
};

export type RulePack = {
  manifest: {
    apiVersion: number;
    id: string;
    version: string;
    minEngineVersion: string;
    license: string;
    locales: string[];
  };
  rules: Rule[];
};

export type GuardConfig = {
  version: 1;
  mode: Mode;
  profiles: string[];
  actions: Partial<Record<string, Action>>;
  exclude: { paths: string[] };
  requiredDetectors: string[];
  suppressions: Suppression[];
  customRules: Rule[];
  maxFileBytes: number;
};

export type Guard = {
  readonly config: GuardConfig;
  readonly rulePacks: RulePack[];
  scan(envelope: Envelope, options?: { redact?: boolean }): Decision;
  sanitize(envelope: Envelope): Decision;
  scanText(text: string, options?: ScanTextOptions): Decision;
};

export type ScanTextOptions = {
  sourceName?: string;
  sourceKind?: string;
  trust?: Trust;
  destination?: Envelope["destination"];
  direction?: Direction;
  mediaType?: string;
  redact?: boolean;
};
