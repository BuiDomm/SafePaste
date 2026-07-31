use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Warn,
    Ask,
    Redact,
    Block,
}

impl Action {
    pub(crate) fn rank(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::Warn => 1,
            Self::Ask => 2,
            Self::Redact => 3,
            Self::Block => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Audit,
    #[default]
    Interactive,
    Enforce,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Source {
    pub kind: String,
    #[serde(default)]
    pub name: Option<String>,
    pub trust: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Destination {
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Segment {
    pub id: String,
    pub text: String,
    #[serde(default)]
    pub json_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Envelope {
    pub direction: String,
    pub source: Source,
    #[serde(default)]
    pub destination: Option<Destination>,
    pub media_type: String,
    pub segments: Vec<Segment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RulePackManifest {
    pub api_version: u32,
    pub id: String,
    pub version: String,
    pub min_engine_version: String,
    pub license: String,
    #[serde(default)]
    pub locales: Vec<String>,
}

fn default_rule_kind() -> String {
    "text".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleFixtures {
    #[serde(default)]
    pub positive: Vec<String>,
    #[serde(default)]
    pub negative: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    #[serde(default = "default_rule_kind")]
    pub kind: String,
    pub pattern: String,
    pub category: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub action: Action,
    pub explanation: String,
    pub remediation: String,
    #[serde(default)]
    pub validator: Option<String>,
    #[serde(default)]
    pub context: Vec<String>,
    #[serde(default)]
    pub negative_context: Vec<String>,
    #[serde(default)]
    pub requires_context: bool,
    #[serde(default)]
    pub min_entropy: Option<f64>,
    #[serde(default)]
    pub fixtures: Option<RuleFixtures>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RulePack {
    pub manifest: RulePackManifest,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Suppression {
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub source_pattern: Option<String>,
    #[serde(default)]
    pub destination: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    pub reason: String,
}

fn default_policy_version() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    #[serde(default = "default_policy_version")]
    pub version: u32,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub actions: BTreeMap<String, Action>,
    #[serde(default)]
    pub suppressions: Vec<Suppression>,
    #[serde(default)]
    pub now: Option<String>,
    #[serde(default)]
    pub redact: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: 1,
            mode: Mode::Interactive,
            actions: BTreeMap::new(),
            suppressions: Vec::new(),
            now: None,
            redact: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    pub segment_id: String,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub rule_id: String,
    pub category: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub location: Location,
    pub masked_preview: String,
    pub fingerprint: String,
    pub explanation: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Complete,
    Partial,
    Unscanned,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Coverage {
    pub status: CoverageStatus,
    pub degraded_detectors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Versions {
    pub engine: String,
    pub policy: String,
    pub rule_packs: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    pub action: Action,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transformed: Option<Envelope>,
    pub coverage: Coverage,
    pub versions: Versions,
}

#[derive(Debug, Clone)]
pub(crate) struct InternalFinding {
    pub public: Finding,
    pub action: Action,
}
