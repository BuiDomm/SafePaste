mod engine;
pub mod model;
mod validators;

pub use engine::{scan_envelope, validate_rule_packs};
pub use model::{Decision, Envelope, Policy, RulePack};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn engine_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn validate_rules_json(rule_packs_json: &str) -> Result<String, JsValue> {
    let packs: Vec<RulePack> = serde_json::from_str(rule_packs_json)
        .map_err(|error| JsValue::from_str(&format!("invalid rule pack JSON: {error}")))?;
    validate_rule_packs(&packs).map_err(|error| JsValue::from_str(&error))?;
    Ok(serde_json::json!({ "valid": true, "packs": packs.len() }).to_string())
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn scan_json(
    envelope_json: &str,
    policy_json: &str,
    rule_packs_json: &str,
    hmac_key: &str,
) -> Result<String, JsValue> {
    let envelope: Envelope = serde_json::from_str(envelope_json)
        .map_err(|error| JsValue::from_str(&format!("invalid envelope JSON: {error}")))?;
    let policy: Policy = serde_json::from_str(policy_json)
        .map_err(|error| JsValue::from_str(&format!("invalid policy JSON: {error}")))?;
    let packs: Vec<RulePack> = serde_json::from_str(rule_packs_json)
        .map_err(|error| JsValue::from_str(&format!("invalid rule pack JSON: {error}")))?;
    let decision = scan_envelope(&envelope, &policy, &packs, hmac_key.as_bytes())
        .map_err(|error| JsValue::from_str(&error))?;
    serde_json::to_string(&decision).map_err(|error| JsValue::from_str(&error.to_string()))
}
