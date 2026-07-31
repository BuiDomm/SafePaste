use aiguard_core::model::{Destination, Segment, Source};
use aiguard_core::{Envelope, Policy, RulePack, scan_envelope};
use rand::RngCore;

struct AppState {
    hmac_key: Vec<u8>,
    rule_packs: Vec<RulePack>,
}

#[tauri::command]
fn scan_text(
    text: String,
    state: tauri::State<'_, AppState>,
) -> Result<aiguard_core::Decision, String> {
    let envelope = Envelope {
        direction: "to_model".to_owned(),
        source: Source {
            kind: "desktop-active-scan".to_owned(),
            name: None,
            trust: "trusted".to_owned(),
        },
        destination: Some(Destination {
            provider: None,
            model: None,
            domain: None,
        }),
        media_type: "text/plain".to_owned(),
        segments: vec![Segment {
            id: "content".to_owned(),
            text,
            json_path: None,
        }],
    };
    let policy = Policy {
        redact: true,
        ..Policy::default()
    };
    scan_envelope(&envelope, &policy, &state.rule_packs, &state.hmac_key)
}

fn main() {
    let rule_packs: Vec<RulePack> = serde_json::from_str(&format!(
        "[{},{}]",
        include_str!("../../../../packages/rules-base/rules.json"),
        include_str!("../../../../packages/rules-vi/rules.json")
    ))
    .expect("bundled rule packs must be valid JSON");
    let mut hmac_key = vec![0_u8; 32];
    rand::rng().fill_bytes(&mut hmac_key);

    tauri::Builder::default()
        .manage(AppState {
            hmac_key,
            rule_packs,
        })
        .invoke_handler(tauri::generate_handler![scan_text])
        .run(tauri::generate_context!())
        .expect("failed to run AI Data Boundary desktop");
}
