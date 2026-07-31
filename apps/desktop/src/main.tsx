import { StrictMode, useState } from "react";
import { createRoot } from "react-dom/client";
import { invoke } from "@tauri-apps/api/core";

import "./styles.css";

type Finding = {
  ruleId: string;
  category: string;
  severity: string;
  confidence: string;
  maskedPreview: string;
  explanation: string;
  remediation: string;
};

type Decision = {
  action: string;
  findings: Finding[];
  transformed?: { segments: Array<{ text: string }> };
  coverage: { status: string; degradedDetectors: string[] };
};

function App() {
  const [text, setText] = useState("");
  const [decision, setDecision] = useState<Decision>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function scan() {
    setBusy(true);
    setError("");
    try {
      setDecision(await invoke<Decision>("scan_text", { text }));
    } catch (caught) {
      setError(String(caught));
    } finally {
      setBusy(false);
    }
  }

  async function scanClipboard() {
    setError("");
    try {
      const clipboard = await navigator.clipboard.readText();
      setText(clipboard);
      setBusy(true);
      setDecision(await invoke<Decision>("scan_text", { text: clipboard }));
    } catch {
      setError("Clipboard access was not granted. Paste the content manually instead.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main>
      <header>
        <p className="eyebrow">LOCAL-FIRST · ACTIVE SCAN ONLY</p>
        <h1>Inspect before AI sees it.</h1>
        <p>Nothing is sent to a model. This preview scans text with the local Rust engine.</p>
      </header>

      <section className="composer">
        <label htmlFor="prompt">Prompt or context</label>
        <textarea
          id="prompt"
          value={text}
          onChange={(event) => setText(event.target.value)}
          placeholder="Paste a prompt, log, configuration excerpt, or tool result…"
          spellCheck={false}
        />
        <div className="actions">
          <button className="primary" onClick={scan} disabled={busy || text.length === 0}>
            {busy ? "Scanning…" : "Scan locally"}
          </button>
          <button onClick={scanClipboard} disabled={busy}>Scan clipboard once</button>
        </div>
      </section>

      {error && <p className="error">{error}</p>}
      {decision && (
        <section className={`result action-${decision.action}`}>
          <div className="result-heading">
            <h2>{decision.action.toUpperCase()}</h2>
            <span>{decision.findings.length} finding(s) · {decision.coverage.status}</span>
          </div>
          {decision.findings.map((finding, index) => (
            <article key={`${finding.ruleId}-${index}`}>
              <div>
                <strong>{finding.ruleId}</strong>
                <span>{finding.severity}/{finding.confidence} · {finding.maskedPreview}</span>
              </div>
              <p>{finding.explanation}</p>
              <p className="fix">Fix: {finding.remediation}</p>
            </article>
          ))}
          {decision.transformed?.segments[0] && (
            <div className="sanitized">
              <h3>Sanitized preview</h3>
              <pre>{decision.transformed.segments[0].text}</pre>
            </div>
          )}
        </section>
      )}
    </main>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
