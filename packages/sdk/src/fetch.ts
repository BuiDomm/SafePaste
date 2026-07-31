import type { Guard } from "./types.js";

export class GuardBlockedError extends Error {
  readonly action: "ask" | "block";
  readonly ruleIds: string[];

  constructor(action: "ask" | "block", ruleIds: string[]) {
    super(`AI Data Boundary ${action}ed the request (${ruleIds.length} finding(s))`);
    this.name = "GuardBlockedError";
    this.action = action;
    this.ruleIds = ruleIds;
  }
}

export function guardedFetch(guard: Guard, implementation: typeof fetch = globalThis.fetch): typeof fetch {
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const contentType = request.headers.get("content-type") ?? "application/octet-stream";
    const body = request.body ? await request.clone().text() : "";
    if (!body) {
      return implementation(request);
    }

    const decision = guard.scanText(body, {
      sourceKind: "sdk-fetch",
      destination: { domain: url.hostname },
      mediaType: contentType,
      redact: true,
    });
    if (decision.action === "block" || decision.action === "ask") {
      throw new GuardBlockedError(
        decision.action,
        decision.findings.map((finding) => finding.ruleId),
      );
    }
    const transformed = decision.transformed?.segments[0]?.text ?? body;
    const headers = new Headers(request.headers);
    headers.delete("content-length");
    return implementation(
      new Request(request, {
        body: transformed,
        headers,
      }),
    );
  };
}
