import {
  createServer,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

import type { Guard } from "@aiguard/sdk";

const hopByHopHeaders = new Set([
  "connection",
  "content-length",
  "host",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailers",
  "transfer-encoding",
  "upgrade",
]);

function safeHeaders(headers: IncomingHttpHeaders): IncomingHttpHeaders {
  return Object.fromEntries(
    Object.entries(headers).filter(([name]) => !hopByHopHeaders.has(name.toLowerCase())),
  );
}

function sendJson(response: ServerResponse, status: number, value: unknown): void {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
  });
  response.end(body);
}

async function readBody(request: IncomingMessage, limit: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > limit) {
      throw new Error("request_body_too_large");
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

function forward(
  request: IncomingMessage,
  response: ServerResponse,
  target: URL,
  body: Buffer,
): void {
  const transport = target.protocol === "https:" ? httpsRequest : httpRequest;
  const upstream = transport(
    target,
    {
      method: request.method,
      headers: {
        ...safeHeaders(request.headers),
        "content-length": body.length,
      },
    },
    (upstreamResponse) => {
      response.writeHead(upstreamResponse.statusCode ?? 502, {
        ...safeHeaders(upstreamResponse.headers),
        "x-aiguard-coverage": "request-complete;response-unscanned",
      });
      upstreamResponse.pipe(response);
    },
  );
  upstream.on("error", () => {
    if (!response.headersSent) {
      sendJson(response, 502, { error: { type: "aiguard_upstream_error" } });
    } else {
      response.destroy();
    }
  });
  upstream.end(body);
}

export async function startProxy(options: {
  guard: Guard;
  upstream: string;
  host: string;
  port: number;
}): Promise<Server> {
  const upstreamBase = new URL(options.upstream);
  if (!["http:", "https:"].includes(upstreamBase.protocol)) {
    throw new Error("proxy upstream must use http or https");
  }

  const server = createServer(async (request, response) => {
    if (request.url === "/__aiguard/health") {
      sendJson(response, 200, {
        status: "ok",
        coverage: { request: "complete", response: "unscanned" },
      });
      return;
    }
    try {
      const raw = await readBody(request, options.guard.config.maxFileBytes);
      const contentType = String(request.headers["content-type"] ?? "application/octet-stream");
      const textLike = contentType.includes("json") || contentType.startsWith("text/");
      if (!textLike && raw.length > 0) {
        sendJson(response, 415, { error: { type: "aiguard_unscanned_media" } });
        return;
      }
      const original = raw.toString("utf8");
      const decision = options.guard.scanText(original, {
        sourceKind: "local-proxy",
        sourceName: request.url ?? "/",
        destination: { domain: upstreamBase.hostname },
        mediaType: contentType,
        redact: true,
      });
      if (decision.action === "block" || decision.action === "ask") {
        console.error(
          `[aiguard] ${request.method ?? "REQUEST"} ${request.url ?? "/"} ${decision.action} findings=${decision.findings.length}`,
        );
        sendJson(response, 400, {
          error: {
            type: "aiguard_blocked",
            action: decision.action,
            ruleIds: decision.findings.map((finding) => finding.ruleId),
          },
        });
        return;
      }
      const body = Buffer.from(decision.transformed?.segments[0]?.text ?? original);
      const target = new URL(request.url ?? "/", upstreamBase);
      console.error(
        `[aiguard] ${request.method ?? "REQUEST"} ${request.url ?? "/"} ${decision.action} findings=${decision.findings.length}`,
      );
      forward(request, response, target, body);
    } catch (error) {
      const type = error instanceof Error ? error.message : "aiguard_proxy_error";
      sendJson(response, type === "request_body_too_large" ? 413 : 500, { error: { type } });
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port, options.host, () => resolve());
  });
  const address = server.address();
  const actualPort = typeof address === "object" && address ? address.port : options.port;
  console.error(`[aiguard] proxy listening on http://${options.host}:${actualPort}`);
  console.error(`[aiguard] forwarding allowed requests to ${upstreamBase.origin}`);
  return server;
}
