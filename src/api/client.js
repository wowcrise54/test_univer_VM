import {
  createRequestId,
  recordFrontendEvent,
  rememberTraceId,
} from "../diagnostics.js";

export async function api(path, options = {}) {
  const headers = options.body instanceof FormData ? {} : { "Content-Type": "application/json" };
  const requestId = options.headers?.["X-Request-ID"] || createRequestId();
  const method = options.method || "GET";
  const started = performance.now();
  recordFrontendEvent("ui.fetch.started", { method, path }, { level: "debug", requestId });
  let response;
  try {
    response = await fetch(path, {
      ...options,
      headers: { ...headers, ...(options.headers || {}), "X-Request-ID": requestId },
    });
  } catch (error) {
    recordFrontendEvent(
      "ui.fetch.failed",
      { method, path, duration_ms: Math.round((performance.now() - started) * 100) / 100, message: error?.message },
      { level: "error", requestId, stack: error?.stack },
    );
    throw error;
  }

  const traceId = response.headers.get("x-trace-id");
  rememberTraceId(traceId);
  const contentType = response.headers.get("content-type") || "";
  let body;
  try {
    body = contentType.includes("application/json") ? await response.json() : await response.text();
  } catch (error) {
    recordFrontendEvent(
      "ui.fetch.parse_failed",
      { method, path, status: response.status, message: error?.message },
      { level: "error", requestId, traceId, stack: error?.stack },
    );
    throw error;
  }
  const durationMs = Math.round((performance.now() - started) * 100) / 100;
  recordFrontendEvent(
    response.ok ? "ui.fetch.completed" : "ui.fetch.failed",
    {
      method,
      path,
      status: response.status,
      duration_ms: durationMs,
      response_bytes: Number(response.headers.get("content-length")) || null,
      content_encoding: response.headers.get("content-encoding"),
      etag: response.headers.get("etag"),
      server_timing: response.headers.get("server-timing"),
    },
    { level: response.ok ? "info" : "error", requestId, traceId },
  );
  if (!response.ok) {
    const detail = typeof body === "object" && body ? body.detail : null;
    const baseMessage = typeof body === "string"
      ? body
      : typeof detail === "string"
        ? detail
        : detail?.message || JSON.stringify(body);
    const message = traceId ? `${baseMessage} [trace: ${traceId}]` : baseMessage;
    const error = new Error(message);
    error.traceId = traceId;
    error.requestId = requestId;
    error.status = response.status;
    throw error;
  }
  return body;
}
