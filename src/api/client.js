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
    throw normalizeApiError(error, { path, requestId });
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
    const normalizedDetail = typeof detail === "object" && detail ? detail : {};
    const baseMessage = typeof body === "string"
      ? body
      : typeof detail === "string"
        ? detail
        : normalizedDetail.message || JSON.stringify(body);
    const operatorMessage = normalizedDetail.operator_message || baseMessage;
    const message = traceId ? `${operatorMessage} [trace: ${traceId}]` : operatorMessage;
    const error = new Error(message);
    error.code = normalizedDetail.code || `HTTP_${response.status}`;
    error.operatorMessage = operatorMessage;
    error.component = normalizedDetail.component || "application";
    error.retryable = Boolean(normalizedDetail.retryable);
    error.context = normalizedDetail.context || {};
    error.traceId = normalizedDetail.trace_id || traceId;
    error.requestId = normalizedDetail.request_id || requestId;
    error.status = response.status;
    throw error;
  }
  return body;
}

export async function downloadApiFile(path, options = {}) {
  const headers = options.body instanceof FormData ? {} : { "Content-Type": "application/json" };
  const requestId = options.headers?.["X-Request-ID"] || createRequestId();
  const method = options.method || "GET";
  const started = performance.now();
  recordFrontendEvent("ui.fetch.started", { method, path, download: true }, { level: "debug", requestId });
  let response;
  try {
    response = await fetch(path, {
      ...options,
      headers: { ...headers, ...(options.headers || {}), "X-Request-ID": requestId },
    });
  } catch (error) {
    recordFrontendEvent(
      "ui.fetch.failed",
      { method, path, download: true, duration_ms: Math.round((performance.now() - started) * 100) / 100, message: error?.message },
      { level: "error", requestId, stack: error?.stack },
    );
    throw normalizeApiError(error, { path, requestId });
  }

  const traceId = response.headers.get("x-trace-id");
  rememberTraceId(traceId);
  if (!response.ok) {
    const contentType = response.headers.get("content-type") || "";
    let body;
    try {
      body = contentType.includes("application/json") ? await response.json() : await response.text();
    } catch {
      body = `HTTP ${response.status}`;
    }
    const detail = typeof body === "object" && body ? body.detail : null;
    const normalizedDetail = typeof detail === "object" && detail ? detail : {};
    const baseMessage = typeof body === "string"
      ? body
      : typeof detail === "string"
        ? detail
        : normalizedDetail.message || JSON.stringify(body);
    const operatorMessage = normalizedDetail.operator_message || baseMessage;
    recordFrontendEvent(
      "ui.fetch.failed",
      { method, path, download: true, status: response.status, duration_ms: Math.round((performance.now() - started) * 100) / 100 },
      { level: "error", requestId, traceId },
    );
    const error = new Error(traceId ? `${operatorMessage} [trace: ${traceId}]` : operatorMessage);
    error.code = normalizedDetail.code || `HTTP_${response.status}`;
    error.operatorMessage = operatorMessage;
    error.component = normalizedDetail.component || "application";
    error.retryable = Boolean(normalizedDetail.retryable);
    error.context = normalizedDetail.context || {};
    error.traceId = normalizedDetail.trace_id || traceId;
    error.requestId = normalizedDetail.request_id || requestId;
    error.status = response.status;
    throw error;
  }

  const blob = await response.blob();
  const disposition = response.headers.get("content-disposition") || "";
  const utf8Name = disposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
  const plainName = disposition.match(/filename="?([^";]+)"?/i)?.[1];
  const filename = utf8Name ? decodeURIComponent(utf8Name) : plainName || "download.csv";
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
  recordFrontendEvent(
    "ui.fetch.completed",
    { method, path, download: true, status: response.status, response_bytes: blob.size, duration_ms: Math.round((performance.now() - started) * 100) / 100 },
    { level: "info", requestId, traceId },
  );
  return { filename, bytes: blob.size };
}

export function normalizeApiError(error, context = {}) {
  if (error?.operatorMessage) return error;
  const normalized = new Error("Сервис приложения недоступен. Проверьте, что backend запущен, и повторите действие.");
  normalized.code = "NETWORK_UNAVAILABLE";
  normalized.operatorMessage = normalized.message;
  normalized.component = "application";
  normalized.retryable = true;
  normalized.traceId = error?.traceId || null;
  normalized.requestId = context.requestId || error?.requestId || null;
  normalized.context = { path: context.path || null };
  normalized.cause = error;
  return normalized;
}

export function createIdempotencyKey(prefix = "operation") {
  const uuid = globalThis.crypto?.randomUUID?.();
  return `${prefix}:${uuid || `${Date.now()}-${Math.random().toString(16).slice(2)}`}`;
}
