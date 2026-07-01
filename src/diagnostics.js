const ENDPOINT = "/api/diagnostics/frontend";
const MAX_QUEUE = 500;
const MAX_BATCH = 50;
const FLUSH_DELAY_MS = 1200;
const SENSITIVE_KEY = /(access.?token|authorization|client.?secret|cookie|password|pdql.?token|refresh.?token|secret|timeline.?token|token)/i;

let queue = [];
let flushTimer = null;
let sending = false;
let lastTraceId = null;
let installed = false;

export function createRequestId() {
  return globalThis.crypto?.randomUUID?.() || `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
}

export function rememberTraceId(value) {
  if (value) lastTraceId = String(value).slice(0, 128);
}

export function currentFrontendTraceId() {
  return lastTraceId;
}

export function recordFrontendEvent(event, fields = {}, options = {}) {
  const entry = {
    event: String(event || "ui.event").slice(0, 128),
    level: options.level || "info",
    timestamp: new Date().toISOString(),
    trace_id: options.traceId || lastTraceId,
    request_id: options.requestId || fields.request_id || null,
    url: sanitizeUrl(options.url || globalThis.location?.href || ""),
    section: options.section || fields.section || null,
    stack: options.stack ? sanitizeString(options.stack, 128000) : null,
    fields: sanitizeValue(fields),
  };
  queue.push(entry);
  if (queue.length > MAX_QUEUE) queue = queue.slice(-MAX_QUEUE);
  if (entry.level === "error" || queue.length >= MAX_BATCH) {
    void flushFrontendDiagnostics();
  } else {
    scheduleFlush();
  }
}

export async function flushFrontendDiagnostics({ useBeacon = false } = {}) {
  if (sending || !queue.length) return;
  const events = queue.splice(0, MAX_BATCH);
  const body = JSON.stringify({ events });
  if (useBeacon && globalThis.navigator?.sendBeacon) {
    globalThis.navigator.sendBeacon(ENDPOINT, new Blob([body], { type: "application/json" }));
    if (queue.length) scheduleFlush();
    return;
  }
  sending = true;
  try {
    const response = await fetch(ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Request-ID": createRequestId() },
      body,
      keepalive: true,
    });
    rememberTraceId(response.headers.get("x-trace-id"));
  } catch (_error) {
    // Diagnostics must never break the application or recursively report itself.
  } finally {
    sending = false;
    if (queue.length) scheduleFlush();
  }
}

export function installGlobalDiagnostics() {
  if (installed || typeof window === "undefined") return;
  installed = true;
  window.addEventListener("error", (event) => {
    recordFrontendEvent(
      "ui.error",
      { message: event.message, filename: event.filename, line: event.lineno, column: event.colno },
      { level: "error", stack: event.error?.stack },
    );
  });
  window.addEventListener("unhandledrejection", (event) => {
    const reason = event.reason;
    recordFrontendEvent(
      "ui.unhandled_rejection",
      { message: reason?.message || String(reason || "Unhandled rejection") },
      { level: "error", stack: reason?.stack },
    );
  });
  window.addEventListener("pagehide", () => {
    void flushFrontendDiagnostics({ useBeacon: true });
  });
  recordFrontendEvent("ui.app.started", {
    navigation_type: performance.getEntriesByType?.("navigation")?.[0]?.type || "unknown",
  });
}

function scheduleFlush() {
  if (flushTimer) return;
  flushTimer = window.setTimeout(() => {
    flushTimer = null;
    void flushFrontendDiagnostics();
  }, FLUSH_DELAY_MS);
}

function sanitizeValue(value, depth = 0, key = "") {
  if (SENSITIVE_KEY.test(key)) return "[REDACTED]";
  if (depth > 8) return "[MAX_DEPTH]";
  if (value === null || value === undefined || typeof value === "boolean" || typeof value === "number") return value;
  if (typeof value === "string") return sanitizeString(value);
  if (Array.isArray(value)) return value.slice(0, 1000).map((item) => sanitizeValue(item, depth + 1));
  if (typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([name, item]) => [
      name,
      SENSITIVE_KEY.test(name) ? "[REDACTED]" : sanitizeValue(item, depth + 1, name),
    ]));
  }
  return sanitizeString(String(value));
}

function sanitizeString(value, maxLength = 16384) {
  const clean = String(value)
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]")
    .replace(/([A-Za-z][A-Za-z0-9+.-]*:\/\/)[^\s/@:]+(?::[^\s/@]*)?@/g, "$1***:***@");
  return clean.length > maxLength ? `${clean.slice(0, maxLength)}...[TRUNCATED]` : clean;
}

function sanitizeUrl(value) {
  try {
    const url = new URL(value, globalThis.location?.origin || "http://localhost");
    for (const key of [...url.searchParams.keys()]) {
      if (SENSITIVE_KEY.test(key)) url.searchParams.set(key, "[REDACTED]");
    }
    return `${url.pathname}${url.search}${url.hash}`.slice(0, 2048);
  } catch (_error) {
    return sanitizeString(value, 2048);
  }
}
