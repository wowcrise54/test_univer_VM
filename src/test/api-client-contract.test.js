import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, createIdempotencyKey } from "../api/client.js";
import { currentFrontendTraceId } from "../diagnostics.js";

function jsonResponse(status, payload, headers = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

describe("api() client contract", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns the parsed JSON body and sends JSON plus X-Request-ID headers", async () => {
    fetch.mockResolvedValue(
      new Response(JSON.stringify({ rows: [], total: 0 }), {
        status: 200,
        headers: { "Content-Type": "application/json; charset=utf-8" },
      }),
    );

    const body = await api("/api/session");

    expect(body).toEqual({ rows: [], total: 0 });
    const init = fetch.mock.calls[0][1];
    expect(init.method).toBeUndefined();
    expect(init.headers["Content-Type"]).toBe("application/json");
    expect(typeof init.headers["X-Request-ID"]).toBe("string");
  });

  it("returns the raw text body for non-JSON responses", async () => {
    fetch.mockResolvedValue(
      new Response("plain text result", {
        status: 200,
        headers: { "Content-Type": "text/plain; charset=utf-8" },
      }),
    );

    await expect(api("/api/report")).resolves.toBe("plain text result");
  });

  it("reuses an X-Request-ID supplied by the caller", async () => {
    fetch.mockResolvedValue(
      new Response("{}", {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await api("/api/operations", { headers: { "X-Request-ID": "fixed-req-1" } });

    expect(fetch.mock.calls[0][1].headers["X-Request-ID"]).toBe("fixed-req-1");
  });

  it("lets the browser set the content type for FormData uploads", async () => {
    const form = new FormData();
    form.append("file", "report.csv");
    fetch.mockResolvedValue(
      new Response("uploaded", {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      }),
    );

    await api("/api/upload", { method: "POST", body: form });

    const init = fetch.mock.calls[0][1];
    expect(init.body).toBe(form);
    expect(init.headers["Content-Type"]).toBeUndefined();
    expect(init.headers["X-Request-ID"]).toBeTruthy();
  });

  it("normalizes a structured detail error with trace and request ids", async () => {
    fetch.mockResolvedValue(
      jsonResponse(
        503,
        {
          detail: {
            code: "MPVM_UNAVAILABLE",
            message: "Внутренний сбой",
            operator_message: "MP VM не отвечает",
            component: "mpvm",
            retryable: true,
            context: { target: "scan" },
            trace_id: "body-trace",
            request_id: "body-req",
          },
        },
        { "X-Trace-ID": "header-trace" },
      ),
    );

    const error = await api("/api/vm/overview").catch((value) => value);

    expect(error).toBeInstanceOf(Error);
    expect(error.message).toBe("MP VM не отвечает [trace: header-trace]");
    expect(error.operatorMessage).toBe("MP VM не отвечает");
    expect(error.code).toBe("MPVM_UNAVAILABLE");
    expect(error.component).toBe("mpvm");
    expect(error.retryable).toBe(true);
    expect(error.context).toEqual({ target: "scan" });
    expect(error.traceId).toBe("body-trace");
    expect(error.requestId).toBe("body-req");
    expect(error.status).toBe(503);
  });

  it("keeps the operator message plain when no trace header is returned", async () => {
    fetch.mockResolvedValue(
      jsonResponse(503, {
        detail: {
          code: "HISTORY_UNAVAILABLE",
          message: "internal detail",
          operator_message: "История недоступна",
          retryable: true,
        },
      }),
    );

    const error = await api("/api/vulnerabilities/trends").catch((value) => value);
    const sentRequestId = fetch.mock.calls[0][1].headers["X-Request-ID"];

    expect(error.message).toBe("История недоступна");
    expect(error.operatorMessage).toBe("История недоступна");
    expect(error.code).toBe("HISTORY_UNAVAILABLE");
    expect(error.retryable).toBe(true);
    expect(error.component).toBe("application");
    expect(error.context).toEqual({});
    expect(error.traceId).toBeNull();
    expect(error.requestId).toBe(sentRequestId);
    expect(error.status).toBe(503);
  });

  it("uses a plain string body as the error message with an HTTP_* code", async () => {
    fetch.mockResolvedValue(
      new Response("Просто ошибка", {
        status: 500,
        headers: { "Content-Type": "text/plain" },
      }),
    );

    const error = await api("/api/export").catch((value) => value);

    expect(error.message).toBe("Просто ошибка");
    expect(error.operatorMessage).toBe("Просто ошибка");
    expect(error.code).toBe("HTTP_500");
    expect(error.retryable).toBe(false);
    expect(error.status).toBe(500);
  });

  it("prefers a string detail over the whole body", async () => {
    fetch.mockResolvedValue(
      jsonResponse(503, { detail: "База данных недоступна", error: "db" }),
    );

    const error = await api("/api/assets").catch((value) => value);

    expect(error.message).toBe("База данных недоступна");
    expect(error.code).toBe("HTTP_503");
    expect(error.status).toBe(503);
  });

  it("falls back to the stringified body when detail is missing", async () => {
    fetch.mockResolvedValue(jsonResponse(500, { error: "boom" }));

    const error = await api("/api/operations/summary").catch((value) => value);

    expect(error.message).toBe('{"error":"boom"}');
    expect(error.code).toBe("HTTP_500");
    expect(error.component).toBe("application");
  });

  it("normalizes a network failure into a retryable availability error", async () => {
    const networkFailure = new TypeError("fetch failed");
    fetch.mockRejectedValue(networkFailure);

    const error = await api("/api/system/status").catch((value) => value);

    expect(error).toBeInstanceOf(Error);
    expect(error.code).toBe("NETWORK_UNAVAILABLE");
    expect(error.retryable).toBe(true);
    expect(error.operatorMessage).toBe(error.message);
    expect(error.message).toContain("Сервис приложения недоступен");
    expect(error.context).toEqual({ path: "/api/system/status" });
    expect(error.requestId).toBe(
      fetch.mock.calls[0][1].headers["X-Request-ID"],
    );
    expect(error.cause).toBe(networkFailure);
  });

  it("rethrows a JSON parse failure instead of masking it", async () => {
    fetch.mockResolvedValue(
      new Response("не-json", {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await expect(api("/api/vm/overview")).rejects.toThrow();
  });

  it("remembers the x-trace-id from a successful response", async () => {
    fetch.mockResolvedValue(
      new Response("{}", {
        status: 200,
        headers: { "Content-Type": "application/json", "X-Trace-ID": "trace-abc" },
      }),
    );

    await api("/api/session");
    expect(currentFrontendTraceId()).toBe("trace-abc");
  });

  it("creates unique prefixed idempotency keys", () => {
    const first = createIdempotencyKey("vm-scan");
    const second = createIdempotencyKey("vm-scan");

    expect(first).toMatch(/^vm-scan:.+$/);
    expect(second).toMatch(/^vm-scan:.+$/);
    expect(first).not.toBe(second);
    expect(createIdempotencyKey()).toMatch(/^operation:.+$/);
  });
});
