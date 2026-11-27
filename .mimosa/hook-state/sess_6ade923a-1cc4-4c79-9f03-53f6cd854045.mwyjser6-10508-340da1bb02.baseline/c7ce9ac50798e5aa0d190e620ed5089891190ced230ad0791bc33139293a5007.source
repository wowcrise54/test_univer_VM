import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ACCESS_CHANGED_EVENT } from "../api/accessEvents.js";
import { api, downloadApiFile } from "../api/client.js";

function jsonResponse(status, payload) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function denied(code, status = 403) {
  return jsonResponse(status, { detail: { code, message: "denied" } });
}

describe("access change signal from the API client", () => {
  let events;
  const listener = (event) => events.push(event.detail);

  beforeEach(() => {
    events = [];
    vi.stubGlobal("fetch", vi.fn());
    window.addEventListener(ACCESS_CHANGED_EVENT, listener);
  });

  afterEach(() => {
    window.removeEventListener(ACCESS_CHANGED_EVENT, listener);
    vi.unstubAllGlobals();
  });

  it.each([
    [403, "PERMISSION_DENIED"],
    [401, "AUTH_REQUIRED"],
  ])(
    "signals a %s %s answer and still rejects the request",
    async (status, code) => {
      fetch.mockResolvedValue(denied(code, status));

      await expect(api("/api/vulnerabilities/summary")).rejects.toMatchObject({
        status,
        code,
      });

      expect(events).toEqual([
        { path: "/api/vulnerabilities/summary", status, code },
      ]);
    },
  );

  it("signals a permission denial on file downloads too", async () => {
    fetch.mockResolvedValue(denied("PERMISSION_DENIED"));

    await expect(
      downloadApiFile("/api/export/assets.csv"),
    ).rejects.toMatchObject({ status: 403 });

    expect(events).toEqual([
      {
        path: "/api/export/assets.csv",
        status: 403,
        code: "PERMISSION_DENIED",
      },
    ]);
  });

  it.each([
    [
      "auth endpoints describe the session itself",
      "/api/auth/login",
      denied("AUTH_REQUIRED", 401),
    ],
    [
      "other 403 codes are not access changes",
      "/api/assets",
      denied("CROSS_SITE_REQUEST"),
    ],
    [
      "mismatched status and code",
      "/api/assets",
      denied("PERMISSION_DENIED", 401),
    ],
    [
      "server errors",
      "/api/assets",
      jsonResponse(500, { detail: { code: "INTERNAL" } }),
    ],
  ])("stays silent for %s", async (_label, path, response) => {
    fetch.mockResolvedValue(response);

    await expect(api(path)).rejects.toBeInstanceOf(Error);

    expect(events).toEqual([]);
  });
});
