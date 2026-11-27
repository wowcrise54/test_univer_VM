import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { downloadApiFile } from "../api/client.js";

describe("downloadApiFile", () => {
  let clickSpy;

  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: vi.fn(() => "blob:test") });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: vi.fn() });
    clickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  });

  afterEach(() => {
    clickSpy.mockRestore();
    vi.unstubAllGlobals();
  });

  it("downloads a blob using the server filename", async () => {
    fetch.mockResolvedValue(new Response(["csv-data"], {
      status: 200,
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="host_os_vulnerabilities_20260710_120000.csv"',
      },
    }));

    const result = await downloadApiFile("/api/report", { method: "POST", body: "{}" });

    expect(result).toEqual({ filename: "host_os_vulnerabilities_20260710_120000.csv", bytes: 8 });
    expect(fetch).toHaveBeenCalledWith("/api/report", expect.objectContaining({
      method: "POST",
      headers: expect.objectContaining({ "Content-Type": "application/json", "X-Request-ID": expect.any(String) }),
    }));
    expect(clickSpy).toHaveBeenCalledOnce();
    expect(URL.createObjectURL).toHaveBeenCalledWith(expect.any(Blob));
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:test");
  });

  it("preserves the structured API error for the existing alert flow", async () => {
    fetch.mockResolvedValue(new Response([JSON.stringify({ detail: { code: "REPORT_FAILED", message: "Ошибка отчёта" } })], {
      status: 503,
      headers: { "Content-Type": "application/json", "X-Trace-ID": "trace-1" },
    }));

    await expect(downloadApiFile("/api/report", { method: "POST", body: "{}" })).rejects.toMatchObject({
      code: "REPORT_FAILED",
      operatorMessage: "Ошибка отчёта",
      traceId: "trace-1",
      status: 503,
    });
  });
});
