import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { CoveragePage } from "../pages/CoveragePage.jsx";
import { RemediationPage } from "../pages/RemediationPage.jsx";

vi.mock("../api/client.js", () => ({ api: vi.fn(), createIdempotencyKey: () => "test-key" }));

const CASE = { case_id:"case-1", version:1, status:"open", severity:"critical", cve:"CVE-2026-1", title:"RCE", asset_id:"asset-1", display_name:"server-1", overdue:true, events:[] };

beforeEach(() => { api.mockReset(); });

describe("RemediationPage", () => {
  it("shows SLA queue and opens an editable case", async () => {
    api.mockImplementation((path) => {
      if (path.startsWith("/api/remediation/cases?")) return Promise.resolve({ rows:[CASE], total:1 });
      if (path === "/api/remediation/summary") return Promise.resolve({ open:1, overdue:1, near_due:0, risk_accepted:0, resolved_30d:0 });
      if (path === "/api/remediation/policy") return Promise.resolve({ critical_days:7, high_days:30, medium_days:90, low_days:180, near_due_days:7 });
      if (path === "/api/remediation/cases/case-1") return Promise.resolve(CASE);
      return Promise.reject(new Error(path));
    });
    render(<RemediationPage showAlert={vi.fn()} onNavigate={vi.fn()} />);
    expect(await screen.findByText("CVE-2026-1")).toBeInTheDocument();
    expect(screen.getAllByText("Просрочено")).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name:"CVE-2026-1" }));
    await waitFor(() => expect(screen.getByLabelText("Ответственный")).toBeInTheDocument());
  });
});

describe("CoveragePage", () => {
  it("shows stale and truncated assets", async () => {
    api.mockImplementation((path) => path === "/api/coverage/summary"
      ? Promise.resolve({ coverage_percent:50, total_assets:2, missing_card:0, stale:1, truncated:1, last_refresh_failed:0, stale_days:7 })
      : Promise.resolve({ rows:[{ asset_id:"asset-1", display_name:"server-1", stale:true, truncated:true, missing_card:false, last_refresh_failed:false }] }));
    render(<CoveragePage showAlert={vi.fn()} onNavigate={vi.fn()} />);
    expect(await screen.findByText("server-1")).toBeInTheDocument();
    expect(screen.getByText("Устарела")).toBeInTheDocument();
    expect(screen.getByText("Данные усечены")).toBeInTheDocument();
  });
});
