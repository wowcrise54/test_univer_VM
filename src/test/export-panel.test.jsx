import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { downloadApiFile } from "../api/client.js";
import { ExportPanel } from "../panels.jsx";

vi.mock("../api/client.js", () => ({
  api: vi.fn(),
  createIdempotencyKey: vi.fn(() => "test-key"),
  downloadApiFile: vi.fn(),
}));

function renderPanel({ busy = {}, downloadError = null } = {}) {
  const showAlert = vi.fn();
  const runBusy = vi.fn(async (_key, action) => {
    try {
      return await action();
    } catch (error) {
      showAlert(error.message, "error");
      return null;
    }
  });
  if (downloadError) downloadApiFile.mockRejectedValue(downloadError);
  render(
    <ExportPanel
      defaults={null}
      busy={busy}
      runBusy={runBusy}
      refreshAssets={vi.fn()}
      showAlert={showAlert}
    />,
  );
  return { runBusy, showAlert };
}

describe("ExportPanel vulnerability reports", () => {
  beforeEach(() => {
    downloadApiFile.mockReset();
    downloadApiFile.mockResolvedValue({ filename: "report.csv", bytes: 100 });
  });

  it("downloads separate OS and software reports with unique asset IDs", async () => {
    const { runBusy, showAlert } = renderPanel();
    fireEvent.change(screen.getByRole("textbox", { name: "Asset ID для отчёта" }), {
      target: { value: "asset-1, asset-1\nasset-2" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Скачать уязвимости ОС" }));

    await waitFor(() => expect(downloadApiFile).toHaveBeenCalledWith(
      "/api/reports/vulnerabilities/os/csv",
      { method: "POST", body: JSON.stringify({ asset_ids: ["asset-1", "asset-2"] }) },
    ));
    expect(runBusy).toHaveBeenCalledWith("report-os", expect.any(Function));
    expect(showAlert).toHaveBeenCalledWith("CSV-отчёт сформирован: report.csv", "success");

    fireEvent.click(screen.getByRole("button", { name: "Скачать уязвимости ПО" }));
    await waitFor(() => expect(downloadApiFile).toHaveBeenLastCalledWith(
      "/api/reports/vulnerabilities/software/csv",
      expect.any(Object),
    ));
  });

  it("shows the existing error alert when download fails", async () => {
    const { showAlert } = renderPanel({ downloadError: new Error("Не удалось сформировать отчёт") });
    fireEvent.click(screen.getByRole("button", { name: "Скачать уязвимости ОС" }));
    await waitFor(() => expect(showAlert).toHaveBeenCalledWith("Не удалось сформировать отчёт", "error"));
  });

  it("keeps OS and software download states independent", () => {
    renderPanel({ busy: { "report-os": true } });
    const busyButton = screen.getByRole("button", { name: /Выполняю/ });
    expect(busyButton).toBeDisabled();
    expect(screen.getByRole("button", { name: "Скачать уязвимости ПО" })).toBeEnabled();
  });
});
