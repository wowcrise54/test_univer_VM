import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api, downloadApiFile } from "../api/client.js";
import { ExportPanel, VulnerabilityPassportsPanel } from "../panels.jsx";

vi.mock("../api/client.js", () => ({
  api: vi.fn(),
  createIdempotencyKey: vi.fn(() => "test-key"),
  downloadApiFile: vi.fn(),
}));

function renderPanel({ busy = {}, downloadError = null, currentUser } = {}) {
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
      currentUser={currentUser}
    />,
  );
  return { runBusy, showAlert };
}

describe("ExportPanel vulnerability reports", () => {
  beforeEach(() => {
    api.mockReset();
    downloadApiFile.mockReset();
    downloadApiFile.mockResolvedValue({ filename: "report.csv", bytes: 100 });
  });

  it("hides PDQL export and import controls without manage permission", () => {
    renderPanel({
      currentUser: {
        permissions: ["imports_exports.read"],
      },
    });

    expect(screen.queryByText("PDQL запрос")).not.toBeInTheDocument();
    expect(screen.queryByText("Параметры экспорта")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Выполнить экспорт" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("Импорт")).not.toBeInTheDocument();
    expect(screen.getAllByText("Отчётность по уязвимостям").length).toBe(2);
  });

  it("downloads separate OS, software, and Docker reports with unique asset IDs", async () => {
    const { runBusy, showAlert } = renderPanel();
    fireEvent.click(
      screen.getByText("CSV по ОС, ПО и Docker").closest("summary"),
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "Asset ID для отчёта" }),
      {
        target: { value: "asset-1, asset-1\nasset-2" },
      },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Скачать уязвимости ОС" }),
    );

    await waitFor(() =>
      expect(downloadApiFile).toHaveBeenCalledWith(
        "/api/reports/vulnerabilities/os/csv",
        {
          method: "POST",
          body: JSON.stringify({ asset_ids: ["asset-1", "asset-2"] }),
        },
      ),
    );
    expect(runBusy).toHaveBeenCalledWith("report-os", expect.any(Function));
    expect(showAlert).toHaveBeenCalledWith(
      "CSV-отчёт сформирован: report.csv",
      "success",
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Скачать уязвимости ПО" }),
    );
    await waitFor(() =>
      expect(downloadApiFile).toHaveBeenLastCalledWith(
        "/api/reports/vulnerabilities/software/csv",
        expect.any(Object),
      ),
    );

    fireEvent.click(screen.getByRole("button", { name: /Docker/ }));
    await waitFor(() =>
      expect(downloadApiFile).toHaveBeenLastCalledWith(
        "/api/reports/vulnerabilities/docker/csv",
        {
          method: "POST",
          body: JSON.stringify({ asset_ids: ["asset-1", "asset-2"] }),
        },
      ),
    );
    expect(runBusy).toHaveBeenCalledWith("report-docker", expect.any(Function));
  });

  it("shows the existing error alert when download fails", async () => {
    const { showAlert } = renderPanel({
      downloadError: new Error("Не удалось сформировать отчёт"),
    });
    fireEvent.click(
      screen.getByText("CSV по ОС, ПО и Docker").closest("summary"),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Скачать уязвимости ОС" }),
    );
    await waitFor(() =>
      expect(showAlert).toHaveBeenCalledWith(
        "Не удалось сформировать отчёт",
        "error",
      ),
    );
  });

  it("keeps OS, software, and Docker download states independent", () => {
    renderPanel({ busy: { "report-os": true } });
    fireEvent.click(
      screen.getByText("CSV по ОС, ПО и Docker").closest("summary"),
    );
    const busyButton = screen.getByRole("button", { name: /Выполняю/ });
    expect(busyButton).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Скачать уязвимости ПО" }),
    ).toBeEnabled();
    expect(screen.getByRole("button", { name: /Docker/ })).toBeEnabled();
  });
});

describe("VulnerabilityPassportsPanel read-only view", () => {
  beforeEach(() => {
    api.mockReset();
  });

  it("hides PDQL query, detail-job controls, and destructive actions", () => {
    render(
      <VulnerabilityPassportsPanel
        defaults={null}
        busy={{}}
        runBusy={vi.fn()}
        showAlert={vi.fn()}
        currentUser={{
          permissions: ["passports.read"],
        }}
      />,
    );

    expect(screen.queryByText("PDQL запрос")).not.toBeInTheDocument();
    expect(screen.queryByText("Параметры PDQL")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Выполнить PDQL" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("Ещё")).not.toBeInTheDocument();
    expect(api).not.toHaveBeenCalledWith(
      "/api/vulnerability-passports/detail-jobs/active",
    );
    expect(screen.getByRole("button", { name: "Сохранённые" })).toBeEnabled();
  });
});
