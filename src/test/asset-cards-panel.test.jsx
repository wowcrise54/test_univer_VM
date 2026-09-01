import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { AssetCardsPanel } from "../panels.jsx";

vi.mock("../api/client.js", () => ({
  api: vi.fn(),
  createIdempotencyKey: vi.fn(() => "batch-test-key"),
}));

function job(assetId, status = "queued", progressPercent = 0) {
  return {
    job_id: `job-${assetId}`,
    asset_id: assetId,
    status,
    stage: status === "completed" ? "completed" : "tree_and_vulnerabilities",
    progress_percent: progressPercent,
    completed_requests: progressPercent,
    discovered_requests: 100,
    node_count: 1,
    collection_count: 1,
    finding_count: 0,
    warning_count: 0,
  };
}

function renderPanel() {
  return render(
    <AssetCardsPanel
      defaults={{}}
      busy={{}}
      runBusy={(_key, action) => action()}
      showAlert={vi.fn()}
    />,
  );
}

describe("AssetCardsPanel batch builds", () => {
  beforeEach(() => {
    api.mockReset();
    api.mockImplementation((path) => {
      if (path === "/api/asset-cards/build-jobs/active")
        return Promise.resolve({ job: null });
      if (path === "/api/asset-cards/refresh-scan/templates") {
        return Promise.resolve({ rows: [], recommended_task_id: null });
      }
      return Promise.resolve({ rows: [], total: 0 });
    });
  });

  it("submits up to two deduplicated asset IDs as one batch", async () => {
    const jobs = [job("asset-1"), job("asset-2")];
    api.mockImplementation((path) => {
      if (path === "/api/asset-cards/build-jobs/active")
        return Promise.resolve({ job: null });
      if (path === "/api/asset-cards/refresh-scan/templates")
        return Promise.resolve({ rows: [] });
      if (path === "/api/asset-cards/build-jobs/batch")
        return Promise.resolve({ jobs });
      return Promise.resolve({ rows: [], total: 0 });
    });
    renderPanel();
    fireEvent.click(screen.getByText("Пакетная сборка").closest("summary"));

    fireEvent.change(
      await screen.findByLabelText("Asset ID для пакетной сборки"),
      {
        target: { value: "asset-1\nasset-2, asset-1" },
      },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Собрать выбранные карточки" }),
    );

    await waitFor(() =>
      expect(api).toHaveBeenCalledWith(
        "/api/asset-cards/build-jobs/batch",
        expect.objectContaining({
          method: "POST",
          headers: { "X-Idempotency-Key": "batch-test-key" },
          body: JSON.stringify({
            asset_ids: ["asset-1", "asset-2"],
            timeline_timestamp: null,
            limit_per_collection: 5000,
            max_items_per_collection: 5000,
            max_depth: 8,
            docker_vulnerability_pdql: "",
          }),
        }),
      ),
    );
  });

  it("includes the visible common build options in a batch request", async () => {
    api.mockImplementation((path) => {
      if (path === "/api/asset-cards/build-jobs/active")
        return Promise.resolve({ job: null });
      if (path === "/api/asset-cards/refresh-scan/templates")
        return Promise.resolve({ rows: [] });
      if (path === "/api/asset-cards/build-jobs/batch")
        return Promise.resolve({ jobs: [job("asset-1")] });
      return Promise.resolve({ rows: [], total: 0 });
    });
    renderPanel();
    fireEvent.click(screen.getByText("Пакетная сборка").closest("summary"));
    fireEvent.click(screen.getByText("Параметры сборки").closest("summary"));

    fireEvent.change(
      await screen.findByLabelText("Asset ID для пакетной сборки"),
      {
        target: { value: "asset-1" },
      },
    );
    fireEvent.change(
      screen.getByLabelText("Timeline datetime, Unix timestamp"),
      {
        target: { value: "1712345678" },
      },
    );
    fireEvent.change(screen.getByLabelText("Лимит запроса коллекции"), {
      target: { value: "123" },
    });
    fireEvent.change(screen.getByLabelText("Максимум элементов коллекции"), {
      target: { value: "456" },
    });
    fireEvent.change(screen.getByLabelText("Глубина обхода"), {
      target: { value: "4" },
    });
    fireEvent.change(
      screen.getByLabelText("PDQL уязвимостей Docker-контейнеров"),
      {
        target: { value: "from Docker | group(@Host)" },
      },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Собрать выбранные карточки" }),
    );

    await waitFor(() =>
      expect(api).toHaveBeenCalledWith(
        "/api/asset-cards/build-jobs/batch",
        expect.objectContaining({
          body: JSON.stringify({
            asset_ids: ["asset-1"],
            timeline_timestamp: 1712345678,
            limit_per_collection: 123,
            max_items_per_collection: 456,
            max_depth: 4,
            docker_vulnerability_pdql: "from Docker | group(@Host)",
          }),
        }),
      ),
    );
  });

  it("renders independent progress for every returned card job", async () => {
    const jobs = [job("asset-1", "running", 25), job("asset-2", "running", 70)];
    api.mockImplementation((path) => {
      if (path === "/api/asset-cards/build-jobs/active")
        return Promise.resolve({ job: null });
      if (path === "/api/asset-cards/refresh-scan/templates")
        return Promise.resolve({ rows: [] });
      if (path === "/api/asset-cards/build-jobs/batch")
        return Promise.resolve({ jobs });
      if (path === "/api/asset-cards/build-jobs/job-asset-1")
        return Promise.resolve(jobs[0]);
      if (path === "/api/asset-cards/build-jobs/job-asset-2")
        return Promise.resolve(jobs[1]);
      return Promise.resolve({ rows: [], total: 0 });
    });
    renderPanel();
    fireEvent.click(screen.getByText("Пакетная сборка").closest("summary"));

    fireEvent.change(
      await screen.findByLabelText("Asset ID для пакетной сборки"),
      {
        target: { value: "asset-1\nasset-2" },
      },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Собрать выбранные карточки" }),
    );

    expect(
      await screen.findByRole("progressbar", {
        name: "Прогресс сборки карточки asset-1",
      }),
    ).toHaveAttribute("aria-valuenow", "25");
    expect(
      screen.getByRole("progressbar", {
        name: "Прогресс сборки карточки asset-2",
      }),
    ).toHaveAttribute("aria-valuenow", "70");
  });

  it("summarizes completed, failed, and active batch jobs", async () => {
    const jobs = [
      job("asset-1", "completed", 100),
      job("asset-2", "failed", 40),
      job("asset-3", "running", 25),
    ];
    api.mockImplementation((path) => {
      if (path === "/api/asset-cards/build-jobs/active")
        return Promise.resolve({ job: null });
      if (path === "/api/asset-cards/refresh-scan/templates")
        return Promise.resolve({ rows: [] });
      if (path === "/api/asset-cards/build-jobs/batch")
        return Promise.resolve({ jobs });
      if (path === "/api/asset-cards/build-jobs/job-asset-3")
        return Promise.resolve(jobs[2]);
      return Promise.resolve({ rows: [], total: 0 });
    });
    renderPanel();
    fireEvent.click(screen.getByText("Пакетная сборка").closest("summary"));

    fireEvent.change(
      await screen.findByLabelText("Asset ID для пакетной сборки"),
      {
        target: { value: "asset-1\nasset-2" },
      },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Собрать выбранные карточки" }),
    );

    expect(
      await screen.findByText("Готово: 1 · Ошибки: 1 · В работе: 1"),
    ).toBeInTheDocument();
    expect(screen.getByText("ошибка")).toBeInTheDocument();
  });
});
