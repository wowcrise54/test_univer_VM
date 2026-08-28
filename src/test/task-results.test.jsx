import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { TaskListPanel } from "../panels.jsx";

vi.mock("../api/client.js", () => ({
  api: vi.fn(),
  createIdempotencyKey: vi.fn(() => "test-key"),
  downloadApiFile: vi.fn(),
}));

function renderPanel(task) {
  render(
    <TaskListPanel
      tasks={[task]}
      lookups={{ scanner_profiles: [], credentials: [] }}
      selectedTaskId={null}
      setSelectedTaskId={vi.fn()}
      refreshTasks={vi.fn()}
      busy={{}}
      showAlert={vi.fn()}
    />,
  );
}

describe("task results", () => {
  it("opens precheck jobs and expands connection check errors", async () => {
    api.mockResolvedValue({
      total: 1,
      is_precheck: true,
      run: { id: "run-1" },
      items: [{
        id: "job-1", status: "finished", errorStatus: "success",
        runMode: "connectionCheck", targets: ["10.0.0.1"],
        agent: { name: "collector-1" }, profile: { name: "Windows Audit" },
        connectionCheckResults: [{ transport: "RPC Filesystem", status: "fail", errors: ["connection"] }],
      }],
    });
    renderPanel({ mp_task_id: "task-1", name: "Precheck", status: "precheck_finished", include_targets: ["10.0.0.1"] });

    fireEvent.click(screen.getByText("Precheck"));
    expect(await screen.findByRole("dialog", { name: "Результаты задачи" })).toBeInTheDocument();
    expect(screen.getByText("0 из 1")).toBeInTheDocument();
    fireEvent.click(screen.getByText("0 из 1"));
    expect(screen.getByText("RPC Filesystem")).toBeInTheDocument();
    expect(screen.getByText("connection")).toBeInTheDocument();
    await waitFor(() => expect(api).toHaveBeenCalledWith("/api/scanner-tasks/task-1/results"));
  });
});
