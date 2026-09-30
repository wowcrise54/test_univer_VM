import { useState } from "react";
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { TaskListPanel } from "../features/tasks/index.jsx";

vi.mock("../api/client.js", () => ({
  api: vi.fn(),
  createIdempotencyKey: vi.fn(() => "test-key"),
  downloadApiFile: vi.fn(),
}));

function renderPanel(task) {
  function Harness() {
    const [selectedTaskId, setSelectedTaskId] = useState(null);
    return (
      <TaskListPanel
        tasks={[task]}
        lookups={{ scanner_profiles: [], credentials: [] }}
        selectedTaskId={selectedTaskId}
        setSelectedTaskId={setSelectedTaskId}
        refreshTasks={vi.fn()}
        busy={{}}
        showAlert={vi.fn()}
      />
    );
  }
  render(<Harness />);
}

const auditTask = {
  mp_task_id: "task-1",
  name: "Audit task",
  status: "finished",
  include_targets: ["10.0.0.1"],
};

describe("task results", () => {
  beforeEach(() => {
    api.mockReset();
    api.mockResolvedValue({ total: 0, items: [] });
  });

  it.each(["click", "Enter", " "])(
    "selects a task with %s without opening or fetching results",
    (activation) => {
      renderPanel(auditTask);
      const row = screen.getByText("Audit task").closest("tr");
      if (activation === "click") fireEvent.click(row);
      else fireEvent.keyDown(row, { key: activation });
      expect(row).toHaveAttribute("aria-selected", "true");
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      expect(api).not.toHaveBeenCalled();
    },
  );

  it("opens precheck jobs through Results and expands connection check errors", async () => {
    api.mockResolvedValue({
      total: 1,
      is_precheck: true,
      run: { id: "run-1" },
      items: [
        {
          id: "job-1",
          status: "finished",
          errorStatus: "success",
          runMode: "connectionCheck",
          targets: ["10.0.0.1"],
          agent: { name: "collector-1" },
          profile: { name: "Windows Audit" },
          connectionCheckResults: [
            {
              transport: "RPC Filesystem",
              status: "fail",
              errors: ["connection"],
            },
          ],
        },
      ],
    });
    renderPanel({
      ...auditTask,
      name: "Precheck",
      status: "precheck_finished",
    });

    fireEvent.click(screen.getByRole("button", { name: "Результаты" }));
    expect(
      await screen.findByRole("dialog", { name: "Результаты задачи" }),
    ).toBeInTheDocument();
    expect(screen.getByText("0 из 1")).toBeInTheDocument();
    fireEvent.click(screen.getByText("0 из 1"));
    expect(screen.getByText("RPC Filesystem")).toBeInTheDocument();
    expect(screen.getByText("connection")).toBeInTheDocument();
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith("/api/scanner-tasks/task-1/results"),
    );
  });

  it("keeps result loading errors retryable through the separate action", async () => {
    api.mockRejectedValueOnce(new Error("Results temporarily unavailable"));
    renderPanel(auditTask);
    fireEvent.click(screen.getByRole("button", { name: "Результаты" }));
    const dialog = await screen.findByRole("dialog", {
      name: "Результаты задачи",
    });
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Results temporarily unavailable",
    );
    fireEvent.click(within(dialog).getByRole("button", { name: "Повторить" }));
    expect(
      await within(dialog).findByText("У задачи пока нет результатов запуска."),
    ).toBeInTheDocument();
    expect(within(dialog).queryByRole("alert")).not.toBeInTheDocument();
  });
});
