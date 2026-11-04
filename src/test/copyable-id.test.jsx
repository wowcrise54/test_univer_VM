import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CopyableId, SnapshotStamp, shortenId } from "../shared/ui.jsx";
import { taskStatusLabel } from "../shared/labels.js";

const UUID = "3f2a9c1e-6b7d-4e55-9a10-0c8d2b7e4f11";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("CopyableId", () => {
  it("shows a shortened identifier with the full value in the tooltip", () => {
    render(<CopyableId value={UUID} label="ID операции" />);
    const button = screen.getByRole("button", {
      name: `Скопировать ID операции: ${UUID}`,
    });
    expect(button).toHaveTextContent("3f2a9c1e…4f11");
    expect(button).not.toHaveTextContent(UUID);
    expect(button.title).toContain(UUID);
  });

  it("copies the full value on click and confirms it", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    render(<CopyableId value={UUID} />);
    fireEvent.click(screen.getByRole("button"));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(UUID));
    expect(await screen.findByText("Скопировано")).toBeInTheDocument();
  });

  it("reports a failed copy instead of failing silently", async () => {
    Object.assign(navigator, {
      clipboard: { writeText: vi.fn().mockRejectedValue(new Error("denied")) },
    });
    render(<CopyableId value={UUID} />);
    fireEvent.click(screen.getByRole("button"));
    expect(await screen.findByText("Не удалось")).toBeInTheDocument();
  });

  it("does not trigger a row click and keeps short or empty values readable", () => {
    const onRow = vi.fn();
    Object.assign(navigator, {
      clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
    render(
      <div onClick={onRow}>
        <CopyableId value="short-id" />
        <CopyableId value="" />
      </div>,
    );
    fireEvent.click(screen.getByRole("button"));
    expect(onRow).not.toHaveBeenCalled();
    expect(screen.getByRole("button")).toHaveTextContent("short-id");
    expect(shortenId("")).toBe("");
  });
});

describe("SnapshotStamp", () => {
  it("renders nothing without snapshot metadata", () => {
    const { container } = render(<SnapshotStamp snapshot={undefined} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows the update time and marks a snapshot that is being recomputed", () => {
    render(
      <SnapshotStamp
        snapshot={{ generated_at: "2026-11-03T10:15:30Z", stale: true }}
      />,
    );
    expect(screen.getByText(/Обновлено в/)).toHaveTextContent("пересчитывается");
  });
});

describe("taskStatusLabel", () => {
  it("translates the precheck statuses on both task screens", () => {
    expect(taskStatusLabel("precheck_finished")).toBe("Хосты доступны");
    expect(taskStatusLabel("precheck_failed")).toBe("Хосты недоступны");
    expect(taskStatusLabel("precheck_validation_failed")).toBe(
      "Ошибка проверки хостов",
    );
  });

  it("keeps unknown keys visible and lets a screen override a label", () => {
    expect(taskStatusLabel("brand_new")).toBe("brand_new");
    expect(taskStatusLabel("STARTED")).toBe("Выполняется");
    expect(taskStatusLabel("started", { started: "Запущена" })).toBe("Запущена");
  });
});
