import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import {
  Button,
  ConfirmDialog,
  Disclosure,
  Panel,
} from "../shared/ui.jsx";
import { filterOptions, formatDate, optionLabel } from "../shared/format.js";
import {
  operationKindLabel,
  remediationStatusLabel,
  severityLabel,
} from "../shared/labels.js";

describe("shared components without explanatory text", () => {
  it("keeps the button label while busy and marks it busy", () => {
    render(<Button busy>Обновить</Button>);
    const button = screen.getByRole("button", { name: "Обновить" });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("aria-busy", "true");
  });

  it("labels an untitled panel by the page heading and shows only actions", () => {
    render(
      <Panel action={<Button>Обновить</Button>}>
        <p>Содержимое</p>
      </Panel>,
    );
    const section = screen.getByText("Содержимое").closest("section");
    expect(section).toHaveAttribute("aria-labelledby", "workspace-title");
    expect(section.querySelector("h2")).toBeNull();
    expect(
      screen.getByRole("button", { name: "Обновить" }),
    ).toBeInTheDocument();
  });

  it("renders a titled panel without a description paragraph", () => {
    render(
      <Panel title="Фильтры" description="Лишний текст">
        <span>Поля</span>
      </Panel>,
    );
    expect(screen.getByRole("heading", { name: "Фильтры" })).toBeInTheDocument();
    expect(screen.queryByText("Лишний текст")).not.toBeInTheDocument();
  });

  it("shows a disclosure title and state but no subtitle", () => {
    render(
      <Disclosure title="Параметры" description="Лишний текст" meta="Не настроено">
        <span>Поля</span>
      </Disclosure>,
    );
    expect(screen.getByText("Параметры")).toBeInTheDocument();
    expect(screen.getByText("Не настроено")).toBeInTheDocument();
    expect(screen.queryByText("Лишний текст")).not.toBeInTheDocument();
  });

  it("confirms without a generic eyebrow and describes only when asked", () => {
    const { rerender } = render(
      <ConfirmDialog open title="Удалить группу?" onConfirm={vi.fn()} onClose={vi.fn()} />,
    );
    const dialog = screen.getByRole("dialog", { name: "Удалить группу?" });
    expect(dialog).not.toHaveAttribute("aria-describedby");
    expect(screen.queryByText("Подтверждение действия")).not.toBeInTheDocument();

    rerender(
      <ConfirmDialog
        open
        title="Удалить группу?"
        description="Группа исчезнет из списка."
        requireText="Серверы"
        onConfirm={vi.fn()}
        onClose={vi.fn()}
      />,
    );
    expect(screen.getByRole("dialog")).toHaveAccessibleDescription(
      "Группа исчезнет из списка.",
    );
    expect(screen.getByText(/для подтверждения/)).toBeInTheDocument();
  });
});

describe("shared formatting", () => {
  it("shows option names and adds the ID only for duplicate names", () => {
    const items = [
      { id: "p-1", name: "Windows" },
      { id: "p-2", name: "Linux" },
      { id: "p-3", name: "Linux" },
    ];
    expect(optionLabel(items[0], items)).toBe("Windows");
    expect(optionLabel(items[1], items)).toBe("Linux · p-2");
    expect(optionLabel({ id: "only-id" })).toBe("only-id");
    expect(filterOptions(items, "p-3")).toEqual([items[2]]);
  });

  it("formats dates and keeps empty or invalid values readable", () => {
    expect(formatDate(null)).toBe("—");
    expect(formatDate("не дата")).toBe("не дата");
    expect(formatDate("2026-10-27T10:05:00Z")).toMatch(/27\.10\.2026/);
  });

  it("translates machine values and falls back to the raw key", () => {
    expect(severityLabel("critical")).toBe("Критическая");
    expect(severityLabel("empty")).toBe("Не указана");
    expect(remediationStatusLabel(undefined)).toBe("Не создана");
    expect(operationKindLabel("automation_run")).toBe("Запуск по расписанию");
    expect(operationKindLabel("new_kind")).toBe("new_kind");
  });
});
