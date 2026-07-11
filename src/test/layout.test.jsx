import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Sidebar, Topbar, WorkflowRail } from "../app/layout.jsx";
import { routeById } from "../app/navigation.js";

describe("guided application shell", () => {
  it("groups navigation around the operator workflow", () => {
    render(
      <Sidebar
        session={{ connected: false }}
        systemStatus={{ components: { database: { state: "ok" } } }}
        activeOperations={2}
        activePath="/tasks"
        onNavigate={vi.fn()}
      />,
    );

    expect(screen.getByRole("heading", { name: "Рабочий процесс" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Данные и анализ" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Управление" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Уязвимости" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Задачи" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "Операции — активных: 2" })).toBeInTheDocument();
  });

  it("shows the active stage and navigates directly between stages", () => {
    const navigate = vi.fn();
    render(<WorkflowRail activeRouteId="tasks" onNavigate={navigate} />);

    expect(screen.getByRole("button", { name: /Сканирование/ })).toHaveClass("workflow-step--active");
    expect(screen.getByRole("button", { name: /Подключение/ })).toHaveClass("workflow-step--complete");
    fireEvent.click(screen.getByRole("button", { name: /Отчётность/ }));
    expect(navigate).toHaveBeenCalledWith("/export");
  });

  it("offers connection setup before route-specific actions", () => {
    const navigate = vi.fn();
    render(<Topbar session={{ connected: false }} route={routeById("tasks")} onNavigate={navigate} />);

    fireEvent.click(screen.getByRole("button", { name: /Настроить подключение/ }));
    expect(navigate).toHaveBeenCalledWith("/connection");
    expect(screen.getByText("MP VM не подключён")).toBeInTheDocument();
  });
});
