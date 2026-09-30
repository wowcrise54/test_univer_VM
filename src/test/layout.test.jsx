import { useState } from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AlertStack, Sidebar, Topbar, WorkflowRail } from "../app/layout.jsx";
import {
  normalizeRoutePath,
  routeById,
  routeByPath,
} from "../app/navigation.js";

describe("guided application shell", () => {
  it("redirects the retired assets route to asset cards", () => {
    expect(normalizeRoutePath("/assets")).toBe("/asset-cards");
    expect(routeByPath("/assets")?.id).toBe("asset-cards");
    expect(routeById("assets")).toBeNull();
  });

  it("keeps primary navigation focused and moves tools behind disclosure", () => {
    render(
      <Sidebar
        session={{ connected: false }}
        systemStatus={{ components: { database: { state: "ok" } } }}
        activeOperations={2}
        activePath="/tasks"
        onNavigate={vi.fn()}
        currentUser={{
          permissions: [
            "connection.read",
            "tasks.read",
            "asset_groups.read",
            "operations.read",
            "assets.read",
            "imports_exports.read",
          ],
        }}
      />,
    );

    expect(
      screen.getByRole("link", { name: "VM Management" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Уязвимости" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Ещё").closest("summary")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Задачи" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(
      screen.getByRole("link", { name: "Группы активов" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Операции — активных: 2" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Активы" }),
    ).not.toBeInTheDocument();
  });

  it("hides navigation sections without effective permissions", () => {
    render(
      <Sidebar
        session={{ connected: false }}
        activePath="/operations"
        onNavigate={vi.fn()}
        currentUser={{ permissions: ["operations.read"] }}
      />,
    );
    expect(screen.getByRole("link", { name: "Операции" })).toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Задачи" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Пользователи" }),
    ).not.toBeInTheDocument();
  });

  it("shows the active stage and navigates directly between stages", () => {
    const navigate = vi.fn();
    render(<WorkflowRail activeRouteId="tasks" onNavigate={navigate} />);

    expect(screen.getByRole("button", { name: /Сканирование/ })).toHaveClass(
      "workflow-step--active",
    );
    expect(screen.getByRole("button", { name: /Обзор/ })).toHaveClass(
      "workflow-step--complete",
    );
    fireEvent.click(screen.getByRole("button", { name: /Отчётность/ }));
    expect(navigate).toHaveBeenCalledWith("/export");
  });

  it("offers connection setup before route-specific actions", () => {
    const navigate = vi.fn();
    render(
      <Topbar
        session={{ connected: false }}
        route={routeById("tasks")}
        onNavigate={navigate}
        currentUser={{ permissions: ["connection.manage"] }}
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: /Настроить подключение/ }),
    );
    expect(navigate).toHaveBeenCalledWith("/connection");
    expect(screen.getByText("Нет подключения")).toBeInTheDocument();
  });
});

describe("dismissible notifications", () => {
  it("removes one notification without clearing the other messages", () => {
    function Notifications() {
      const [alerts, setAlerts] = useState([
        { id: "first", message: "Сканирование запущено", type: "info" },
        { id: "second", message: "Архив готов", type: "success" },
      ]);
      return (
        <AlertStack
          alerts={alerts}
          onDismiss={(id) =>
            setAlerts((items) => items.filter((item) => item.id !== id))
          }
        />
      );
    }
    render(<Notifications />);
    fireEvent.click(
      screen.getAllByRole("button", { name: "Закрыть уведомление" })[0],
    );
    expect(screen.queryByText("Сканирование запущено")).not.toBeInTheDocument();
    expect(screen.getByText("Архив готов")).toBeInTheDocument();
  });
});
