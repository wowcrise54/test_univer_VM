// @vitest-environment node

import { describe, expect, it, vi } from "vitest";
import { nextTableSort, SortableHeader } from "../shared/table.jsx";

describe("table sorting", () => {
  it("computes the next direction without depending on React state", () => {
    expect(nextTableSort({ key: "name", direction: "asc" }, "name")).toEqual({
      key: "name",
      direction: "desc",
    });
    expect(nextTableSort({ key: "name", direction: "desc" }, "name")).toEqual({
      key: "name",
      direction: "asc",
    });
    expect(
      nextTableSort({ key: "name", direction: "asc" }, "updated_at", "desc"),
    ).toEqual({ key: "updated_at", direction: "desc" });
  });

  it("announces the next action and marks the active header", () => {
    const onSort = vi.fn();
    const header = SortableHeader({
      column: "name",
      sort: { key: "name", direction: "asc" },
      onSort,
      children: "Название",
    });
    const button = header.props.children;

    expect(header.props["aria-sort"]).toBe("ascending");
    expect(button.props.className).toBe("sortable-header is-active");
    expect(button.props["aria-label"]).toBe(
      "Сортировать «Название» по убыванию",
    );
    expect(button.props.title).toBe("Сортировать «Название» по убыванию");

    button.props.onClick();
    expect(onSort).toHaveBeenCalledWith("name", "asc");
  });

  it("uses the initial direction for an inactive header", () => {
    const header = SortableHeader({
      column: "updated_at",
      sort: { key: "name", direction: "asc" },
      onSort: vi.fn(),
      children: "Обновлено",
      initialDirection: "desc",
    });
    const button = header.props.children;

    expect(header.props["aria-sort"]).toBe("none");
    expect(button.props.className).toBe("sortable-header");
    expect(button.props["aria-label"]).toBe(
      "Сортировать «Обновлено» по убыванию",
    );
  });
});
