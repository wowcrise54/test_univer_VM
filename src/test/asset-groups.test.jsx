import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AssetGroupsPage } from "../pages/AssetGroupsPage.jsx";

function renderPage(permissions = ["asset_groups.read", "asset_groups.manage"]) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}><AssetGroupsPage currentUser={{ permissions }} showAlert={vi.fn()} /></QueryClientProvider>);
}

function response(payload) {
  return Promise.resolve(new Response(JSON.stringify(payload), { status: 200, headers: { "Content-Type": "application/json" } }));
}

afterEach(() => vi.restoreAllMocks());

describe("local asset groups management", () => {
  it("renders and filters the calculated hierarchy", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((input) => String(input).includes("/fields")
      ? response({ rows: [] })
      : response({ rows: [{ group_id: "root-1", name: "Infrastructure", status: "ready", member_count: 12, children: [
        { group_id: "group-1", name: "Production Linux", status: "ready", member_count: 4, children: [] },
      ] }] }));

    renderPage();
    expect(await screen.findByRole("button", { name: /Infrastructure/ })).toBeInTheDocument();
    fireEvent.change(screen.getByRole("searchbox", { name: "Поиск групп" }), { target: { value: "Linux" } });
    expect(screen.getByRole("button", { name: /Production Linux/ })).toBeInTheDocument();
  });

  it("hides mutation controls from read-only users", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(() => response({ rows: [] }));

    renderPage(["asset_groups.read"]);
    await waitFor(() => expect(screen.getByText("Групп пока нет.")).toBeInTheDocument());
    expect(screen.queryByRole("heading", { name: "Новая динамическая группа" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Создать группу" })).not.toBeInTheDocument();
  });
});
