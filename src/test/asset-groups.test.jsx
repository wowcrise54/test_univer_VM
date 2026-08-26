import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AssetGroupsPage } from "../pages/AssetGroupsPage.jsx";

function renderPage(permissions = ["asset_groups.read", "asset_groups.manage"]) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <AssetGroupsPage currentUser={{ permissions }} showAlert={vi.fn()} />
    </QueryClientProvider>,
  );
}

afterEach(() => vi.restoreAllMocks());

describe("asset groups management", () => {
  it("renders and filters the remote hierarchy", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      rows: [{ id: "root-1", name: "Infrastructure", groupType: "static", children: [
        { id: "group-1", name: "Production Linux", groupType: "dynamic", predicate: "(ImageSet)", children: [] },
      ] }],
    }), { status: 200, headers: { "Content-Type": "application/json" } }));

    renderPage();
    expect(await screen.findByRole("button", { name: /Infrastructure/ })).toBeInTheDocument();
    fireEvent.change(screen.getByRole("searchbox", { name: "Поиск групп" }), { target: { value: "Linux" } });
    expect(screen.getByRole("button", { name: /Production Linux/ })).toBeInTheDocument();
  });

  it("hides mutation controls from read-only users", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ rows: [] }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));

    renderPage(["asset_groups.read"]);
    await waitFor(() => expect(screen.getByText("Группы не найдены.")).toBeInTheDocument());
    expect(screen.queryByRole("heading", { name: "Новая динамическая группа" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Создать группу" })).not.toBeInTheDocument();
  });
});
