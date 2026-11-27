import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useRouter } from "../app/router.js";

vi.mock("../diagnostics.js", () => ({ recordFrontendEvent: vi.fn() }));

function RouterHarness() {
  const { navigate, path, search } = useRouter();
  return (
    <>
      <output aria-label="Current location">
        {path}
        {search}
      </output>
      <button onClick={() => navigate("/vulnerabilities?asset_id=host-1")}>
        Choose host
      </button>
      <button onClick={() => navigate("/vulnerabilities?severity=critical")}>
        Choose severity
      </button>
    </>
  );
}

describe("selection links", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/dashboards");
    window.scrollTo = vi.fn();
  });

  it("preserves the chosen asset in the URL and rendered location", () => {
    render(<RouterHarness />);
    fireEvent.click(screen.getByRole("button", { name: "Choose host" }));
    expect(window.location.search).toBe("?asset_id=host-1");
    expect(screen.getByLabelText("Current location")).toHaveTextContent(
      "/vulnerabilities?asset_id=host-1",
    );
  });

  it("updates selection links even when the page route stays the same", () => {
    window.history.replaceState({}, "", "/vulnerabilities?asset_id=previous");
    render(<RouterHarness />);
    fireEvent.click(screen.getByRole("button", { name: "Choose severity" }));
    expect(window.location.search).toBe("?severity=critical");
    expect(screen.getByLabelText("Current location")).toHaveTextContent(
      "/vulnerabilities?severity=critical",
    );
  });

  it("restores selection on browser navigation and retains legacy route queries", async () => {
    window.history.replaceState({}, "", "/assets?q=server");
    render(<RouterHarness />);
    expect(window.location.pathname).toBe("/asset-cards");
    expect(window.location.search).toBe("?q=server");
    window.history.replaceState({}, "", "/vulnerabilities?asset_id=host-2");
    window.dispatchEvent(new PopStateEvent("popstate"));
    await waitFor(() =>
      expect(screen.getByLabelText("Current location")).toHaveTextContent(
        "/vulnerabilities?asset_id=host-2",
      ),
    );
  });
});
