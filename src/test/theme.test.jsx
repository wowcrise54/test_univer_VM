import { fireEvent, render, screen } from "@testing-library/react";
import { JSDOM } from "jsdom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  initializeTheme,
  ThemeProvider,
  useTheme,
} from "../app/theme.jsx";

function ThemeControl() {
  const { theme, toggleTheme } = useTheme();
  return (
    <button type="button" aria-pressed={theme === "dark"} onClick={toggleTheme}>
      Toggle theme
    </button>
  );
}

describe("theme preference", () => {
  let storageWindow;

  beforeEach(() => {
    storageWindow = new JSDOM("", { url: "https://mpvm.test" }).window;
    vi.stubGlobal("localStorage", storageWindow.localStorage);
    document.documentElement.removeAttribute("data-theme");
    document.documentElement.style.colorScheme = "";
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    storageWindow.close();
  });

  it("starts light and saves a dark selection", () => {
    render(
      <ThemeProvider>
        <ThemeControl />
      </ThemeProvider>,
    );

    const toggle = screen.getByRole("button", { name: "Toggle theme" });
    expect(toggle).toHaveAttribute("aria-pressed", "false");
    expect(document.documentElement).toHaveAttribute("data-theme", "light");

    fireEvent.click(toggle);

    expect(toggle).toHaveAttribute("aria-pressed", "true");
    expect(document.documentElement).toHaveAttribute("data-theme", "dark");
    expect(globalThis.localStorage.getItem("mpvm-client-theme")).toBe("dark");
  });

  it("restores the saved theme", () => {
    globalThis.localStorage.setItem("mpvm-client-theme", "dark");

    render(
      <ThemeProvider>
        <ThemeControl />
      </ThemeProvider>,
    );

    expect(screen.getByRole("button", { name: "Toggle theme" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(document.documentElement).toHaveAttribute("data-theme", "dark");
  });

  it("applies the saved theme before the app renders", () => {
    globalThis.localStorage.setItem("mpvm-client-theme", "dark");

    expect(initializeTheme()).toBe("dark");
    expect(document.documentElement).toHaveAttribute("data-theme", "dark");
    expect(document.documentElement.style.colorScheme).toBe("dark");
  });
});
