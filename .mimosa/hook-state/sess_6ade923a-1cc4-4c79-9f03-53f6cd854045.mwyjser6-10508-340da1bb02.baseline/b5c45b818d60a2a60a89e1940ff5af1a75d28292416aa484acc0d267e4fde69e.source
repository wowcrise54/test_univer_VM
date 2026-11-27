import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

describe("useAlerts", () => {
  afterEach(() => vi.useRealTimers());

  it("deduplicates messages, closes them and expires them automatically", async () => {
    vi.useFakeTimers();
    const { useAlerts } =
      await import("../features/notifications/useAlerts.js");
    const { result } = renderHook(() => useAlerts());
    act(() => {
      result.current.showAlert("Сбой", "error");
      result.current.showAlert("Сбой", "error");
      result.current.showAlert("Готово", "success");
    });
    expect(result.current.alerts).toHaveLength(2);
    expect(result.current.alerts[0].type).toBe("error");
    act(() => result.current.dismissAlert(result.current.alerts[0].id));
    expect(result.current.alerts.map((item) => item.message)).toEqual([
      "Готово",
    ]);
    act(() => vi.advanceTimersByTime(10000));
    expect(result.current.alerts).toHaveLength(0);
  });

  it("cleans its timers when unmounted and retains stable callbacks", async () => {
    vi.useFakeTimers();
    const { useAlerts } =
      await import("../features/notifications/useAlerts.js");
    const { result, rerender, unmount } = renderHook(() => useAlerts());
    const show = result.current.showAlert;
    const dismiss = result.current.dismissAlert;
    act(() => show("Готово"));
    rerender();
    expect(result.current.showAlert).toBe(show);
    expect(result.current.dismissAlert).toBe(dismiss);
    expect(vi.getTimerCount()).toBe(1);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});
describe("Bounded alert queue", () => {
  it("drops old alerts and clears their timers when the queue reaches four", async () => {
    vi.useFakeTimers();
    const { useAlerts } =
      await import("../features/notifications/useAlerts.js");
    const { result, unmount } = renderHook(() => useAlerts());
    act(() => {
      for (let index = 0; index < 10; index += 1)
        result.current.showAlert("Событие " + index);
    });
    expect(result.current.alerts.map((item) => item.message)).toEqual([
      "Событие 6",
      "Событие 7",
      "Событие 8",
      "Событие 9",
    ]);
    expect(vi.getTimerCount()).toBe(4);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
    vi.useRealTimers();
  });
});
