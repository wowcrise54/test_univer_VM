import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useAlerts } from "../features/notifications/useAlerts.js";
import { useTaskForm } from "../features/tasks/useTaskForm.js";

const storageDescriptor = Object.getOwnPropertyDescriptor(
  window,
  "localStorage",
);
let storage;
beforeEach(() => {
  vi.useFakeTimers();
  storage = { getItem: vi.fn(() => null), setItem: vi.fn() };
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: storage,
  });
});
afterEach(() => {
  Object.defineProperty(window, "localStorage", storageDescriptor);
  vi.useRealTimers();
});

describe("alert lifecycle boundaries", () => {
  it.each(["", null, undefined, false, 0])(
    "ignores an empty message %s without scheduling work",
    (message) => {
      const { result, unmount } = renderHook(() => useAlerts());
      act(() => result.current.showAlert(message));
      expect(result.current.alerts).toEqual([]);
      expect(vi.getTimerCount()).toBe(0);
      unmount();
    },
  );

  it("retains distinct severity, returns duplicate IDs and tolerates already closed messages", () => {
    const { result, unmount } = renderHook(() => useAlerts());
    let first, duplicate;
    act(() => {
      first = result.current.showAlert("Same", "error");
      duplicate = result.current.showAlert("Same", "error");
      result.current.showAlert("Same", "info");
      result.current.dismissAlert("missing");
    });
    expect(first).toBe(duplicate);
    expect(result.current.alerts.map((item) => item.type)).toEqual([
      "error",
      "info",
    ]);
    expect(vi.getTimerCount()).toBe(2);
    act(() => {
      result.current.dismissAlert(first);
      result.current.dismissAlert(first);
      vi.advanceTimersByTime(5999);
    });
    expect(result.current.alerts).toHaveLength(1);
    act(() => vi.advanceTimersByTime(1));
    expect(result.current.alerts).toHaveLength(0);
    unmount();
  });
});

function taskProps(overrides = {}) {
  return {
    defaults: { utc_offset: "+03:00" },
    selectedTask: null,
    selectedTaskId: null,
    setSelectedTaskId: vi.fn(),
    ...overrides,
  };
}

describe("task draft storage and credential boundaries", () => {
  it.each([
    "not-json",
    '{"version":2,"form":{"name":"ignore"}}',
    '{"version":1}',
    "null",
  ])("starts safely with an unsupported saved draft %s", (saved) => {
    storage.getItem.mockReturnValue(saved);
    const { result, unmount } = renderHook(() => useTaskForm(taskProps()));
    expect(result.current.form.name).toBe("");
    expect(result.current.form.time_zone).toBe("+03:00");
    unmount();
  });

  it("keeps an editable draft when storage access and persistence are blocked", () => {
    storage.getItem.mockImplementation(() => {
      throw new Error("Storage blocked");
    });
    storage.setItem.mockImplementation(() => {
      throw new Error("Quota exceeded");
    });
    const { result, unmount } = renderHook(() =>
      useTaskForm(taskProps({ defaults: undefined })),
    );
    act(() =>
      result.current.setForm((form) => ({
        ...form,
        name: "Independent draft",
      })),
    );
    act(() => vi.advanceTimersByTime(350));
    expect(result.current.form.name).toBe("Independent draft");
    expect(result.current.form.time_zone).toBe("+05:00");
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("coalesces edits into the last saved new draft and clears pending persistence on unmount", () => {
    const { result, unmount } = renderHook(() => useTaskForm(taskProps()));
    act(() =>
      result.current.setForm({ ...result.current.form, name: "First" }),
    );
    act(() => result.current.setForm((form) => ({ ...form, name: "Final" })));
    act(() => vi.advanceTimersByTime(350));
    expect(storage.setItem).toHaveBeenCalledTimes(1);
    expect(JSON.parse(storage.setItem.mock.calls[0][1]).form.name).toBe(
      "Final",
    );
    act(() =>
      result.current.setForm({ ...result.current.form, name: "Unsaved" }),
    );
    unmount();
    act(() => vi.advanceTimersByTime(350));
    expect(storage.setItem).toHaveBeenCalledTimes(1);
  });

  it.each([
    [{}, "", "windows", "+03:00", true],
    [
      {
        overrides: {
          transports: {
            terminal: {
              ssh: { connection: { auth: { ref_value: "ssh-ref" } } },
            },
          },
        },
      },
      "ssh-ref",
      "ssh",
      "+03:00",
      true,
    ],
    [
      {
        overrides: {
          transports: {
            windows: {
              wmi_and_rpc_and_re: {
                connection: { auth: { ref_value: "windows-ref" } },
              },
            },
          },
        },
      },
      "windows-ref",
      "windows",
      "+03:00",
      true,
    ],
    [
      { triggerParameters: { timeZone: "+01:00" }, isFqdnPriority: false },
      "",
      "windows",
      "+01:00",
      false,
    ],
  ])(
    "loads available transport references and respects explicit task settings",
    (payload, credential, transport, zone, priority) => {
      const { result, unmount } = renderHook(() =>
        useTaskForm(
          taskProps({
            selectedTaskId: "task",
            selectedTask: { name: "Existing", payload },
          }),
        ),
      );
      expect(result.current.form).toMatchObject({
        name: "Existing",
        credential_id: credential,
        credential_transport: transport,
        time_zone: zone,
        is_fqdn_priority: priority,
      });
      unmount();
    },
  );

  it("handles a legacy task with no payload and preserves an edit across data refresh", () => {
    const props = taskProps({
      selectedTaskId: "legacy",
      selectedTask: { name: "Legacy" },
    });
    const { result, rerender, unmount } = renderHook(
      (values) => useTaskForm(values),
      { initialProps: props },
    );
    act(() =>
      result.current.setForm((form) => ({ ...form, name: "Edited locally" })),
    );
    rerender({ ...props, selectedTask: { name: "Remote refresh" } });
    expect(result.current.form.name).toBe("Edited locally");
    unmount();
  });
});
