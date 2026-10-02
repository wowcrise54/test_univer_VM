import { useEffect, useMemo, useState } from "react";

const DRAFT_KEY = "mpvm.task-draft.v1";
const EDIT_DRAFT_KEY = `${DRAFT_KEY}.edits`;

function initialForm(utcOffset) {
  return {
    name: "",
    description: "Windows audit vulnerability collection",
    scope_id: "",
    profile_id: "",
    credential_id: "",
    credential_transport: "windows",
    host_discovery_profile_id: "",
    include_targets: "",
    exclude_targets: "",
    agent_ids: "",
    host_discovery_enabled: false,
    is_fqdn_priority: true,
    time_zone: utcOffset || "+05:00",
    schedule_enabled: false,
    schedule_type: "Daily",
    schedule_from_date: "",
    schedule_to_date: "",
    schedule_at_time: "09:00:00",
    schedule_days_of_week: [
      "monday",
      "tuesday",
      "wednesday",
      "thursday",
      "friday",
    ],
    schedule_interval: "1",
    schedule_interval_unit: "Days",
    schedule_start_time: "09:00:00",
    schedule_end_time: "17:00:00",
    schedule_day_of_month: "1",
    schedule_cron_expression: "0 9 * * 1-5",
    denied_scan_enabled: false,
    denied_periods: [],
    precheck_enabled: false,
    precheck_profile_id: "",
    precheck_timeout_minutes: "10",
    precheck_max_runtime_minutes: "5",
    precheck_poll_seconds: "10",
    task_timeout_minutes: "120",
    task_poll_seconds: "15",
    require_clean_jobs: false,
  };
}

function readNewDraft(emptyForm) {
  try {
    const saved = JSON.parse(window.localStorage.getItem(DRAFT_KEY) || "null");
    if (saved?.version === 1 && saved.form) {
      return { ...emptyForm, ...saved.form };
    }
  } catch (_error) {
    // A blocked or invalid storage entry must not prevent using the form.
  }
  return emptyForm;
}

function readEditDrafts() {
  try {
    const saved = JSON.parse(
      window.localStorage.getItem(EDIT_DRAFT_KEY) || "null",
    );
    return saved?.version === 1 &&
      saved.edits &&
      typeof saved.edits === "object"
      ? saved.edits
      : {};
  } catch (_error) {
    return {};
  }
}

function localDateTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
  return local.toISOString().slice(0, 16);
}

function taskForm(task, emptyForm) {
  const payload = task.payload || {};
  const trigger = payload.triggerParameters || {};
  const denied = payload.deniedScanSettings || {};
  return {
    ...emptyForm,
    name: payload.name || task.name || "",
    description: payload.description || "",
    scope_id: payload.scope || "",
    profile_id: payload.profile || "",
    credential_id:
      task.credential_id ||
      payload.overrides?.transports?.terminal?.ssh?.connection?.auth
        ?.ref_value ||
      payload.overrides?.transports?.windows?.wmi_and_rpc_and_re?.connection
        ?.auth?.ref_value ||
      "",
    credential_transport: payload.overrides?.transports?.terminal?.ssh
      ? "ssh"
      : "windows",
    host_discovery_profile_id: payload.hostDiscovery?.profile || "",
    include_targets: (payload.include?.targets || []).join("\n"),
    exclude_targets: (payload.exclude?.targets || []).join("\n"),
    agent_ids: (payload.agents?.agentIds || []).join("\n"),
    host_discovery_enabled: Boolean(payload.hostDiscovery?.enabled),
    is_fqdn_priority: payload.isFqdnPriority !== false,
    time_zone: trigger.timeZone || emptyForm.time_zone,
    schedule_enabled: Boolean(trigger.isEnabled),
    schedule_type: trigger.type || "Daily",
    schedule_from_date: localDateTime(trigger.fromDate),
    schedule_to_date: localDateTime(trigger.toDate),
    schedule_at_time: trigger.atTime || "09:00:00",
    schedule_days_of_week:
      trigger.daysOfWeek || emptyForm.schedule_days_of_week,
    schedule_interval: String(trigger.interval || 1),
    schedule_interval_unit: trigger.intervalUnit || "Days",
    schedule_start_time: trigger.startTime || "09:00:00",
    schedule_end_time: trigger.endTime || "17:00:00",
    schedule_day_of_month: String(trigger.dayOfMonth || 1),
    schedule_cron_expression: trigger.cronExpression || "0 9 * * 1-5",
    denied_scan_enabled: Boolean(denied.isEnabled),
    denied_periods: (denied.periods || []).map((period) => ({
      daysOfWeek: period.daysOfWeek || [],
      timeZone: period.timeZone || trigger.timeZone || emptyForm.time_zone,
      isAllDay: Boolean(period.isAllDay),
      fromTime: period.fromTime || "00:00:00",
      toTime: period.toTime || "06:00:00",
    })),
  };
}

export function useTaskForm({
  defaults,
  selectedTask,
  selectedTaskId,
  setSelectedTaskId,
  copyTask = null,
}) {
  const emptyForm = useMemo(
    () => initialForm(defaults?.utc_offset),
    [defaults?.utc_offset],
  );
  const [newDraft, setNewDraft] = useState(() =>
    copyTask ? taskForm(copyTask, emptyForm) : readNewDraft(emptyForm),
  );
  const [editDrafts, setEditDrafts] = useState(readEditDrafts);
  const selectedForm = selectedTask
    ? taskForm(selectedTask, emptyForm)
    : newDraft;
  const form = selectedTaskId
    ? editDrafts[selectedTaskId] || selectedForm
    : newDraft;

  useEffect(() => {
    const timer = window.setTimeout(() => {
      try {
        window.localStorage.setItem(
          DRAFT_KEY,
          JSON.stringify({
            version: 1,
            saved_at: new Date().toISOString(),
            form: newDraft,
          }),
        );
      } catch (_error) {
        // The in-memory draft remains usable if browser storage is unavailable.
      }
    }, 350);
    return () => window.clearTimeout(timer);
  }, [newDraft]);

  useEffect(() => {
    if (Object.keys(editDrafts).length === 0) return undefined;
    const timer = window.setTimeout(() => {
      try {
        window.localStorage.setItem(
          EDIT_DRAFT_KEY,
          JSON.stringify({
            version: 1,
            saved_at: new Date().toISOString(),
            edits: editDrafts,
          }),
        );
      } catch (_error) {
        // The in-memory edit remains available until the current page closes.
      }
    }, 350);
    return () => window.clearTimeout(timer);
  }, [editDrafts]);

  const setForm = (update) => {
    const nextForm = (current) =>
      typeof update === "function" ? update(current) : update;
    if (selectedTaskId) {
      const nextEdits = {
        ...editDrafts,
        [selectedTaskId]: nextForm(editDrafts[selectedTaskId] || selectedForm),
      };
      setEditDrafts(nextEdits);
      try {
        window.localStorage.setItem(
          EDIT_DRAFT_KEY,
          JSON.stringify({
            version: 1,
            saved_at: new Date().toISOString(),
            edits: nextEdits,
          }),
        );
      } catch (_error) {
        // The editor state remains in memory if browser storage is unavailable.
      }
    } else {
      setNewDraft(nextForm);
    }
  };

  const startNewTask = () => {
    setNewDraft(initialForm(defaults?.utc_offset));
    setSelectedTaskId(null);
  };

  return { form, setForm, startNewTask };
}
