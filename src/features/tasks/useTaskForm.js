import { useEffect, useMemo, useState } from "react";

const DRAFT_KEY = "mpvm.task-draft.v1";

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

function taskForm(task, emptyForm) {
  const payload = task.payload || {};
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
    time_zone: payload.triggerParameters?.timeZone || emptyForm.time_zone,
  };
}

export function useTaskForm({
  defaults,
  selectedTask,
  selectedTaskId,
  setSelectedTaskId,
}) {
  const emptyForm = useMemo(
    () => initialForm(defaults?.utc_offset),
    [defaults?.utc_offset],
  );
  const [newDraft, setNewDraft] = useState(() => readNewDraft(emptyForm));
  const [editDrafts, setEditDrafts] = useState({});
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

  const setForm = (update) => {
    const nextForm = (current) =>
      typeof update === "function" ? update(current) : update;
    if (selectedTaskId) {
      setEditDrafts((current) => ({
        ...current,
        [selectedTaskId]: nextForm(current[selectedTaskId] || selectedForm),
      }));
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
