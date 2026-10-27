export const OS_LABELS = { windows: "Windows", linux: "Linux" };
export const OS_TRANSPORT = { windows: "windows", linux: "ssh" };

// Targets are separated by commas, semicolons, spaces or new lines; the
// backend validates IP addresses, networks, ranges and FQDNs.
export function parseTargets(text) {
  return [
    ...new Set(
      String(text || "")
        .split(/[\s,;]+/)
        .map((value) => value.trim())
        .filter(Boolean),
    ),
  ];
}

export function emptyPresetForm() {
  return {
    preset_id: null,
    version: null,
    name: "",
    description: "",
    os_family: "windows",
    scope_id: "",
    profile_id: "",
    credential_id: "",
    agent_ids: [],
    host_discovery_enabled: false,
    host_discovery_profile_id: "",
    is_fqdn_priority: true,
    time_zone: "+05:00",
    precheck_enabled: true,
    precheck_profile_id: "",
    allowed_asset_groups: [],
    allowed_targets_text: "",
    max_groups_per_task: 5,
    max_active_tasks: 3,
    name_prefix: "",
    role_ids: [],
    trigger_parameters: null,
    denied_scan_settings: null,
  };
}

export function presetToForm(preset) {
  const base = emptyPresetForm();
  if (!preset) return base;
  const startOptions = preset.start_options || {};
  return {
    ...base,
    preset_id: preset.preset_id || null,
    version: preset.version || null,
    name: preset.name || "",
    description: preset.description || "",
    os_family: preset.os_family === "linux" ? "linux" : "windows",
    scope_id: preset.scope_id || "",
    profile_id: preset.profile_id || "",
    credential_id: preset.credential_id || "",
    agent_ids: preset.agent_ids || [],
    host_discovery_enabled: Boolean(preset.host_discovery_enabled),
    host_discovery_profile_id: preset.host_discovery_profile_id || "",
    is_fqdn_priority: preset.is_fqdn_priority !== false,
    time_zone: preset.time_zone || base.time_zone,
    precheck_enabled:
      startOptions.precheck_enabled ?? (preset.preset_id ? false : true),
    precheck_profile_id: startOptions.precheck_profile_id || "",
    allowed_asset_groups: preset.allowed_asset_groups || [],
    allowed_targets_text: (preset.allowed_targets || []).join("\n"),
    max_groups_per_task: preset.max_groups_per_task || base.max_groups_per_task,
    max_active_tasks:
      preset.max_active_tasks === undefined
        ? base.max_active_tasks
        : preset.max_active_tasks,
    name_prefix: preset.name_prefix || "",
    role_ids: preset.role_ids || [],
    trigger_parameters: preset.trigger_parameters || null,
    denied_scan_settings: preset.denied_scan_settings || null,
  };
}

export function templateDraftToForm(result) {
  return {
    ...presetToForm(result?.draft),
    template_id: result?.draft?.template_id || null,
    template_warnings: result?.warnings || [],
  };
}

export function formToPayload(form) {
  const payload = {
    name: form.name.trim(),
    description: form.description.trim(),
    os_family: form.os_family,
    scope_id: form.scope_id,
    profile_id: form.profile_id,
    credential_id: form.credential_id || null,
    credential_transport: OS_TRANSPORT[form.os_family],
    agent_ids: form.agent_ids,
    host_discovery_enabled: form.host_discovery_enabled,
    host_discovery_profile_id: form.host_discovery_enabled
      ? form.host_discovery_profile_id || null
      : null,
    is_fqdn_priority: form.is_fqdn_priority,
    time_zone: form.time_zone.trim(),
    trigger_parameters: form.trigger_parameters,
    denied_scan_settings: form.denied_scan_settings,
    start_options: {
      precheck_enabled: form.precheck_enabled,
      precheck_profile_id: form.precheck_enabled
        ? form.precheck_profile_id || null
        : null,
    },
    allowed_asset_groups: form.allowed_asset_groups.map((group) => ({
      id: group.id,
    })),
    allowed_targets: parseTargets(form.allowed_targets_text),
    max_groups_per_task: Number(form.max_groups_per_task) || 1,
    max_active_tasks:
      form.max_active_tasks === "" || form.max_active_tasks === null
        ? null
        : Number(form.max_active_tasks),
    name_prefix: form.name_prefix.trim(),
    role_ids: form.role_ids,
  };
  if (form.preset_id) payload.expected_version = form.version;
  return payload;
}

export function presetFormProblems(form) {
  const problems = [];
  if (!form.name.trim()) problems.push("Укажите название пресета.");
  if (!form.scope_id) problems.push("Выберите область (scope).");
  if (!form.profile_id) problems.push("Выберите профиль сканирования.");
  if (!form.role_ids.length) problems.push("Выберите хотя бы одну роль.");
  if (
    !form.allowed_asset_groups.length &&
    !parseTargets(form.allowed_targets_text).length
  )
    problems.push(
      "Добавьте хотя бы одну разрешённую группу активов, IP-адрес или FQDN.",
    );
  if (!/^[+-]\d{2}:\d{2}$/.test(form.time_zone.trim()))
    problems.push("Часовой пояс задаётся в формате +05:00.");
  return problems;
}
