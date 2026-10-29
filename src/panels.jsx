import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";
import { api, createIdempotencyKey, downloadApiFile } from "./api/client.js";
import { recordFrontendEvent } from "./diagnostics.js";
import { useTaskForm } from "./features/tasks/useTaskForm.js";
import { severityLabel } from "./shared/labels.js";
import {
  filterOptions,
  formatCount,
  optionLabel,
  splitTokens,
} from "./shared/format.js";
import {
  ActionMenu,
  Button,
  ConfirmDialog,
  Disclosure,
  Field,
  Panel,
  Toggle,
  useDialogAccessibility,
} from "./shared/ui.jsx";
import {
  nextTableSort,
  SortableHeader,
  sortRows,
  useSortedRows,
  useTableSort,
} from "./shared/table.jsx";

const ACTIVE_PASSPORT_JOB_STATUSES = new Set([
  "queued",
  "running",
  "cancelling",
]);
const ACTIVE_ASSET_CARD_JOB_STATUSES = new Set([
  "queued",
  "running",
  "cancelling",
]);
const ACTIVE_SCAN_POSTPROCESS_STATUSES = new Set([
  "monitoring",
  "resolving",
  "processing",
  "waiting",
]);
const ACTIVE_BULK_REFRESH_STATUSES = new Set([
  "queued",
  "running",
  "cancelling",
  "recovering",
]);
const WEEKDAYS = [
  ["monday", "Пн"],
  ["tuesday", "Вт"],
  ["wednesday", "Ср"],
  ["thursday", "Чт"],
  ["friday", "Пт"],
  ["saturday", "Сб"],
  ["sunday", "Вс"],
];
const ASSET_CONFIG_TREE_LIMIT = 200;
const ASSET_CONFIG_DETAIL_LIMIT = 200;
const ASSET_VULNERABILITY_FINDING_LIMIT = 100;

function ConnectionPanel({
  connectionDraft: form,
  setConnectionDraft: setForm,
  session,
  setSession,
  lookupsError,
  lookupsUpdatedAt,
  refreshLookups,
  setLookups,
  busy,
  runBusy,
  showAlert,
  onNavigate,
}) {
  const update = (key, value) =>
    setForm((current) => ({ ...current, [key]: value }));

  const connect = () =>
    runBusy("session", async () => {
      const payload = Object.fromEntries(
        Object.entries(form).map(([key, value]) => [
          key,
          value === "" ? null : value,
        ]),
      );
      const result = await api("/api/session/connect", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setSession(result);
      setForm((current) => ({
        ...current,
        api_url: result.api_url || current.api_url,
        token_url: result.token_url || current.token_url,
        username: result.username ?? current.username,
        verify_tls: result.verify_tls ?? current.verify_tls,
      }));
      // Lookups load automatically once the session is marked connected.
      showAlert("Подключение к MP VM установлено.", "success");
      onNavigate?.("/vm");
    });

  const disconnect = () =>
    runBusy("session", async () => {
      const result = await api("/api/session/disconnect", { method: "POST" });
      setSession(result);
      setLookups({
        credentials: [],
        scopes: [],
        scanner_profiles: [],
        agents: [],
      });
      showAlert("Сессия MP VM отключена.", "info");
    });

  const loadLookups = () =>
    runBusy("lookups", async () => {
      await refreshLookups();
      showAlert("Справочники обновлены.", "success");
    });

  return (
    <Panel
      id="connection"
      action={
        session.connected ? (
          <Button
            variant="secondary"
            busy={busy.lookups}
            disabled={busy.session}
            onClick={loadLookups}
          >
            Обновить справочники
          </Button>
        ) : null
      }
    >
      {!session.connected && session.env_connect_error ? (
        <div className="query-state query-state--error" role="alert">
          <span>
            Автоподключение не выполнено: {session.env_connect_error}
          </span>
        </div>
      ) : null}
      <div className="form-grid form-grid--two connection-primary-fields">
        <Field label="Адрес MP VM">
          <input
            value={form.api_url}
            onChange={(event) => update("api_url", event.target.value)}
            placeholder="https://srv-siem.local"
          />
        </Field>
        <Field label="Логин">
          <input
            value={form.username}
            onChange={(event) => update("username", event.target.value)}
            autoComplete="username"
          />
        </Field>
        <Field label="Пароль">
          <input
            value={form.password}
            onChange={(event) => update("password", event.target.value)}
            type="password"
            autoComplete="current-password"
          />
          <small className="field-note">Хранится только в памяти.</small>
        </Field>
      </div>
      <Disclosure
        title="Дополнительная авторизация"
        meta={form.access_token ? "Токен задан" : null}
      >
        <div className="form-grid form-grid--two">
          <Field label="Адрес выдачи токена">
            <input
              value={form.token_url}
              onChange={(event) => update("token_url", event.target.value)}
              placeholder="https://srv-siem.local:3334/connect/token"
            />
          </Field>
          <Field label="ID клиента">
            <input
              value={form.client_id}
              onChange={(event) => update("client_id", event.target.value)}
            />
          </Field>
          <Field label="Секрет клиента">
            <input
              value={form.client_secret}
              onChange={(event) => update("client_secret", event.target.value)}
              type="password"
            />
          </Field>
          <Field label="Область доступа" wide>
            <input
              value={form.scope}
              onChange={(event) => update("scope", event.target.value)}
            />
          </Field>
          <Field label="Токен доступа" wide>
            <input
              value={form.access_token}
              onChange={(event) => update("access_token", event.target.value)}
              type="password"
              placeholder="Вместо логина и пароля"
            />
          </Field>
          <Toggle
            label="Проверять TLS-сертификат"
            checked={form.verify_tls}
            onChange={(value) => update("verify_tls", value)}
          />
        </div>
      </Disclosure>
      <div className="action-row">
        <Button busy={busy.session} onClick={connect}>
          Подключиться
        </Button>
        {session.connected ? (
          <Button variant="ghost" busy={busy.session} onClick={disconnect}>
            Отключиться
          </Button>
        ) : null}
        {session.connected && lookupsUpdatedAt ? (
          <div className="inline-metric">
            Справочники обновлены{" "}
            {new Date(lookupsUpdatedAt).toLocaleTimeString("ru-RU", {
              hour: "2-digit",
              minute: "2-digit",
            })}
          </div>
        ) : null}
        {session.connected && lookupsError ? (
          <div className="query-state query-state--error" role="alert">
            <span>
              Не удалось обновить справочники:{" "}
              {lookupsError.operatorMessage || lookupsError.message}
            </span>
          </div>
        ) : null}
        {session.connected ? (
          <div className="mini-state mini-state--ok">{session.api_url}</div>
        ) : null}
      </div>
    </Panel>
  );
}

function ProfileSelect({
  value,
  onChange,
  profiles,
  emptyLabel,
  searchLabel = "Поиск профиля по имени или ID",
}) {
  const [query, setQuery] = useState("");
  const normalizedQuery = query.trim().toLocaleLowerCase("ru-RU");
  const filteredProfiles = useMemo(
    () => filterOptions(profiles, normalizedQuery),
    [normalizedQuery, profiles],
  );
  const selectedProfile = useMemo(
    () =>
      profiles.find((item) => String(item.id || "") === String(value || "")),
    [profiles, value],
  );
  const visibleProfiles = useMemo(() => {
    if (
      !selectedProfile ||
      filteredProfiles.some((item) => item.id === selectedProfile.id)
    )
      return filteredProfiles;
    return [selectedProfile, ...filteredProfiles];
  }, [filteredProfiles, selectedProfile]);

  return (
    <div className="profile-select">
      <input
        type="search"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        placeholder={searchLabel}
        aria-label={searchLabel}
        autoComplete="off"
      />
      <select
        value={value}
        aria-label={`${searchLabel}: выбор`}
        onChange={(event) => {
          onChange(event.target.value);
          setQuery("");
        }}
      >
        <option value="">{emptyLabel}</option>
        {visibleProfiles.map((item) => (
          <option value={item.id || ""} key={item.id || item.name}>
            {optionLabel(item, visibleProfiles)}
          </option>
        ))}
        {normalizedQuery && !filteredProfiles.length ? (
          <option disabled>Профили не найдены</option>
        ) : null}
      </select>
      {normalizedQuery ? (
        <small>Найдено: {filteredProfiles.length}</small>
      ) : null}
    </div>
  );
}

function TaskBuilderPanel({
  defaults,
  lookups,
  selectedTask,
  selectedTaskId,
  setSelectedTaskId,
  refreshTasks,
  busy,
  runBusy,
  showAlert,
  session,
  systemStatus,
  copyTask = null,
  onCancel,
  onSaved,
}) {
  const { form, setForm } = useTaskForm({
    defaults,
    selectedTask,
    selectedTaskId,
    setSelectedTaskId,
    copyTask,
  });
  const scopeOptions = useMemo(
    () => (Array.isArray(lookups.scopes) ? lookups.scopes : []),
    [lookups.scopes],
  );
  const scannerAgents = useMemo(
    () => (Array.isArray(lookups.agents) ? lookups.agents : []),
    [lookups.agents],
  );
  const selectedAgentIds = splitTokens(form.agent_ids);
  const selectedAgentSet = new Set(selectedAgentIds);
  const agentIdsInLookup = new Set(
    scannerAgents.map((item) => String(item.id || "")),
  );
  const selectableAgents = [
    ...scannerAgents,
    ...selectedAgentIds
      .filter((id) => !agentIdsInLookup.has(id))
      .map((id) => ({ id, name: id })),
  ];

  useEffect(() => {
    if (selectedTaskId || copyTask) return;
    const onlyScope = scopeOptions.length === 1 ? scopeOptions[0] : null;
    const onlyAgent = scannerAgents.length === 1 ? scannerAgents[0] : null;
    if (!onlyScope && !onlyAgent) return;
    setForm((current) => {
      const scopeId = onlyScope?.id && !current.scope_id
        ? String(onlyScope.id)
        : current.scope_id;
      const agentIds = onlyAgent?.id && !current.agent_ids?.trim()
        ? String(onlyAgent.id)
        : current.agent_ids;
      if (scopeId === current.scope_id && agentIds === current.agent_ids) {
        return current;
      }
      return { ...current, scope_id: scopeId, agent_ids: agentIds };
    });
  }, [copyTask, scannerAgents, scopeOptions, selectedTaskId, setForm]);

  const update = (key, value) =>
    setForm((current) => ({ ...current, [key]: value }));
  const payload = () => ({
    name: form.name.trim(),
    description: form.description.trim(),
    scope_id: form.scope_id,
    profile_id: form.profile_id,
    credential_id: form.credential_id || null,
    credential_transport: form.credential_transport,
    host_discovery_profile_id: form.host_discovery_profile_id || null,
    include_targets: splitTokens(form.include_targets),
    exclude_targets: splitTokens(form.exclude_targets),
    agent_ids: splitTokens(form.agent_ids),
    host_discovery_enabled: form.host_discovery_enabled,
    is_fqdn_priority: form.is_fqdn_priority,
    time_zone: form.time_zone || "+05:00",
    trigger_parameters: form.schedule_enabled
      ? {
          isEnabled: true,
          fromDate: form.schedule_from_date
            ? new Date(form.schedule_from_date).toISOString()
            : new Date().toISOString(),
          ...(form.schedule_to_date
            ? { toDate: new Date(form.schedule_to_date).toISOString() }
            : {}),
          timeZone: form.time_zone || "+05:00",
          type: form.schedule_type,
          ...(form.schedule_type === "Daily" || form.schedule_type === "Weekly" || form.schedule_type === "Fortnightly"
            ? { atTime: timeWithSeconds(form.schedule_at_time) }
            : {}),
          ...(form.schedule_type === "Weekly" || form.schedule_type === "Fortnightly"
            ? { daysOfWeek: form.schedule_days_of_week }
            : {}),
          ...(form.schedule_type === "Periodic"
            ? { interval: Number(form.schedule_interval), intervalUnit: form.schedule_interval_unit }
            : {}),
          ...(form.schedule_type === "RepeatableDaily"
            ? { startTime: timeWithSeconds(form.schedule_start_time), endTime: timeWithSeconds(form.schedule_end_time), interval: Number(form.schedule_interval), intervalUnit: "Minutes" }
            : {}),
          ...(form.schedule_type === "Monthly"
            ? { dayOfMonth: Number(form.schedule_day_of_month), atTime: timeWithSeconds(form.schedule_at_time) }
            : {}),
          ...(form.schedule_type === "CronScheduler"
            ? { cronExpression: form.schedule_cron_expression }
            : {}),
        }
      : null,
    denied_scan_settings: form.denied_scan_enabled
      ? {
          isEnabled: true,
          periods: form.denied_periods.map((period) => ({
            ...period,
            fromTime: timeWithSeconds(period.fromTime),
            toTime: timeWithSeconds(period.toTime),
            daysOfWeek: period.daysOfWeek,
            timeZone: period.timeZone || form.time_zone || "+05:00",
          })),
        }
      : null,
  });
  const startPayload = () => ({
    precheck_enabled: form.precheck_enabled,
    precheck_profile_id: form.precheck_profile_id || null,
    precheck_timeout_minutes: Number(form.precheck_timeout_minutes || 10),
    precheck_max_runtime_minutes: Number(
      form.precheck_max_runtime_minutes || 0,
    ),
    precheck_poll_seconds: Number(form.precheck_poll_seconds || 10),
    wait_for_finish: false,
    task_timeout_minutes: Number(form.task_timeout_minutes || 120),
    task_poll_seconds: Number(form.task_poll_seconds || 15),
    require_clean_jobs: form.require_clean_jobs,
  });

  const preflight = [
    {
      label: "База данных",
      ok: systemStatus?.components?.database?.state === "ok",
      detail: "Нужна для истории запусков",
    },
    {
      label: "Сессия MP VM",
      ok: Boolean(session?.connected),
      detail: "Подключитесь к MP VM",
    },
    {
      label: "Справочники",
      ok: Boolean(lookups.scopes.length && lookups.scanner_profiles.length),
      detail: "Обновите справочники в разделе «Подключение»",
    },
    {
      label: "Инфраструктура и профиль",
      ok: Boolean(form.scope_id && form.profile_id),
      detail: "Заполните обязательные параметры",
    },
    {
      label: "Цели сканирования",
      ok: splitTokens(form.include_targets).length > 0,
      detail: "Добавьте хотя бы одну цель",
    },
  ];
  const preflightReady = preflight.every((item) => item.ok);

  const createTask = () =>
    runBusy("createTask", async () => {
      const result = await api("/api/scanner-tasks", {
        method: "POST",
        body: JSON.stringify(payload()),
      });
      setSelectedTaskId(result.mp_task_id);
      showAlert(`Задача создана: ${result.mp_task_id}`, "success");
      await refreshTasks();
      onSaved?.(result);
      return result;
    });

  const updateTask = () =>
    runBusy("updateTask", async () => {
      if (!selectedTaskId) throw new Error("Сначала выберите задачу.");
      const result = await api(`/api/scanner-tasks/${encodeURIComponent(selectedTaskId)}`, {
        method: "PUT",
        body: JSON.stringify(payload()),
      });
      showAlert(`Задача изменена: ${selectedTaskId}`, "success");
      await refreshTasks();
      onSaved?.(result);
      return result;
    });

  const saveAndRun = () =>
    runBusy("saveAndRunTask", async () => {
      let taskId = selectedTaskId;
      if (taskId) {
        await api(`/api/scanner-tasks/${encodeURIComponent(taskId)}`, {
          method: "PUT",
          body: JSON.stringify(payload()),
        });
      } else {
        const created = await api("/api/scanner-tasks", {
          method: "POST",
          body: JSON.stringify(payload()),
        });
        taskId = created.mp_task_id;
        setSelectedTaskId(taskId);
      }
      const result = await api(`/api/scanner-tasks/${encodeURIComponent(taskId)}/start`, {
        method: "POST",
        headers: { "X-Idempotency-Key": createIdempotencyKey("scan-start") },
        body: JSON.stringify(startPayload()),
      });
      showAlert(startSuccessText(result), "success");
      await refreshTasks();
      onSaved?.({ mp_task_id: taskId });
      return result;
    });

  return (
    <Panel
      id="task-builder"
      title={copyTask ? "Копирование задачи" : selectedTaskId ? "Изменение задачи" : "Новая задача"}
      className="task-builder task-builder--editor"
    >
      <div className="form-grid form-grid--two task-primary-fields">
        <Field label="Название задачи">
          <input
            value={form.name}
            onChange={(event) => update("name", event.target.value)}
            placeholder="Аудит Windows 10.0.0.0/24"
          />
        </Field>
        <Field label="Инфраструктура">
          <select
            value={form.scope_id}
            onChange={(event) => update("scope_id", event.target.value)}
          >
            <option value="">Выберите инфраструктуру</option>
            {lookups.scopes.map((item) => (
              <option value={item.id || ""} key={item.id || item.name}>
                {optionLabel(item, lookups.scopes)}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Профиль сканирования">
          <ProfileSelect
            value={form.profile_id}
            onChange={(value) => {
              const profile = lookups.scanner_profiles.find(
                (item) => String(item.id || "") === String(value || ""),
              );
              const profileText = JSON.stringify(profile || {}).toLowerCase();
              setForm((current) => ({
                ...current,
                profile_id: value,
                credential_transport: /linux|unix|ssh/.test(profileText)
                  ? "ssh"
                  : /windows|wmi/.test(profileText)
                    ? "windows"
                    : current.credential_transport,
              }));
            }}
            profiles={lookups.scanner_profiles}
            emptyLabel="Выберите профиль"
          />
        </Field>
        <Field label="Цели сканирования">
          <textarea
            rows={4}
            value={form.include_targets}
            onChange={(event) => update("include_targets", event.target.value)}
            placeholder="10.104.103.0/24"
          />
        </Field>
      </div>

      <Disclosure
        title="Описание и охват"
        meta={
          splitTokens(form.exclude_targets).length
            ? "Есть исключения"
            : "По умолчанию"
        }
      >
        <div className="form-grid form-grid--two">
          <Field label="Описание" wide>
            <input
              value={form.description}
              onChange={(event) => update("description", event.target.value)}
            />
          </Field>
          <Field label="Исключить цели">
            <textarea
              rows={3}
              value={form.exclude_targets}
              onChange={(event) =>
                update("exclude_targets", event.target.value)
              }
            />
          </Field>
          <Field label="Часовой пояс">
            <input
              value={form.time_zone}
              onChange={(event) => update("time_zone", event.target.value)}
            />
          </Field>
          <fieldset className="task-agent-picker">
            <legend>Коллекторы / agents</legend>
            {selectableAgents.length ? (
              <div className="task-agent-picker__options">
                {selectableAgents.map((agent) => {
                  const id = String(agent.id || "");
                  return (
                    <label key={id} className="task-agent-option">
                      <input
                        type="checkbox"
                        checked={selectedAgentSet.has(id)}
                        onChange={() => {
                          const next = selectedAgentSet.has(id)
                            ? selectedAgentIds.filter((item) => item !== id)
                            : [...selectedAgentIds, id];
                          update("agent_ids", next.join("\n"));
                        }}
                      />
                      <span>{optionLabel(agent, scannerAgents)}</span>
                      <small>{id}</small>
                    </label>
                  );
                })}
              </div>
            ) : (
              <div className="task-agent-picker__empty">
                <span>Список коллекторов пока пуст. Можно указать UUID вручную.</span>
                <textarea
                  aria-label="Коллекторы"
                  rows={2}
                  value={form.agent_ids}
                  onChange={(event) => update("agent_ids", event.target.value)}
                  placeholder="ID коллекторов через запятую"
                />
              </div>
            )}
          </fieldset>
        </div>
      </Disclosure>

      <section className="task-settings-card" aria-labelledby="task-schedule-title">
        <div className="task-settings-card__header">
          <div>
            <h3 id="task-schedule-title">Расписание</h3>
            <p>Автоматический запуск задачи по часовому поясу</p>
          </div>
          <Toggle label="Включить" checked={form.schedule_enabled} onChange={(value) => update("schedule_enabled", value)} />
        </div>
        {form.schedule_enabled ? (
          <div className="form-grid form-grid--two">
            <Field label="Тип расписания">
              <select value={form.schedule_type} onChange={(event) => update("schedule_type", event.target.value)}>
                <option value="Daily">Ежедневно</option>
                <option value="Periodic">Периодически</option>
                <option value="RepeatableDaily">Повторять в течение дня</option>
                <option value="Weekly">Еженедельно</option>
                <option value="Fortnightly">Раз в две недели</option>
                <option value="Monthly">Ежемесячно</option>
                <option value="CronScheduler">Cron</option>
              </select>
            </Field>
            <Field label="Начать с">
              <input aria-label="Начать расписание с" type="datetime-local" value={form.schedule_from_date} onChange={(event) => update("schedule_from_date", event.target.value)} />
            </Field>
            <Field label="Завершить после">
              <input aria-label="Завершить расписание после" type="datetime-local" value={form.schedule_to_date} onChange={(event) => update("schedule_to_date", event.target.value)} />
            </Field>
            {["Daily", "Weekly", "Fortnightly", "Monthly"].includes(form.schedule_type) ? (
              <Field label="Время запуска"><input type="time" value={form.schedule_at_time} onChange={(event) => update("schedule_at_time", event.target.value)} /></Field>
            ) : null}
            {["Weekly", "Fortnightly"].includes(form.schedule_type) ? (
              <fieldset className="task-weekday-picker"><legend>Дни недели</legend>{WEEKDAYS.map(([value, label]) => (
                <label key={value}><input type="checkbox" checked={form.schedule_days_of_week.includes(value)} onChange={(event) => update("schedule_days_of_week", event.target.checked ? [...form.schedule_days_of_week, value] : form.schedule_days_of_week.filter((day) => day !== value))} /> {label}</label>
              ))}</fieldset>
            ) : null}
            {["Periodic", "RepeatableDaily"].includes(form.schedule_type) ? (
              <Field label="Интервал"><input type="number" min="1" value={form.schedule_interval} onChange={(event) => update("schedule_interval", event.target.value)} /></Field>
            ) : null}
            {form.schedule_type === "Periodic" ? (
              <Field label="Единица интервала"><select value={form.schedule_interval_unit} onChange={(event) => update("schedule_interval_unit", event.target.value)}><option value="Minutes">Минуты</option><option value="Hours">Часы</option><option value="Days">Дни</option></select></Field>
            ) : null}
            {form.schedule_type === "RepeatableDaily" ? (
              <><Field label="Повторять с"><input type="time" value={form.schedule_start_time} onChange={(event) => update("schedule_start_time", event.target.value)} /></Field><Field label="Повторять до"><input type="time" value={form.schedule_end_time} onChange={(event) => update("schedule_end_time", event.target.value)} /></Field></>
            ) : null}
            {form.schedule_type === "Monthly" ? (
              <Field label="День месяца"><input type="number" min="1" max="31" value={form.schedule_day_of_month} onChange={(event) => update("schedule_day_of_month", event.target.value)} /></Field>
            ) : null}
            {form.schedule_type === "CronScheduler" ? (
              <Field label="Cron"><input value={form.schedule_cron_expression} onChange={(event) => update("schedule_cron_expression", event.target.value)} /></Field>
            ) : null}
          </div>
        ) : null}
      </section>

      <section className="task-settings-card" aria-labelledby="task-denied-title">
        <div className="task-settings-card__header">
          <div>
            <h3 id="task-denied-title">Запрещённое время сканирования</h3>
            <p>Периоды, в которые MP VM не будет выполнять сканирование</p>
          </div>
          <Toggle label="Включить" checked={form.denied_scan_enabled} onChange={(value) => {
            update("denied_scan_enabled", value);
            if (value && !form.denied_periods.length) update("denied_periods", [{ daysOfWeek: ["saturday", "sunday"], timeZone: form.time_zone, isAllDay: false, fromTime: "00:00:00", toTime: "06:00:00" }]);
          }} />
        </div>
        {form.denied_scan_enabled ? (
          <div className="task-denied-periods">
            {form.denied_periods.map((period, index) => (
              <div className="task-denied-period" key={`denied-${index}`}>
                <div className="task-settings-card__header"><strong>Период {index + 1}</strong><Button variant="ghost" onClick={() => update("denied_periods", form.denied_periods.filter((_, periodIndex) => periodIndex !== index))}>Удалить</Button></div>
                <fieldset className="task-weekday-picker"><legend>Дни недели</legend>{WEEKDAYS.map(([value, label]) => (
                  <label key={value}><input type="checkbox" checked={period.daysOfWeek.includes(value)} onChange={(event) => update("denied_periods", form.denied_periods.map((entry, periodIndex) => periodIndex !== index ? entry : { ...entry, daysOfWeek: event.target.checked ? [...entry.daysOfWeek, value] : entry.daysOfWeek.filter((day) => day !== value) }))} /> {label}</label>
                ))}</fieldset>
                <Toggle label="Весь день" checked={period.isAllDay} onChange={(value) => update("denied_periods", form.denied_periods.map((entry, periodIndex) => periodIndex === index ? { ...entry, isAllDay: value } : entry))} />
                {!period.isAllDay ? <div className="form-grid form-grid--two"><Field label="С"><input type="time" value={period.fromTime} onChange={(event) => update("denied_periods", form.denied_periods.map((entry, periodIndex) => periodIndex === index ? { ...entry, fromTime: event.target.value } : entry))} /></Field><Field label="По"><input type="time" value={period.toTime} onChange={(event) => update("denied_periods", form.denied_periods.map((entry, periodIndex) => periodIndex === index ? { ...entry, toTime: event.target.value } : entry))} /></Field></div> : null}
              </div>
            ))}
            <Button variant="secondary" onClick={() => update("denied_periods", [...form.denied_periods, { daysOfWeek: ["saturday", "sunday"], timeZone: form.time_zone, isAllDay: false, fromTime: "00:00:00", toTime: "06:00:00" }])}>Добавить период</Button>
          </div>
        ) : null}
      </section>

      <Disclosure
        title="Подключение и обнаружение"
        meta={
          form.host_discovery_enabled ? "Обнаружение хостов" : "Стандартно"
        }
      >
        <div className="form-grid form-grid--two">
          <Field label="Тип подключения">
            <select
              value={form.credential_transport}
              onChange={(event) =>
                update("credential_transport", event.target.value)
              }
            >
              <option value="windows">Windows (WMI/RPC)</option>
              <option value="ssh">Linux/Unix (SSH + sudo)</option>
            </select>
          </Field>
          <Field label="Учётная запись">
            <select
              value={form.credential_id}
              onChange={(event) => update("credential_id", event.target.value)}
            >
              <option value="">Из профиля</option>
              {lookups.credentials.map((item) => (
                <option value={item.id || ""} key={item.id || item.name}>
                  {optionLabel(item, lookups.credentials)}
                </option>
              ))}
            </select>
          </Field>
          <Toggle
            label="Обнаружение хостов"
            checked={form.host_discovery_enabled}
            onChange={(value) => update("host_discovery_enabled", value)}
          />
          <Field label="Профиль обнаружения хостов">
            <ProfileSelect
              value={form.host_discovery_profile_id}
              onChange={(value) => update("host_discovery_profile_id", value)}
              profiles={lookups.scanner_profiles}
              emptyLabel="Без профиля"
              searchLabel="Поиск профиля обнаружения"
            />
          </Field>
          <Toggle
            label="Приоритет FQDN"
            checked={form.is_fqdn_priority}
            onChange={(value) => update("is_fqdn_priority", value)}
          />
        </div>
      </Disclosure>

      <Disclosure
        title="Проверка доступности и таймеры"
        meta={form.precheck_enabled ? "Проверка включена" : "Выключено"}
      >
        <div className="form-grid form-grid--two">
          <Toggle
            label="Проверить доступность хостов перед запуском"
            checked={form.precheck_enabled}
            onChange={(value) => update("precheck_enabled", value)}
          />
          <div className="mini-state mini-state--ok">
            Мониторинг, карточки и удаление выполняются в фоне
          </div>
          <Field label="Профиль проверки">
            <ProfileSelect
              value={form.precheck_profile_id}
              onChange={(value) => update("precheck_profile_id", value)}
              profiles={lookups.scanner_profiles}
              emptyLabel="Использовать профиль основной задачи"
              searchLabel="Поиск Precheck-профиля"
            />
          </Field>
          <Field label="Таймаут задачи, минут">
            <input
              type="number"
              min="1"
              value={form.task_timeout_minutes}
              onChange={(event) =>
                update("task_timeout_minutes", event.target.value)
              }
            />
          </Field>
          <Field label="Таймаут проверки, минут">
            <input
              type="number"
              min="1"
              value={form.precheck_timeout_minutes}
              onChange={(event) =>
                update("precheck_timeout_minutes", event.target.value)
              }
            />
          </Field>
          <Field label="Остановить проверку через, минут">
            <input
              type="number"
              min="0"
              value={form.precheck_max_runtime_minutes}
              onChange={(event) =>
                update("precheck_max_runtime_minutes", event.target.value)
              }
            />
          </Field>
          <Field label="Опрос проверки, секунд">
            <input
              type="number"
              min="1"
              value={form.precheck_poll_seconds}
              onChange={(event) =>
                update("precheck_poll_seconds", event.target.value)
              }
            />
          </Field>
          <Field label="Опрос задачи, секунд">
            <input
              type="number"
              min="1"
              value={form.task_poll_seconds}
              onChange={(event) =>
                update("task_poll_seconds", event.target.value)
              }
            />
          </Field>
          <Toggle
            label="Строгий режим: не запускать при активных процессах и считать ошибки заданий сбоем"
            checked={form.require_clean_jobs}
            onChange={(value) => update("require_clean_jobs", value)}
          />
        </div>
      </Disclosure>

      <Disclosure
        title="Готовность к запуску"
        meta={preflightReady ? "Готово" : "Есть замечания"}
        defaultOpen={!preflightReady}
      >
        <section
          className={`task-preflight ${preflightReady ? "task-preflight--ready" : ""}`}
        >
          <ul>
            {preflight.map((item) => (
              <li className={item.ok ? "is-ok" : "is-error"} key={item.label}>
                <span>{item.ok ? "✓" : "!"}</span>
                <div>
                  <strong>{item.label}</strong>
                  <small>{item.ok ? "Готово" : item.detail}</small>
                </div>
              </li>
            ))}
          </ul>
        </section>
      </Disclosure>

      <footer className="task-editor-footer">
        <Button busy={selectedTaskId ? busy.updateTask : busy.createTask} onClick={selectedTaskId ? updateTask : createTask}>{selectedTaskId ? "Сохранить" : "Создать задачу"}</Button>
        <Button variant="secondary" disabled={!preflightReady} busy={busy.saveAndRunTask} onClick={saveAndRun}>Сохранить и запустить</Button>
        <Button variant="ghost" onClick={onCancel}>Отмена</Button>
      </footer>
    </Panel>
  );
}

function startSuccessText(result) {
  const precheck = result.precheck?.successful_target_count;
  const precheckText =
    typeof precheck === "number" ? ` Доступно хостов: ${precheck}.` : "";
  if (result.status === "finished")
    return `Задача завершена успешно.${precheckText}`;
  if (result.status === "timeout_stop_requested")
    return `Таймер истёк, отправлена остановка задачи.${precheckText}`;
  if (result.status === "precheck_failed")
    return "Проверка доступности не нашла ни одного доступного хоста.";
  if (result.status === "validation_failed")
    return `Задача не прошла проверку: ${result.error || "причина не указана"}`;
  if (result.postprocess_run_id)
    return `Сканирование запущено. Фоновая обработка: ${result.postprocess_run_id}.${precheckText}`;
  return `Запуск запрошен.${precheckText}`;
}

function timeWithSeconds(value) {
  return typeof value === "string" && /^\d{2}:\d{2}$/.test(value)
    ? `${value}:00`
    : value;
}

function TaskPostprocessPanel({ run }) {
  const items = Array.isArray(run.items) ? run.items : [];
  const [tableSort, toggleTableSort] = useTableSort();
  const sortedItems = useSortedRows(items, tableSort);
  return (
    <section className="task-postprocess" aria-live="polite">
      <div className="task-postprocess__header">
        <div>
          <span className="eyebrow">Фоновая обработка</span>
          <h3>{postprocessStageLabel(run.stage)}</h3>
          {run.message || run.error ? <p>{run.message || run.error}</p> : null}
          {run.error ? (
            <p className="error-text">Исходная причина: {run.error}</p>
          ) : null}
        </div>
        <div className="task-postprocess__metrics">
          <span>
            Задания{" "}
            <strong>
              {formatCount(run.successful_job_count)} /{" "}
              {formatCount(run.total_job_count)}
            </strong>
          </span>
          <span>
            Активы{" "}
            <strong>
              {formatCount(run.completed_count)} /{" "}
              {formatCount(run.asset_count)}
            </strong>
          </span>
          <span>
            Ошибки <strong>{formatCount(run.failed_count)}</strong>
          </span>
        </div>
      </div>
      {items.length ? (
        <div className="mpvm-table-shell">
          <table className="postprocess-item-table">
            <thead>
              <tr>
                <SortableHeader
                  column="target"
                  sort={tableSort}
                  onSort={toggleTableSort}
                >
                  Цель
                </SortableHeader>
                <SortableHeader
                  column="asset_id"
                  sort={tableSort}
                  onSort={toggleTableSort}
                >
                  ID актива
                </SortableHeader>
                <SortableHeader
                  column="mp_job_id"
                  sort={tableSort}
                  onSort={toggleTableSort}
                >
                  Задание
                </SortableHeader>
                <SortableHeader
                  column="build_job_id"
                  sort={tableSort}
                  onSort={toggleTableSort}
                >
                  Карточка
                </SortableHeader>
                <SortableHeader
                  column="removal_operation_id"
                  sort={tableSort}
                  onSort={toggleTableSort}
                >
                  Удаление MP VM
                </SortableHeader>
                <SortableHeader
                  column="status"
                  sort={tableSort}
                  onSort={toggleTableSort}
                >
                  Статус / ошибка
                </SortableHeader>
              </tr>
            </thead>
            <tbody>
              {sortedItems.map((item) => (
                <tr key={item.id || item.item_key}>
                  <td>{item.target || "—"}</td>
                  <td className="mono-cell">{item.asset_id || "—"}</td>
                  <td className="mono-cell">{item.mp_job_id || "—"}</td>
                  <td className="mono-cell">
                    {item.build_job_id || postprocessCardLabel(item.status)}
                  </td>
                  <td className="mono-cell">
                    {item.removal_operation_id ||
                      postprocessRemovalLabel(item.status)}
                  </td>
                  <td>
                    <TaskStatus status={item.status} />
                    {item.error ? (
                      <small className="error-text">{item.error}</small>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-cell">
          Ожидаем завершения сканирования и появления успешных устройств.
        </div>
      )}
    </section>
  );
}

function taskStatusLabel(status) {
  return (
    {
      pending: "Ожидает",
      building: "Сборка карточки",
      card_saved: "Карточка сохранена",
      asset_refresh_created: "Обновление карточки запущено",
      deleted: "Удалён из MP VM",
      removal_failed: "Ошибка удаления",
      queued: "В очереди",
      running: "Выполняется",
      started: "Запущена",
      finished: "Завершена",
      failed: "Ошибка",
      timeout: "Истекло время",
    }[String(status).toLowerCase()] || postprocessStageLabel(status)
  );
}

function postprocessStageLabel(stage) {
  const labels = {
    waiting_for_run: "Ожидание запуска MP VM",
    scanning: "Сканирование выполняется",
    watching_jobs: "Ожидание заданий сканирования",
    scan_finished: "Сканирование завершено",
    scanner_start_failed: "Не удалось подтвердить запуск сканирования",
    resolving_assets: "Поиск просканированных активов",
    building_cards: "Создание карточек и удаление активов",
    completed: "Обработка завершена",
    completed_with_errors: "Обработка завершена с ошибками",
    failed: "Ошибка фоновой обработки",
  };
  return labels[stage] || stage || "Фоновая обработка";
}

function postprocessCardLabel(status) {
  if (["queued", "resolution_failed"].includes(status)) return "—";
  if (status === "building") return "собирается";
  if (status === "build_failed") return "ошибка";
  return "сохранена";
}

function postprocessRemovalLabel(status) {
  if (["deleting", "card_saved"].includes(status)) return "выполняется";
  if (status === "completed") return "удалён";
  if (status === "removal_failed") return "ошибка";
  return "—";
}

function TaskStatus({ status }) {
  const normalized = String(status || "").toLowerCase();
  let kind = "neutral";
  let icon = "•";
  if (
    [
      "started",
      "precheck_started",
      "monitoring",
      "resolving",
      "processing",
      "building",
      "deleting",
      "queued",
      "waiting",
    ].some((item) => normalized.includes(item))
  ) {
    kind = "running";
    icon = "◔";
  } else if (normalized.includes("with_errors")) {
    kind = "danger";
    icon = "⚠";
  } else if (
    ["finished", "valid", "created", "updated", "completed", "card_saved"].some(
      (item) => normalized.includes(item),
    )
  ) {
    kind = "success";
    icon = "✓";
  } else if (
    ["failed", "timeout", "stop", "deleted"].some((item) =>
      normalized.includes(item),
    )
  ) {
    kind = "danger";
    icon = "⚠";
  }
  return (
    <span className={`task-status task-status--${kind}`}>
      <span>{icon}</span>
      {status ? taskStatusLabel(status) : "Неизвестно"}
    </span>
  );
}

function formatList(items) {
  if (!items || !items.length) return "—";
  const values = Array.isArray(items) ? items : [items];
  const text = values.filter(Boolean).join(", ");
  return text || "—";
}

function formatDateTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat("ru-RU", {
    day: "numeric",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function ExportPanel({
  defaults,
  busy,
  runBusy,
  refreshAssets,
  showAlert,
  currentUser,
}) {
  const permissions = new Set(currentUser?.permissions || []);
  const canManageExports = permissions.has("imports_exports.manage");
  const [form, setForm] = useState({
    pdql: "",
    utc_offset: "+05:00",
    group_ids: "",
    asset_ids: "",
    report_asset_ids: "",
    include_nested_groups: true,
    import_results: true,
    delete_assets_after_export: false,
  });
  const [result, setResult] = useState("");
  const [importBusy, setImportBusy] = useState(false);
  const [reportAssetSearch, setReportAssetSearch] = useState("");
  const [reportAssetOptions, setReportAssetOptions] = useState([]);
  const [selectedReportAssetId, setSelectedReportAssetId] = useState("");
  const [reportAssetLookupBusy, setReportAssetLookupBusy] = useState(false);

  useEffect(() => {
    if (!defaults) return;
    setForm((value) => ({
      ...value,
      pdql: value.pdql || defaults.software_vuln_pdql || "",
      utc_offset: value.utc_offset || defaults.utc_offset || "+05:00",
    }));
  }, [defaults]);

  useEffect(() => {
    const query = reportAssetSearch.trim();
    if (!query) {
      setReportAssetOptions([]);
      setReportAssetLookupBusy(false);
      return undefined;
    }
    let alive = true;
    const timer = window.setTimeout(async () => {
      setReportAssetLookupBusy(true);
      try {
        const response = await api(
          `/api/asset-cards/local?q=${encodeURIComponent(query)}&limit=20&sort_by=display_name&sort_dir=asc`,
        );
        if (alive) setReportAssetOptions(response.rows || []);
      } catch {
        if (alive) setReportAssetOptions([]);
      } finally {
        if (alive) setReportAssetLookupBusy(false);
      }
    }, 250);
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [reportAssetSearch]);

  const update = (key, value) =>
    setForm((current) => ({ ...current, [key]: value }));
  const runExport = () =>
    runBusy("export", async () => {
      const payload = {
        pdql: form.pdql,
        utc_offset: form.utc_offset || null,
        group_ids: splitTokens(form.group_ids),
        asset_ids: splitTokens(form.asset_ids),
        include_nested_groups: form.include_nested_groups,
        import_results: form.import_results,
        delete_assets_after_export: form.delete_assets_after_export,
      };
      const response = await api("/api/exports/pdql", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setResult(JSON.stringify(response, null, 2));
      showAlert("Экспорт завершён.", "success");
      await refreshAssets();
    });

  const importCsvFile = async (event) => {
    const input = event.target;
    const file = input.files?.[0];
    if (!file) return;
    const body = new FormData();
    body.append("file", file);
    setImportBusy(true);
    try {
      const response = await api("/api/import/csv-file", {
        method: "POST",
        body,
      });
      setResult(JSON.stringify(response, null, 2));
      showAlert(`CSV загружен: ${file.name}`, "success");
      await refreshAssets();
    } catch (error) {
      showAlert(error.operatorMessage || error.message, "error");
    } finally {
      setImportBusy(false);
      input.value = "";
    }
  };

  const downloadVulnerabilityReport = (reportType) =>
    runBusy(`report-${reportType}`, async () => {
      const report = await downloadApiFile(
        `/api/reports/vulnerabilities/${reportType}/csv`,
        {
          method: "POST",
          body: JSON.stringify({
            asset_ids: [...new Set(splitTokens(form.report_asset_ids))],
          }),
        },
      );
      showAlert(`CSV-отчёт сформирован: ${report.filename}`, "success");
    });

  const downloadVulnerabilityXlsx = () =>
    runBusy("report-xlsx", async () => {
      const report = await downloadApiFile("/api/reports/vulnerabilities/xlsx", {
        method: "POST",
        body: JSON.stringify({ asset_id: selectedReportAssetId }),
      });
      showAlert(`XLSX-отчёт сформирован: ${report.filename}`, "success");
    });

  return (
    <>
      <Panel id="export-reports" title="Отчёты по уязвимостям">
        <div className="form-grid form-grid--two">
          <Field label="Актив для XLSX">
            <input
              aria-label="Поиск актива для XLSX-отчёта"
              value={reportAssetSearch}
              onChange={(event) => {
                setReportAssetSearch(event.target.value);
                setSelectedReportAssetId("");
              }}
              placeholder="IP, имя хоста или ID"
            />
            {reportAssetLookupBusy ? (
              <small className="muted-text">Поиск…</small>
            ) : null}
            {reportAssetOptions.length ? (
              <div
                className="report-asset-options"
                role="listbox"
                aria-label="Найденные активы"
              >
                {reportAssetOptions.map((asset) => {
                  const label =
                    asset.display_name || asset.hostname || asset.asset_id;
                  const details = [asset.ip_address, asset.hostname]
                    .filter(Boolean)
                    .join(" · ");
                  return (
                    <button
                      type="button"
                      role="option"
                      aria-selected={selectedReportAssetId === asset.asset_id}
                      className={`report-asset-option${selectedReportAssetId === asset.asset_id ? " is-selected" : ""}`}
                      key={asset.asset_id}
                      title={asset.asset_id}
                      onClick={() => {
                        setSelectedReportAssetId(asset.asset_id);
                        setReportAssetSearch(label);
                        setReportAssetOptions([]);
                      }}
                    >
                      <strong>{label}</strong>
                      <span>{details}</span>
                    </button>
                  );
                })}
              </div>
            ) : null}
          </Field>
          <Field label="ID активов для CSV">
            <textarea
              aria-label="Asset ID для отчёта"
              rows={2}
              value={form.report_asset_ids}
              onChange={(event) => update("report_asset_ids", event.target.value)}
              placeholder="ID через запятую"
            />
          </Field>
        </div>
        <div className="action-row report-downloads">
          <span className="selection-count">Скачать:</span>
          <Button
            variant="secondary"
            busy={busy["report-xlsx"]}
            disabled={!selectedReportAssetId}
            onClick={downloadVulnerabilityXlsx}
          >
            XLSX
          </Button>
          <Button
            variant="secondary"
            aria-label="Скачать уязвимости ОС"
            busy={busy["report-os"]}
            onClick={() => downloadVulnerabilityReport("os")}
          >
            ОС
          </Button>
          <Button
            variant="secondary"
            aria-label="Скачать уязвимости ПО"
            busy={busy["report-software"]}
            onClick={() => downloadVulnerabilityReport("software")}
          >
            ПО
          </Button>
          <Button
            variant="secondary"
            aria-label="Скачать уязвимости Docker"
            busy={busy["report-docker"]}
            onClick={() => downloadVulnerabilityReport("docker")}
          >
            Docker
          </Button>
        </div>
      </Panel>
      {canManageExports ? (
        <Panel id="export">
          <Disclosure
            className={
              form.delete_assets_after_export ? "disclosure--danger" : ""
            }
            title="PDQL-выгрузка"
            meta={
              form.delete_assets_after_export ? "Удаление в MP VM" : null
            }
          >
            <Field label="PDQL запрос">
              <textarea
                className="code-input"
                rows={8}
                value={form.pdql}
                onChange={(event) => update("pdql", event.target.value)}
              />
            </Field>
            <div className="form-grid form-grid--four">
              <Field label="Часовой пояс">
                <input
                  value={form.utc_offset}
                  onChange={(event) => update("utc_offset", event.target.value)}
                />
              </Field>
              <Field label="Группы">
                <input
                  value={form.group_ids}
                  onChange={(event) => update("group_ids", event.target.value)}
                  placeholder="ID через запятую"
                />
              </Field>
              <Field label="Активы">
                <input
                  value={form.asset_ids}
                  onChange={(event) => update("asset_ids", event.target.value)}
                  placeholder="ID через запятую"
                />
              </Field>
              <Toggle
                label="Включая вложенные группы"
                checked={form.include_nested_groups}
                onChange={(value) => update("include_nested_groups", value)}
              />
              <Toggle
                label="Сохранить локально"
                checked={form.import_results}
                onChange={(value) => update("import_results", value)}
              />
            </div>
            <div className="action-row export-run">
              <label
                className={`toggle${form.delete_assets_after_export ? " toggle--danger" : ""}`}
              >
                <input
                  type="checkbox"
                  checked={form.delete_assets_after_export}
                  onChange={(event) =>
                    update("delete_assets_after_export", event.target.checked)
                  }
                />
                <span>Удалить активы в MP VM после сохранения</span>
              </label>
              <Button
                variant={form.delete_assets_after_export ? "danger" : "primary"}
                busy={busy.export}
                onClick={runExport}
              >
                {form.delete_assets_after_export
                  ? "Экспортировать и удалить из MP VM"
                  : "Выполнить экспорт"}
              </Button>
              <ActionMenu label="Импорт">
                <label className="upload-button">
                  {importBusy ? "Загрузка…" : "Загрузить CSV"}
                  <input
                    className="visually-hidden"
                    type="file"
                    accept=".csv,text/csv"
                    disabled={importBusy}
                    onChange={importCsvFile}
                  />
                </label>
              </ActionMenu>
            </div>
            {result ? (
              <Disclosure title="Результат">
                <pre className="result-box">{result}</pre>
              </Disclosure>
            ) : null}
          </Disclosure>
        </Panel>
      ) : null}
    </>
  );
}

function AssetCardsPanel({ defaults, busy, runBusy, showAlert, currentUser }) {
  const [form, setForm] = useState({
    pdql: "",
    utc_offset: "+05:00",
    group_ids: "",
    asset_ids: "",
    asset_limit: "1001",
    batch_size: "5000",
    include_nested_groups: true,
    selected_asset_id: "",
    batch_asset_ids: "",
    timeline_timestamp: "",
    limit_per_collection: "5000",
    max_items_per_collection: "5000",
    max_depth: "64",
    docker_vulnerability_pdql: "",
    asset_refresh_parallelism: "",
    save_to_db: true,
  });
  const [candidates, setCandidates] = useState([]);
  const [cards, setCards] = useState([]);
  const [selectedCard, setSelectedCard] = useState(null);
  const [candidateSearch, setCandidateSearch] = useState("");
  const [cardSearch, setCardSearch] = useState("");
  const [queryRaw, setQueryRaw] = useState(null);
  const [assetWindowOpen, setAssetWindowOpen] = useState(false);
  const [selectedPassport, setSelectedPassport] = useState(null);
  const [assetPassportDetail, setAssetPassportDetail] = useState(null);
  const [assetPassportError, setAssetPassportError] = useState("");
  const [assetPassportWindowOpen, setAssetPassportWindowOpen] = useState(false);
  const [assetCardJob, setAssetCardJob] = useState(null);
  const [assetCardBatchJobs, setAssetCardBatchJobs] = useState([]);
  const [assetRefreshRun, setAssetRefreshRun] = useState(null);
  const [assetBulkRefreshOperation, setAssetBulkRefreshOperation] =
    useState(null);
  const [assetRefreshTemplates, setAssetRefreshTemplates] = useState([]);
  const [selectedRefreshTemplateId, setSelectedRefreshTemplateId] =
    useState("");
  const [assetRefreshTemplatesError, setAssetRefreshTemplatesError] =
    useState("");
  const [pendingCardDelete, setPendingCardDelete] = useState(null);
  const [candidateSort, toggleCandidateSort] = useTableSort();
  const [cardSort, toggleCardSort] = useTableSort("last_seen", "desc");
  const permissions = useMemo(
    () => new Set(currentUser?.permissions || []),
    [currentUser],
  );
  const canBuildAssetCards = permissions.has("asset_cards.build");
  const canManageAssetCards = permissions.has("asset_cards.manage");

  const refreshLocalCards = useCallback(
    async (sorting = cardSort) => {
      const params = new URLSearchParams({
        limit: String(clampNumber(form.asset_limit, 1000, 1, 50000)),
      });
      if (cardSearch.trim()) params.set("q", cardSearch.trim());
      params.set("sort_by", sorting.key);
      params.set("sort_dir", sorting.direction);
      const result = await api(`/api/asset-cards/local?${params.toString()}`);
      setCards(result.rows || []);
      return result;
    },
    [cardSearch, cardSort, form.asset_limit],
  );

  useEffect(() => {
    if (!defaults) return;
    setForm((value) => ({
      ...value,
      pdql: value.pdql || defaults.asset_card_pdql || "",
      docker_vulnerability_pdql:
        value.docker_vulnerability_pdql ||
        defaults.docker_vulnerability_pdql ||
        "",
      asset_refresh_parallelism:
        value.asset_refresh_parallelism ||
        String(defaults.asset_card_refresh_workers || 10),
      utc_offset: value.utc_offset || defaults.utc_offset || "+05:00",
    }));
  }, [defaults]);

  useEffect(() => {
    if (!assetWindowOpen) return;
    const closeOnEscape = (event) => {
      if (event.key === "Escape") setAssetWindowOpen(false);
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [assetWindowOpen]);

  useEffect(() => {
    let alive = true;
    Promise.allSettled([
      api("/api/asset-cards/build-jobs/active"),
      api("/api/asset-cards/refresh-scan/templates"),
    ]).then(([activeRequest, templatesRequest]) => {
      if (!alive) return;
      if (activeRequest.status === "fulfilled" && activeRequest.value.job) {
        setAssetCardJob(activeRequest.value.job);
      }
      if (templatesRequest.status === "rejected") {
        const error = templatesRequest.reason;
        setAssetRefreshTemplatesError(
          error?.operatorMessage || error?.message || String(error),
        );
        return;
      }
      const templatesResult = templatesRequest.value;
      const rows = templatesResult.rows || [];
      setAssetRefreshTemplates(rows);
      setSelectedRefreshTemplateId(
        templatesResult.recommended_task_id || rows[0]?.mp_task_id || "",
      );
      setAssetRefreshTemplatesError("");
    });
    return () => {
      alive = false;
    };
  }, [showAlert]);

  useEffect(() => {
    if (
      !assetCardJob?.job_id ||
      !ACTIVE_ASSET_CARD_JOB_STATUSES.has(assetCardJob.status)
    )
      return undefined;
    let alive = true;
    let timerId;
    const poll = async () => {
      try {
        const nextJob = await api(
          `/api/asset-cards/build-jobs/${encodeURIComponent(assetCardJob.job_id)}`,
        );
        if (!alive) return;
        setAssetCardJob(nextJob);
        if (ACTIVE_ASSET_CARD_JOB_STATUSES.has(nextJob.status)) {
          timerId = window.setTimeout(poll, 1000);
          return;
        }
        if (nextJob.status === "completed") {
          const [card] = await Promise.all([
            api(
              `/api/asset-cards/${encodeURIComponent(nextJob.asset_id)}/summary`,
            ),
            refreshLocalCards(),
          ]);
          if (!alive) return;
          setSelectedCard(card);
          setAssetWindowOpen(true);
          showAlert(
            `Карточка актива ${card.display_name || card.asset_id} собрана.`,
            "success",
          );
        } else {
          showAlert(
            `Сборка карточки завершена со статусом «${assetCardJobStatusLabel(nextJob.status)}».`,
            nextJob.status === "failed" ? "error" : "info",
          );
        }
      } catch (_error) {
        if (alive) timerId = window.setTimeout(poll, 3000);
      }
    };
    timerId = window.setTimeout(poll, 500);
    return () => {
      alive = false;
      window.clearTimeout(timerId);
    };
  }, [
    assetCardJob?.job_id,
    assetCardJob?.status,
    refreshLocalCards,
    showAlert,
  ]);

  useEffect(() => {
    const activeJobs = assetCardBatchJobs.filter(
      (job) => job.job_id && ACTIVE_ASSET_CARD_JOB_STATUSES.has(job.status),
    );
    if (!activeJobs.length) return undefined;
    let alive = true;
    let timerId;
    const poll = async () => {
      const settled = await Promise.allSettled(
        activeJobs.map((job) =>
          api(`/api/asset-cards/build-jobs/${encodeURIComponent(job.job_id)}`),
        ),
      );
      if (!alive) return;
      const updates = new Map();
      settled.forEach((result, index) => {
        if (result.status === "fulfilled") {
          updates.set(activeJobs[index].job_id, result.value);
        }
      });
      const nextJobs = assetCardBatchJobs.map(
        (job) => updates.get(job.job_id) || job,
      );
      setAssetCardBatchJobs(nextJobs);
      const stillActive = nextJobs.some((job) =>
        ACTIVE_ASSET_CARD_JOB_STATUSES.has(job.status),
      );
      if (stillActive) {
        timerId = window.setTimeout(poll, 1000);
        return;
      }
      await refreshLocalCards();
      if (!alive) return;
      const completed = nextJobs.filter(
        (job) => job.status === "completed",
      ).length;
      showAlert(
        `Пакетная сборка завершена: ${formatCount(completed)} из ${formatCount(nextJobs.length)} карточек сохранено.`,
        completed === nextJobs.length ? "success" : "error",
      );
    };
    timerId = window.setTimeout(poll, 500);
    return () => {
      alive = false;
      window.clearTimeout(timerId);
    };
  }, [assetCardBatchJobs, refreshLocalCards, showAlert]);

  useEffect(() => {
    if (
      !assetRefreshRun?.mp_task_id ||
      !ACTIVE_SCAN_POSTPROCESS_STATUSES.has(assetRefreshRun.status)
    )
      return undefined;
    let alive = true;
    let timerId;
    const poll = async () => {
      try {
        const nextRun = await api(
          `/api/scanner-tasks/${encodeURIComponent(assetRefreshRun.mp_task_id)}/postprocess-runs/latest`,
        );
        if (!alive) return;
        setAssetRefreshRun(nextRun);
        if (ACTIVE_SCAN_POSTPROCESS_STATUSES.has(nextRun.status)) {
          timerId = window.setTimeout(poll, 3000);
          return;
        }
        const refreshed = await refreshLocalCards();
        if (!alive) return;
        const completedAssetId = (nextRun.items || []).find(
          (item) => item.status === "completed",
        )?.asset_id;
        const nextCardSummary =
          (refreshed.rows || []).find(
            (item) => item.asset_id === completedAssetId,
          ) ||
          (refreshed.rows || []).find(
            (item) => item.ip_address === nextRun.options?.refresh_target_ip,
          );
        if (nextRun.status === "completed" && nextCardSummary?.asset_id) {
          const card = await api(
            `/api/asset-cards/${encodeURIComponent(nextCardSummary.asset_id)}/summary`,
          );
          if (!alive) return;
          setSelectedCard(card);
          setAssetWindowOpen(true);
          showAlert(
            `Карточка ${card.display_name || card.asset_id} обновлена после повторного сканирования IP.`,
            "success",
          );
        } else {
          showAlert(
            nextRun.message ||
              "Повторное сканирование карточки завершилось с ошибками.",
            "error",
          );
        }
      } catch (_error) {
        if (alive) timerId = window.setTimeout(poll, 5000);
      }
    };
    timerId = window.setTimeout(poll, 1000);
    return () => {
      alive = false;
      window.clearTimeout(timerId);
    };
  }, [assetRefreshRun?.mp_task_id, refreshLocalCards, showAlert]);

  useEffect(() => {
    if (
      !assetBulkRefreshOperation?.operation_id ||
      !ACTIVE_BULK_REFRESH_STATUSES.has(assetBulkRefreshOperation.status)
    )
      return undefined;
    let alive = true;
    let timerId;
    const poll = async () => {
      try {
        const nextOperation = await api(
          `/api/operations/${encodeURIComponent(assetBulkRefreshOperation.operation_id)}`,
        );
        if (!alive) return;
        setAssetBulkRefreshOperation(nextOperation);
        if (ACTIVE_BULK_REFRESH_STATUSES.has(nextOperation.status)) {
          timerId = window.setTimeout(poll, 3000);
          return;
        }
        await refreshLocalCards();
        if (!alive) return;
        const result = nextOperation.result || {};
        showAlert(
          nextOperation.message ||
            `Массовое обновление завершено: ${formatCount(result.completed_count)} из ${formatCount(result.selected_count)}.`,
          nextOperation.status === "completed" ? "success" : "error",
        );
      } catch (_error) {
        if (alive) timerId = window.setTimeout(poll, 5000);
      }
    };
    timerId = window.setTimeout(poll, 1000);
    return () => {
      alive = false;
      window.clearTimeout(timerId);
    };
  }, [
    assetBulkRefreshOperation?.operation_id,
    assetBulkRefreshOperation?.status,
    refreshLocalCards,
    showAlert,
  ]);

  const update = (key, value) =>
    setForm((current) => ({ ...current, [key]: value }));
  const filteredCandidates = useMemo(
    () => filterAssetCandidates(candidates, candidateSearch),
    [candidates, candidateSearch],
  );
  const sortedCandidates = useSortedRows(filteredCandidates, candidateSort);

  const changeCardSort = (key, initialDirection = "asc") => {
    const next = {
      key,
      direction:
        cardSort.key === key
          ? cardSort.direction === "asc"
            ? "desc"
            : "asc"
          : initialDirection,
    };
    toggleCardSort(key, initialDirection);
    runBusy("assetCardsLocal", () => refreshLocalCards(next));
  };

  const queryAssets = () =>
    runBusy("assetCandidateQuery", async () => {
      const requestedLimit = clampNumber(form.asset_limit, 1001, 1, 50000);
      const requestedBatchSize = clampNumber(form.batch_size, 5000, 1, 10000);
      const result = await api("/api/asset-cards/query-assets", {
        method: "POST",
        body: JSON.stringify({
          pdql: form.pdql,
          utc_offset: form.utc_offset || null,
          group_ids: splitTokens(form.group_ids),
          asset_ids: splitTokens(form.asset_ids),
          include_nested_groups: form.include_nested_groups,
          limit: requestedLimit,
          batch_size: requestedBatchSize,
        }),
      });
      const records = result.records || [];
      setCandidates(records);
      setQueryRaw(result.raw || null);
      if (!form.selected_asset_id && records[0]?.asset_id) {
        update("selected_asset_id", records[0].asset_id);
      }
      showAlert(
        `Получено активов: ${formatCount(records.length)}.`,
        records.length ? "success" : "info",
      );
    });

  const buildCard = () =>
    runBusy("assetCardBuild", async () => {
      const assetId = form.selected_asset_id.trim();
      if (!assetId)
        throw new Error("Введите asset_id или выберите актив из списка.");
      const payload = {
        asset_id: assetId,
        timeline_timestamp: form.timeline_timestamp
          ? Number(form.timeline_timestamp)
          : null,
        limit_per_collection: clampNumber(
          form.limit_per_collection,
          5000,
          1,
          5000,
        ),
        max_items_per_collection: clampNumber(
          form.max_items_per_collection,
          5000,
          1,
          50000,
        ),
        max_depth: clampNumber(form.max_depth, 64, 0, 64),
        docker_vulnerability_pdql: form.docker_vulnerability_pdql,
      };
      if (form.save_to_db) {
        const result = await api("/api/asset-cards/build-jobs", {
          method: "POST",
          headers: { "X-Idempotency-Key": createIdempotencyKey("asset-card") },
          body: JSON.stringify(payload),
        });
        setAssetCardJob(result.job);
        showAlert(`Сборка карточки ${assetId} запущена в фоне.`, "info");
        return;
      }
      const result = await api("/api/asset-cards/build", {
        method: "POST",
        body: JSON.stringify({ ...payload, save_to_db: false }),
      });
      const nextCard = result.card;
      setSelectedCard(nextCard);
      setAssetWindowOpen(true);
      if (result.saved) {
        setCards((items) => [
          nextCard,
          ...items.filter((item) => item.asset_id !== nextCard.asset_id),
        ]);
      }
      const stats = assetCardStats(nextCard);
      showAlert(
        `Карточка собрана: ${formatCount(stats.table_rows)} строк data, ${formatCount(stats.collections)} коллекций.`,
        "success",
      );
    });

  const batchAssetIds = useMemo(
    () => [...new Set(splitTokens(form.batch_asset_ids))],
    [form.batch_asset_ids],
  );
  const batchAssetIdsValid =
    batchAssetIds.length >= 1 && batchAssetIds.length <= 2;

  const toggleBatchAsset = (assetId) => {
    if (!assetId) return;
    const selected = new Set(batchAssetIds);
    if (selected.has(assetId)) selected.delete(assetId);
    else if (selected.size < 2) selected.add(assetId);
    update("batch_asset_ids", [...selected].join("\n"));
  };

  const buildCardBatch = () =>
    runBusy("assetCardBatchBuild", async () => {
      if (!batchAssetIdsValid) {
        throw new Error("Укажите один или два уникальных asset_id.");
      }
      const result = await api("/api/asset-cards/build-jobs/batch", {
        method: "POST",
        headers: {
          "X-Idempotency-Key": createIdempotencyKey("asset-card-batch"),
        },
        body: JSON.stringify({
          asset_ids: batchAssetIds,
          timeline_timestamp: form.timeline_timestamp
            ? Number(form.timeline_timestamp)
            : null,
          limit_per_collection: clampNumber(
            form.limit_per_collection,
            5000,
            1,
            5000,
          ),
          max_items_per_collection: clampNumber(
            form.max_items_per_collection,
            5000,
            1,
            50000,
          ),
          max_depth: clampNumber(form.max_depth, 64, 0, 64),
          docker_vulnerability_pdql: form.docker_vulnerability_pdql,
        }),
      });
      const responseJobs =
        result.jobs || result.items || result.batch?.jobs || [];
      if (!Array.isArray(responseJobs) || responseJobs.length === 0) {
        throw new Error("Backend не вернул задачи пакетной сборки.");
      }
      const jobs = responseJobs.map((item) => item.job || item);
      setAssetCardBatchJobs(jobs);
      showAlert(
        `Запущена сборка ${formatCount(jobs.length)} карточек активов.`,
        "info",
      );
    });

  const loadLocalCards = () =>
    runBusy("assetCardsLocal", async () => {
      await refreshLocalCards();
    });

  useEffect(() => {
    refreshLocalCards().catch(() => {
      // The list keeps its empty state; the refresh button shows errors.
    });
    // Only the first render loads automatically.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const openLocalCard = (row) => {
    setSelectedCard({ ...row, loaded_sections: ["summary"] });
    setAssetWindowOpen(true);
  };

  useEffect(() => {
    const assetId =
      typeof window === "undefined"
        ? null
        : new URLSearchParams(window.location.search).get("asset");
    if (!assetId) return;
    api(`/api/asset-cards/${encodeURIComponent(assetId)}/summary`)
      .then((card) => {
        setSelectedCard(card);
        setAssetWindowOpen(true);
      })
      .catch((error) =>
        showAlert(error.operatorMessage || error.message, "error"),
      );
  }, [showAlert]);

  const updateLocalCard = (row) =>
    runBusy(`assetCardUpdate:${row.asset_id}`, async () => {
      const result = await api(
        `/api/asset-cards/${encodeURIComponent(row.asset_id)}/refresh-scan`,
        {
          method: "POST",
          headers: {
            "X-Idempotency-Key": createIdempotencyKey(
              "asset-card-refresh-scan",
            ),
          },
          body: JSON.stringify({}),
        },
      );
      if (!result.postprocess_run_id || result.status !== "started") {
        throw new Error(
          result.error ||
            result.message ||
            "Автоматическая задача не была запущена.",
        );
      }
      setAssetRefreshRun(result.postprocess);
      showAlert(
        `Создана задача ${result.task_id}; IP ${result.target_ip} отправлен на повторное сканирование.`,
        "info",
      );
    });

  const updateAllLocalCards = () =>
    runBusy("assetCardsBulkRefresh", async () => {
      const result = await api("/api/asset-cards/refresh-scan/bulk", {
        method: "POST",
        headers: {
          "X-Idempotency-Key": createIdempotencyKey("asset-cards-bulk-refresh"),
        },
        body: JSON.stringify({
          selection: "all",
          template_task_id: selectedRefreshTemplateId || null,
          parallelism: clampNumber(
            form.asset_refresh_parallelism,
            defaults?.asset_card_refresh_workers || 10,
            1,
            defaults?.asset_card_refresh_workers || 10,
          ),
        }),
      });
      if (!result.operation_id || !result.operation) {
        throw new Error(
          "Массовое обновление карточек не было поставлено в очередь.",
        );
      }
      setAssetBulkRefreshOperation(result.operation);
      showAlert(
        `Все сохранённые карточки поставлены на обновление: до ${clampNumber(
          form.asset_refresh_parallelism,
          defaults?.asset_card_refresh_workers || 10,
          1,
          defaults?.asset_card_refresh_workers || 10,
        )} одновременно. Прогресс доступен в центре операций.`,
        "info",
      );
    });

  const cancelAssetCardJob = () => {
    if (!assetCardJob?.job_id) return;
    runBusy("assetCardJobCancel", async () => {
      const result = await api(
        `/api/asset-cards/build-jobs/${encodeURIComponent(assetCardJob.job_id)}/cancel`,
        {
          method: "POST",
        },
      );
      setAssetCardJob(result);
      showAlert("Остановка сборки карточки запрошена.", "info");
    });
  };

  const deleteLocalCard = (row) => {
    const label = row.display_name || row.hostname || row.asset_id;
    runBusy(`assetCardDelete:${row.asset_id}`, async () => {
      await api(`/api/asset-cards/${encodeURIComponent(row.asset_id)}`, {
        method: "DELETE",
      });
      setCards((items) =>
        items.filter((item) => item.asset_id !== row.asset_id),
      );
      if (selectedCard?.asset_id === row.asset_id) {
        setSelectedCard(null);
        setAssetWindowOpen(false);
      }
      showAlert(`Карточка актива ${label} удалена.`, "success");
      setPendingCardDelete(null);
    });
  };

  const openAssetPassport = (passport) =>
    runBusy("assetCardPassportDetail", async () => {
      const passportSummary =
        typeof passport === "string"
          ? { internal_id: passport }
          : passport || {};
      const passportId = passportSummary.internal_id;
      if (!passportId)
        throw new Error("Для этой уязвимости ещё не найден локальный паспорт.");
      setSelectedPassport(passportSummary);
      setAssetPassportDetail(null);
      setAssetPassportError("");
      setAssetPassportWindowOpen(true);
      try {
        const result = await api(
          `/api/vulnerability-passports/${encodeURIComponent(passportId)}`,
        );
        const nextPassport = result.passport || {
          ...passportSummary,
          internal_id: passportId,
          raw_detail: result.raw || null,
          has_detail: Boolean(result.raw),
        };
        setSelectedPassport(nextPassport);
        setAssetPassportDetail(result.raw || nextPassport.raw_detail || {});
      } catch (error) {
        setAssetPassportError(error.message || String(error));
        throw error;
      }
    });

  const assetCardJobProgress = Math.max(
    0,
    Math.min(100, Number(assetCardJob?.progress_percent) || 0),
  );
  const assetCardJobActive = ACTIVE_ASSET_CARD_JOB_STATUSES.has(
    assetCardJob?.status,
  );
  const assetCardBatchActive = assetCardBatchJobs.some((job) =>
    ACTIVE_ASSET_CARD_JOB_STATUSES.has(job.status),
  );
  const assetCardBatchCompletedCount = assetCardBatchJobs.filter(
    (job) => job.status === "completed",
  ).length;
  const assetCardBatchFailedCount = assetCardBatchJobs.filter((job) =>
    ["failed", "cancelled", "interrupted"].includes(job.status),
  ).length;
  const assetCardBatchActiveCount = assetCardBatchJobs.filter((job) =>
    ACTIVE_ASSET_CARD_JOB_STATUSES.has(job.status),
  ).length;
  const assetRefreshActive = ACTIVE_SCAN_POSTPROCESS_STATUSES.has(
    assetRefreshRun?.status,
  );
  const assetBulkRefreshActive = ACTIVE_BULK_REFRESH_STATUSES.has(
    assetBulkRefreshOperation?.status,
  );

  return (
    <Panel
      id="asset-cards"
      action={
        <div className="row-actions">
          {canBuildAssetCards ? (
            <ActionMenu label="Ещё">
              <Button
                aria-label="Обновить все карточки активов"
                busy={busy.assetCardsBulkRefresh}
                disabled={
                  !selectedRefreshTemplateId ||
                  assetCardJobActive ||
                  assetRefreshActive ||
                  assetBulkRefreshActive
                }
                onClick={updateAllLocalCards}
              >
                Обновить все из MP VM
              </Button>
            </ActionMenu>
          ) : null}
        </div>
      }
    >
      <div className="asset-local-header">
        <input
          value={cardSearch}
          onChange={(event) => setCardSearch(event.target.value)}
          onKeyDown={(event) => event.key === "Enter" && loadLocalCards()}
          placeholder="IP, FQDN, имя хоста или ОС"
        />
        <Button
          variant="secondary"
          busy={busy.assetCardsLocal}
          onClick={loadLocalCards}
        >
          Показать сохранённые
        </Button>
      </div>
      <div className="table-shell">
        <table className="asset-card-list-table">
          <thead>
            <tr>
              <SortableHeader
                column="display_name"
                sort={cardSort}
                onSort={changeCardSort}
              >
                Актив
              </SortableHeader>
              <SortableHeader
                column="ip_address"
                sort={cardSort}
                onSort={changeCardSort}
              >
                IP / FQDN
              </SortableHeader>
              <SortableHeader
                column="os_name"
                sort={cardSort}
                onSort={changeCardSort}
              >
                Платформа
              </SortableHeader>
              <SortableHeader
                column="last_seen"
                sort={cardSort}
                onSort={changeCardSort}
                initialDirection="desc"
              >
                Обновлено
              </SortableHeader>
              <th>Действия</th>
            </tr>
          </thead>
          <tbody>
            {cards.length ? (
              cards.map((row) => {
                const stats = assetCardStats(row);
                return (
                  <tr key={row.asset_id}>
                    <td className="wide-cell">
                      <strong>
                        {row.display_name || row.hostname || row.asset_id}
                      </strong>
                      <span>
                        <code>{row.asset_id}</code>
                      </span>
                    </td>
                    <td>
                      {[row.ip_address, row.fqdn].filter(Boolean).join(" / ") ||
                        "—"}
                    </td>
                    <td>
                      {[row.os_name, row.os_version]
                        .filter(Boolean)
                        .join(" ") || "—"}
                      <small className="table-cell-meta">
                        {row.asset_type || "Тип не указан"} ·{" "}
                        {formatCount(stats.table_rows)} строк ·{" "}
                        {formatCount(stats.collections)} коллекций
                      </small>
                    </td>
                    <td>
                      <FreshnessBadge
                        value={row.last_seen}
                        freshForHours={14 * 24}
                        staleAfterHours={14 * 24}
                      />
                    </td>
                    <td>
                      <div className="row-actions">
                        <Button
                          variant="tiny"
                          busy={
                            busy.assetCardOpen &&
                            selectedCard?.asset_id === row.asset_id
                          }
                          onClick={() => openLocalCard(row)}
                        >
                          Открыть
                        </Button>
                        {canBuildAssetCards || canManageAssetCards ? (
                          <ActionMenu label="Ещё">
                            {canBuildAssetCards ? (
                              <Button
                                variant="tiny"
                                disabled={
                                  assetCardJobActive || assetRefreshActive
                                }
                                busy={busy[`assetCardUpdate:${row.asset_id}`]}
                                onClick={() => updateLocalCard(row)}
                              >
                                Обновить
                              </Button>
                            ) : null}
                            {canManageAssetCards ? (
                              <Button
                                variant="tiny-danger"
                                busy={busy[`assetCardDelete:${row.asset_id}`]}
                                onClick={() => setPendingCardDelete(row)}
                              >
                                Удалить
                              </Button>
                            ) : null}
                          </ActionMenu>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan={5} className="empty-cell">
                  {canBuildAssetCards
                    ? "Соберите карточку или загрузите сохранённые из БД."
                    : "Загрузите сохранённые карточки из БД."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {canBuildAssetCards ? (
        <Disclosure className="asset-card-build" title="Сбор из MP VM">
          <Disclosure
            title="Обновление карточек из MP VM"
            meta={selectedRefreshTemplateId ? "Шаблон выбран" : "Не настроено"}
          >
            <Field label="Задача MP VM для обновления карточек">
              <select
                value={selectedRefreshTemplateId}
                onChange={(event) =>
                  setSelectedRefreshTemplateId(event.target.value)
                }
              >
                <option value="">Выберите задачу-шаблон</option>
                {assetRefreshTemplates.map((task) => (
                  <option key={task.mp_task_id} value={task.mp_task_id}>
                    {task.name || task.mp_task_id}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Параллельных обновлений">
              <input
                type="number"
                min="1"
                max={defaults?.asset_card_refresh_workers || 10}
                value={form.asset_refresh_parallelism}
                onChange={(event) =>
                  update("asset_refresh_parallelism", event.target.value)
                }
              />
            </Field>
            {assetRefreshTemplatesError ? (
              <small className="error-text">
                Не удалось загрузить задачи-шаблоны:{" "}
                {assetRefreshTemplatesError}
              </small>
            ) : assetRefreshTemplates.length === 0 ? (
              <small className="error-text">
                В MP VM не найдено задач с заполненными scope и scanner profile.
                Создайте такую задачу перед массовым обновлением карточек.
              </small>
            ) : null}
          </Disclosure>
          <Field label="PDQL-запрос активов">
            <textarea
              className="code-input"
              rows={4}
              value={form.pdql}
              onChange={(event) => update("pdql", event.target.value)}
            />
          </Field>
          <Disclosure
            title="Параметры поиска"
            meta={
              form.group_ids || form.asset_ids
                ? "Есть ограничения"
                : "По умолчанию"
            }
          >
            <div className="form-grid form-grid--four">
              <Field label="Часовой пояс">
                <input
                  value={form.utc_offset}
                  onChange={(event) => update("utc_offset", event.target.value)}
                />
              </Field>
              <Field label="Группы">
                <input
                  value={form.group_ids}
                  onChange={(event) => update("group_ids", event.target.value)}
                  placeholder="ID через запятую"
                />
              </Field>
              <Field label="Активы">
                <input
                  value={form.asset_ids}
                  onChange={(event) => update("asset_ids", event.target.value)}
                  placeholder="ID через запятую"
                />
              </Field>
              <Field label="Сколько загрузить">
                <input
                  value={form.asset_limit}
                  onChange={(event) =>
                    update("asset_limit", event.target.value)
                  }
                  type="number"
                  min="1"
                  max="50000"
                />
              </Field>
              <Field label="Размер пачки">
                <input
                  value={form.batch_size}
                  onChange={(event) => update("batch_size", event.target.value)}
                  type="number"
                  min="1"
                  max="10000"
                />
              </Field>
              <Toggle
                label="Включая вложенные группы"
                checked={form.include_nested_groups}
                onChange={(value) => update("include_nested_groups", value)}
              />
            </div>
          </Disclosure>
          <div className="action-row">
            <Button busy={busy.assetCandidateQuery} onClick={queryAssets}>
              Найти активы
            </Button>
            <div className="inline-metric">
              Найдено: <span>{formatCount(filteredCandidates.length)}</span>
            </div>
          </div>

          <div className="asset-card-builder">
            <div className="asset-card-build-primary">
              <Field label="ID актива">
                <input
                  value={form.selected_asset_id}
                  onChange={(event) =>
                    update("selected_asset_id", event.target.value)
                  }
                  placeholder="ID из списка или вручную"
                />
              </Field>
              <Button
                busy={busy.assetCardBuild}
                disabled={assetCardJobActive || assetCardBatchActive}
                onClick={buildCard}
              >
                Собрать карточку
              </Button>
            </div>
            <Disclosure
              title="Параметры сборки"
              meta={form.save_to_db ? "Сохранить в БД" : "Без сохранения"}
            >
              <Field label="PDQL уязвимостей Docker-контейнеров">
                <textarea
                  className="code-input"
                  rows={6}
                  value={form.docker_vulnerability_pdql}
                  onChange={(event) =>
                    update("docker_vulnerability_pdql", event.target.value)
                  }
                />
              </Field>
              <div className="form-grid form-grid--two form-grid--spaced">
                <Field label="Момент времени (Unix)">
                  <input
                    value={form.timeline_timestamp}
                    onChange={(event) =>
                      update("timeline_timestamp", event.target.value)
                    }
                    type="number"
                    placeholder="Сейчас"
                  />
                </Field>
                <Field label="Лимит запроса коллекции">
                  <input
                    value={form.limit_per_collection}
                    onChange={(event) =>
                      update("limit_per_collection", event.target.value)
                    }
                    type="number"
                    min="1"
                    max="5000"
                  />
                </Field>
                <Field label="Максимум элементов коллекции">
                  <input
                    value={form.max_items_per_collection}
                    onChange={(event) =>
                      update("max_items_per_collection", event.target.value)
                    }
                    type="number"
                    min="1"
                    max="50000"
                  />
                </Field>
                <Field label="Глубина обхода">
                  <input
                    value={form.max_depth}
                    onChange={(event) =>
                      update("max_depth", event.target.value)
                    }
                    type="number"
                    min="0"
                    max="64"
                  />
                </Field>
                <Toggle
                  label="Сохранить карточку локально"
                  checked={form.save_to_db}
                  onChange={(value) => update("save_to_db", value)}
                />
              </div>
            </Disclosure>
          </div>

          <Disclosure
            title="Пакетная сборка"
            meta={
              batchAssetIds.length
                ? `Выбрано: ${batchAssetIds.length}`
                : "Не выбрано"
            }
          >
            <Field label="ID активов для пакетной сборки" wide>
              <textarea
                rows={4}
                value={form.batch_asset_ids}
                onChange={(event) =>
                  update("batch_asset_ids", event.target.value)
                }
                placeholder="До двух ID, по одному в строке"
                aria-describedby="asset-card-batch-help"
              />
            </Field>
            <small
              id="asset-card-batch-help"
              className={batchAssetIds.length > 2 ? "error-text" : undefined}
            >
              Выбрано: {formatCount(batchAssetIds.length)} из 2
              {batchAssetIds.length > 2 ? ". Удалите лишние значения." : ""}
            </small>
            <div className="action-row">
              <Button
                busy={busy.assetCardBatchBuild}
                disabled={
                  !batchAssetIdsValid ||
                  assetCardJobActive ||
                  assetCardBatchActive
                }
                onClick={buildCardBatch}
              >
                Собрать выбранные карточки
              </Button>
            </div>
          </Disclosure>
        </Disclosure>
      ) : null}

      {canBuildAssetCards && assetCardBatchJobs.length ? (
        <section className="passport-job asset-card-job" aria-live="polite">
          <div className="passport-job__header">
            <strong>Пакетная сборка карточек</strong>
            <span>
              Готово: {formatCount(assetCardBatchCompletedCount)} · Ошибки:{" "}
              {formatCount(assetCardBatchFailedCount)} · В работе:{" "}
              {formatCount(assetCardBatchActiveCount)}
            </span>
          </div>
          {assetCardBatchJobs.map((job, index) => {
            const progress = Math.max(
              0,
              Math.min(100, Number(job.progress_percent) || 0),
            );
            return (
              <div key={job.job_id || job.asset_id || index}>
                <div className="asset-local-header">
                  <div>
                    <strong>{job.asset_id || `Карточка ${index + 1}`}</strong>
                    <small>
                      {assetCardJobStatusLabel(job.status)} ·{" "}
                      {assetCardJobStageLabel(job.stage)} ·{" "}
                      {formatCount(progress)}%
                    </small>
                  </div>
                  <span
                    className={`status-pill ${ACTIVE_ASSET_CARD_JOB_STATUSES.has(job.status) ? "status-pill--running" : ""}`}
                  >
                    {assetCardJobStatusLabel(job.status)}
                  </span>
                </div>
                <div
                  className="passport-job__track"
                  role="progressbar"
                  aria-label={`Прогресс сборки карточки ${
                    job.asset_id || index + 1
                  }`}
                  aria-valuemin="0"
                  aria-valuemax="100"
                  aria-valuenow={progress}
                  aria-valuetext={`${progress}% — ${assetCardJobStageLabel(job.stage)}`}
                >
                  <span style={{ width: `${progress}%` }} />
                </div>
                {job.message ? <small>{job.message}</small> : null}
              </div>
            );
          })}
        </section>
      ) : null}

      {canBuildAssetCards && assetCardJob ? (
        <section
          className={`passport-job asset-card-job passport-job--${assetCardJob.status}${assetCardJobActive ? " asset-card-job--active" : ""}`}
          aria-live="polite"
        >
          <div className="passport-job__header">
            <div>
              <strong>
                Сборка карточки {assetCardJob.asset_id}:{" "}
                {assetCardJobStatusLabel(assetCardJob.status)}
              </strong>
              <span>
                Этап: {assetCardJobStageLabel(assetCardJob.stage)} ·{" "}
                {formatCount(assetCardJobProgress)}% · запросов{" "}
                {formatCount(assetCardJob.completed_requests)} /{" "}
                {formatCount(assetCardJob.discovered_requests)} · узлов{" "}
                {formatCount(assetCardJob.node_count)} · коллекций{" "}
                {formatCount(assetCardJob.collection_count)} · уязвимостей{" "}
                {formatCount(assetCardJob.finding_count)} · предупреждений{" "}
                {formatCount(assetCardJob.warning_count)}
              </span>
            </div>
            {assetCardJobActive ? (
              <Button
                variant="tiny-danger"
                busy={busy.assetCardJobCancel}
                onClick={cancelAssetCardJob}
              >
                Остановить
              </Button>
            ) : null}
          </div>
          {assetCardJob.trace_id ? (
            <small>
              Trace ID: <code>{assetCardJob.trace_id}</code>
            </small>
          ) : null}
          <div
            className="passport-job__track"
            role="progressbar"
            aria-label="Прогресс сборки карточки"
            aria-valuemin="0"
            aria-valuemax="100"
            aria-valuenow={assetCardJobProgress}
            aria-valuetext={`${assetCardJobProgress}% — ${assetCardJobStageLabel(assetCardJob.stage)}`}
          >
            <span style={{ width: `${assetCardJobProgress}%` }} />
          </div>
          {assetCardJob.message ? <small>{assetCardJob.message}</small> : null}
        </section>
      ) : null}

      {canBuildAssetCards && assetRefreshRun ? (
        <div className="asset-refresh-scan">
          <div className="asset-local-header">
            <div>
              <strong>Обновление карточки через повторное сканирование</strong>
              <small>
                Задача MP VM: <code>{assetRefreshRun.mp_task_id}</code>
              </small>
            </div>
            {assetRefreshActive ? (
              <span className="status-pill status-pill--running">
                Выполняется
              </span>
            ) : null}
          </div>
          <TaskPostprocessPanel run={assetRefreshRun} />
        </div>
      ) : null}

      {canBuildAssetCards && assetBulkRefreshOperation ? (
        <section className="passport-job asset-refresh-scan" aria-live="polite">
          <div className="asset-local-header">
            <div>
              <strong>Массовое обновление карточек активов</strong>
              <small>
                {assetBulkRefreshOperation.message ||
                  "Операция поставлена в очередь."}
              </small>
            </div>
            <span
              className={`status-pill ${assetBulkRefreshActive ? "status-pill--running" : ""}`}
            >
              {formatCount(assetBulkRefreshOperation.progress_percent)}%
            </span>
          </div>
          <div
            className="passport-job__track"
            role="progressbar"
            aria-label="Прогресс массового обновления карточек"
            aria-valuemin="0"
            aria-valuemax="100"
            aria-valuenow={
              Number(assetBulkRefreshOperation.progress_percent) || 0
            }
          >
            <span
              style={{
                width: `${Math.max(0, Math.min(100, Number(assetBulkRefreshOperation.progress_percent) || 0))}%`,
              }}
            />
          </div>
        </section>
      ) : null}

      {canBuildAssetCards && candidates.length ? (
        <>
          <div className="passport-controls">
            <input
              value={candidateSearch}
              onChange={(event) => setCandidateSearch(event.target.value)}
              placeholder="Поиск по asset_id, имени, ОС"
            />
            <select
              value={form.selected_asset_id}
              onChange={(event) =>
                update("selected_asset_id", event.target.value)
              }
            >
              <option value="">Выберите актив</option>
              {sortedCandidates.slice(0, 1000).map((row, index) => (
                <option
                  value={row.asset_id || ""}
                  key={row.asset_id || `${row.display_name}-${index}`}
                >
                  {[row.display_name, row.os_name, row.asset_id]
                    .filter(Boolean)
                    .join(" · ")}
                </option>
              ))}
            </select>
          </div>
          <div className="table-shell asset-candidates-shell">
            <table className="asset-candidates-table">
              <thead>
                <tr>
                  <SortableHeader
                    column="display_name"
                    sort={candidateSort}
                    onSort={toggleCandidateSort}
                  >
                    Актив
                  </SortableHeader>
                  <SortableHeader
                    column="os_name"
                    sort={candidateSort}
                    onSort={toggleCandidateSort}
                  >
                    ОС
                  </SortableHeader>
                  <SortableHeader
                    column="creation_time"
                    sort={candidateSort}
                    onSort={toggleCandidateSort}
                    initialDirection="desc"
                  >
                    Создан
                  </SortableHeader>
                  <SortableHeader
                    column="update_time"
                    sort={candidateSort}
                    onSort={toggleCandidateSort}
                    initialDirection="desc"
                  >
                    Обновлён
                  </SortableHeader>
                  <SortableHeader
                    column="asset_id"
                    sort={candidateSort}
                    onSort={toggleCandidateSort}
                  >
                    ID актива
                  </SortableHeader>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {sortedCandidates.slice(0, 300).map((row, index) => (
                  <tr key={row.asset_id || `${row.display_name}-${index}`}>
                    <td>{row.display_name || "—"}</td>
                    <td>{row.os_name || "—"}</td>
                    <td>{formatDateTime(row.creation_time)}</td>
                    <td>{formatDateTime(row.update_time)}</td>
                    <td>
                      <code>{row.asset_id || "n/a"}</code>
                    </td>
                    <td>
                      <Button
                        variant="tiny"
                        disabled={!row.asset_id}
                        onClick={() =>
                          update("selected_asset_id", row.asset_id || "")
                        }
                      >
                        Выбрать
                      </Button>
                      <Button
                        variant="tiny"
                        disabled={
                          !row.asset_id ||
                          (!batchAssetIds.includes(row.asset_id) &&
                            batchAssetIds.length >= 2)
                        }
                        aria-pressed={batchAssetIds.includes(row.asset_id)}
                        onClick={() => toggleBatchAsset(row.asset_id)}
                      >
                        {batchAssetIds.includes(row.asset_id)
                          ? "Убрать из пакета"
                          : "В пакет"}
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : canBuildAssetCards && queryRaw ? (
        <details className="raw-details">
          <summary>Raw-ответ PDQL запроса активов</summary>
          <pre>{JSON.stringify(queryRaw, null, 2)}</pre>
        </details>
      ) : null}


      {assetWindowOpen ? (
        <PassportModal
          title="Карточка актива"
          className="asset-modal"
          overlayClassName="asset-modal-overlay"
          closeLabel="Закрыть"
          onClose={() => setAssetWindowOpen(false)}
        >
          <AssetCard
            card={selectedCard}
            loading={busy.assetCardBuild || busy.assetCardOpen}
            onOpenPassport={openAssetPassport}
          />
        </PassportModal>
      ) : null}
      {assetPassportWindowOpen ? (
        <PassportModal
          title="Паспорт уязвимости"
          className="asset-modal"
          overlayClassName="asset-modal-overlay"
          closeLabel="Назад к активу"
          onClose={() => setAssetPassportWindowOpen(false)}
        >
          {assetPassportError ? (
            <div className="passport-load-error" role="alert">
              Не удалось загрузить паспорт: {assetPassportError}
            </div>
          ) : null}
          <PassportCard
            row={selectedPassport}
            detail={assetPassportDetail}
            loading={busy.assetCardPassportDetail && !assetPassportDetail}
          />
        </PassportModal>
      ) : null}
      <ConfirmDialog
        open={Boolean(pendingCardDelete)}
        title="Удалить локальную карточку?"
        description={`Карточка «${pendingCardDelete?.display_name || pendingCardDelete?.hostname || pendingCardDelete?.asset_id || ""}» будет удалена только из PostgreSQL.`}
        impact={[
          "Актив в MP VM не изменится",
          "Карточку можно собрать заново из MP VM",
        ]}
        confirmLabel="Удалить из БД"
        busy={Boolean(
          pendingCardDelete &&
          busy[`assetCardDelete:${pendingCardDelete.asset_id}`],
        )}
        onClose={() => setPendingCardDelete(null)}
        onConfirm={() => deleteLocalCard(pendingCardDelete)}
      />
    </Panel>
  );
}

function VulnerabilityPassportsPanel({
  defaults,
  busy,
  runBusy,
  showAlert,
  currentUser,
}) {
  const permissions = new Set(currentUser?.permissions || []);
  const canManagePassports = permissions.has("passports.manage");
  const [form, setForm] = useState({
    pdql: "",
    utc_offset: "+05:00",
    group_ids: "",
    asset_ids: "",
    passport_limit: "",
    batch_size: "5000",
    include_nested_groups: true,
    load_details: true,
  });
  const [rows, setRows] = useState([]);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [queryRaw, setQueryRaw] = useState(null);
  const [passportSearch, setPassportSearch] = useState("");
  const [passportPage, setPassportPage] = useState(1);
  const [passportTotal, setPassportTotal] = useState(0);
  const [passportSourceToken, setPassportSourceToken] = useState(null);
  const [passportJob, setPassportJob] = useState(null);
  const [passportRefreshJob, setPassportRefreshJob] = useState(null);
  const [passportWindowOpen, setPassportWindowOpen] = useState(false);
  const [pendingPassportDelete, setPendingPassportDelete] = useState(null);
  const [passportSort, togglePassportSort] = useTableSort();
  const passportPageSize = 50;

  useEffect(() => {
    if (!defaults) return;
    setForm((value) => ({
      ...value,
      pdql: value.pdql || defaults.vulnerability_passport_pdql || "",
      utc_offset: value.utc_offset || defaults.utc_offset || "+05:00",
    }));
  }, [defaults]);

  const update = (key, value) =>
    setForm((current) => ({ ...current, [key]: value }));
  const totalPages = Math.max(1, Math.ceil(passportTotal / passportPageSize));
  const safePage = Math.min(passportPage, totalPages);
  const pageRows = rows;

  const fetchPassportPage = useCallback(
    async (
      page,
      search = passportSearch,
      pdqlToken = passportSourceToken,
      sorting = passportSort,
    ) => {
      const safeRequestedPage = Math.max(1, page);
      const params = new URLSearchParams({
        limit: String(passportPageSize),
        offset: String((safeRequestedPage - 1) * passportPageSize),
      });
      if (search.trim()) params.set("q", search.trim());
      if (pdqlToken) params.set("pdql_token", pdqlToken);
      if (sorting.key) params.set("sort_by", sorting.key);
      if (sorting.key) params.set("sort_dir", sorting.direction);
      const result = await api(
        `/api/vulnerability-passports/local?${params.toString()}`,
      );
      setRows(result.rows || []);
      setPassportTotal(result.total || 0);
      setPassportPage(safeRequestedPage);
      return result;
    },
    [passportSearch, passportSort, passportSourceToken],
  );

  const changePassportSort = (key, initialDirection = "asc") => {
    const next = {
      key,
      direction:
        passportSort.key === key
          ? passportSort.direction === "asc"
            ? "desc"
            : "asc"
          : initialDirection,
    };
    togglePassportSort(key, initialDirection);
    runBusy("passportLocal", () =>
      fetchPassportPage(1, passportSearch, passportSourceToken, next),
    );
  };

  useEffect(() => {
    if (!passportWindowOpen) return;
    const closeOnEscape = (event) => {
      if (event.key === "Escape") setPassportWindowOpen(false);
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [passportWindowOpen]);

  useEffect(() => {
    if (!canManagePassports) return undefined;
    let alive = true;
    api("/api/vulnerability-passports/refresh-jobs/latest")
      .then((result) => {
        if (alive) setPassportRefreshJob(result.job || null);
      })
      .catch((error) => {
        if (alive) showAlert(error.message || String(error), "error");
      });
    return () => {
      alive = false;
    };
  }, [canManagePassports, showAlert]);

  useEffect(() => {
    if (!passportRefreshJob?.operation_id || !ACTIVE_PASSPORT_JOB_STATUSES.has(passportRefreshJob.status))
      return undefined;
    let alive = true;
    let timerId;
    const poll = async () => {
      try {
        const next = await api(`/api/vulnerability-passports/refresh-jobs/${encodeURIComponent(passportRefreshJob.operation_id)}`);
        if (!alive) return;
        setPassportRefreshJob(next);
        if (ACTIVE_PASSPORT_JOB_STATUSES.has(next.status)) {
          timerId = window.setTimeout(poll, 1000);
          return;
        }
        if (next.status === "completed" || next.status === "completed_with_errors") {
          setPassportJob(next.result?.detail_job || null);
          await fetchPassportPage(1, "", null);
          setPassportSearch("");
          setPassportSourceToken(null);
          showAlert(`Обновление завершено: сохранено ${formatCount(next.result?.db?.saved || 0)} паспортов.${next.status === "completed_with_errors" ? " Тренды не обновлены." : ""}`, next.status === "completed_with_errors" ? "info" : "success");
        } else {
          showAlert(next.message || `Обновление: ${passportJobStatusLabel(next.status)}.`, next.status === "failed" ? "error" : "info");
        }
      } catch (error) {
        if (alive) timerId = window.setTimeout(poll, 3000);
      }
    };
    timerId = window.setTimeout(poll, 500);
    return () => {
      alive = false;
      window.clearTimeout(timerId);
    };
  }, [passportRefreshJob?.operation_id, passportRefreshJob?.status, fetchPassportPage, showAlert]);

  useEffect(() => {
    if (!canManagePassports) return undefined;
    let alive = true;
    api("/api/vulnerability-passports/detail-jobs/active")
      .then((result) => {
        if (alive && result.job) setPassportJob(result.job);
      })
      .catch((error) => {
        if (alive) showAlert(error.message || String(error), "error");
      });
    return () => {
      alive = false;
    };
  }, [canManagePassports, showAlert]);

  useEffect(() => {
    if (
      !passportJob?.job_id ||
      !ACTIVE_PASSPORT_JOB_STATUSES.has(passportJob.status)
    )
      return undefined;
    let alive = true;
    let timerId;
    const poll = async () => {
      try {
        const nextJob = await api(
          `/api/vulnerability-passports/detail-jobs/${encodeURIComponent(passportJob.job_id)}`,
        );
        if (!alive) return;
        setPassportJob(nextJob);
        if (ACTIVE_PASSPORT_JOB_STATUSES.has(nextJob.status)) {
          timerId = window.setTimeout(poll, 1000);
          return;
        }
        await fetchPassportPage(passportPage, passportSearch);
        const message =
          nextJob.status === "completed"
            ? `Детали паспортов загружены: ${formatCount(nextJob.loaded_count)}.`
            : `Синхронизация завершена со статусом «${passportJobStatusLabel(nextJob.status)}». Загружено: ${formatCount(nextJob.loaded_count)}, ошибок: ${formatCount(nextJob.failed_count)}.`;
        showAlert(message, nextJob.status === "completed" ? "success" : "info");
      } catch (error) {
        if (alive) timerId = window.setTimeout(poll, 3000);
      }
    };
    timerId = window.setTimeout(poll, 500);
    return () => {
      alive = false;
      window.clearTimeout(timerId);
    };
  }, [
    fetchPassportPage,
    passportJob?.job_id,
    passportJob?.status,
    passportPage,
    passportSearch,
    showAlert,
  ]);

  const queryPassports = () =>
    runBusy("passportQuery", async () => {
      const requestedLimit = optionalPositiveInteger(
        form.passport_limit,
        "Лимит паспортов",
      );
      const requestedBatchSize = clampNumber(form.batch_size, 5000, 1, 10000);
      const result = await api("/api/vulnerability-passports/query", {
        method: "POST",
        body: JSON.stringify({
          pdql: form.pdql,
          utc_offset: form.utc_offset || null,
          group_ids: splitTokens(form.group_ids),
          asset_ids: splitTokens(form.asset_ids),
          include_nested_groups: form.include_nested_groups,
          limit: requestedLimit,
          batch_size: requestedBatchSize,
          save_to_db: true,
          load_details: form.load_details,
        }),
      });
      const records = result.records || [];
      setRows(records);
      setPassportTotal(result.total || 0);
      setPassportSourceToken(result.pdql_token || null);
      setPassportJob(result.detail_job || null);
      setPassportSearch("");
      setSelected(null);
      setDetail(null);
      setPassportPage(1);
      setPassportWindowOpen(false);
      setQueryRaw(result.raw || null);
      if (records.length) {
        const saved = result.db?.saved;
        const detailJob = result.detail_job;
        const detailsLine = detailJob
          ? `, деталей в очереди: ${formatCount(detailJob.eligible_count)}, свежих в кэше: ${formatCount(detailJob.skipped_fresh_count)}`
          : "";
        const trendSync = result.trend_sync;
        const trendsLine =
          trendSync?.status === "completed"
            ? `, трендовых: ${formatCount(trendSync.total)}`
            : trendSync?.status === "failed"
              ? ", тренды не обновлены"
              : "";
        showAlert(
          `Получено паспортов: ${formatCount(result.total)}${saved == null ? "" : `, сохранено в БД: ${formatCount(saved)}`}${detailsLine}${trendsLine}.`,
          trendSync?.status === "failed" ? "info" : "success",
        );
      } else {
        showAlert(
          "Паспорта не найдены в ответе /assets_grid/data. Raw-ответ показан под таблицей.",
          "info",
        );
      }
    });

  const refreshAllPassports = () =>
    runBusy("passportRefresh", async () => {
      const result = await api("/api/vulnerability-passports/refresh-jobs", { method: "POST" });
      setPassportRefreshJob(result.job);
      showAlert("Обновление паспортов запущено. Прогресс показан под кнопкой.", "info");
    });

  const cancelPassportRefresh = () => {
    if (!passportRefreshJob?.operation_id) return;
    runBusy("passportRefreshCancel", async () => {
      const result = await api(`/api/vulnerability-passports/refresh-jobs/${encodeURIComponent(passportRefreshJob.operation_id)}/cancel`, { method: "POST" });
      setPassportRefreshJob(result);
    });
  };

  const loadLocalPassports = (
    page = 1,
    announce = true,
    pdqlToken = passportSourceToken,
  ) =>
    runBusy("passportLocal", async () => {
      const result = await fetchPassportPage(page, passportSearch, pdqlToken);
      setSelected(null);
      setDetail(null);
      setPassportWindowOpen(false);
      setQueryRaw(null);
      if (announce) {
        showAlert(
          `Загружено из локальной БД: ${formatCount(result.rows?.length || 0)} из ${formatCount(result.total)}.`,
          "success",
        );
      }
    });

  const loadAllLocalPassports = () => {
    setPassportSourceToken(null);
    loadLocalPassports(1, true, null);
  };

  const cancelPassportJob = () => {
    if (!passportJob?.job_id) return;
    runBusy("passportJobCancel", async () => {
      const result = await api(
        `/api/vulnerability-passports/detail-jobs/${encodeURIComponent(passportJob.job_id)}/cancel`,
        {
          method: "POST",
        },
      );
      setPassportJob(result);
      showAlert("Остановка фоновой загрузки запрошена.", "info");
    });
  };

  const openPassport = (row) =>
    runBusy("passportDetail", async () => {
      if (!row.internal_id)
        throw new Error("У записи нет @VulnerPassport.internalId.");
      setSelected(row);
      setPassportWindowOpen(true);
      if (row.raw_detail) {
        setDetail(row.raw_detail);
        return;
      }
      setDetail(null);
      const result = await api(
        `/api/vulnerability-passports/${encodeURIComponent(row.internal_id)}`,
      );
      const nextRow = result.passport || {
        ...row,
        raw_detail: result.raw || null,
        has_detail: Boolean(result.raw),
      };
      setRows((items) =>
        items.map((item) =>
          item.internal_id === row.internal_id ? nextRow : item,
        ),
      );
      setSelected(nextRow);
      setDetail(result.raw || nextRow.raw_detail || {});
    });

  useEffect(() => {
    const passportId =
      typeof window === "undefined"
        ? null
        : new URLSearchParams(window.location.search).get("passport");
    if (!passportId) return;
    api(`/api/vulnerability-passports/${encodeURIComponent(passportId)}`)
      .then((result) => {
        const row = result.passport || {
          internal_id: passportId,
          raw_detail: result.raw || null,
        };
        setSelected(row);
        setDetail(result.raw || row.raw_detail || {});
        setPassportWindowOpen(true);
      })
      .catch((error) =>
        showAlert(error.operatorMessage || error.message, "error"),
      );
  }, [showAlert]);

  const updatePassport = (row) =>
    runBusy(`passportUpdate:${row.internal_id}`, async () => {
      if (!row.internal_id)
        throw new Error("У записи нет @VulnerPassport.internalId.");
      const result = await api(
        `/api/vulnerability-passports/${encodeURIComponent(row.internal_id)}`,
        {
          method: "PUT",
        },
      );
      const nextRow = result.passport || {
        ...row,
        raw_detail: result.raw || null,
        has_detail: Boolean(result.raw),
      };
      setRows((items) =>
        items.map((item) =>
          item.internal_id === row.internal_id ? nextRow : item,
        ),
      );
      if (selected?.internal_id === row.internal_id) {
        setSelected(nextRow);
        setDetail(result.raw || nextRow.raw_detail || {});
      }
      showAlert(
        `Паспорт ${row.external_id || row.internal_id} обновлён.`,
        "success",
      );
    });

  const deletePassport = (row) => {
    const label = row.external_id || row.name || row.internal_id;
    runBusy(`passportDelete:${row.internal_id}`, async () => {
      if (!row.internal_id)
        throw new Error("У записи нет @VulnerPassport.internalId.");
      await api(
        `/api/vulnerability-passports/${encodeURIComponent(row.internal_id)}`,
        { method: "DELETE" },
      );
      setRows((items) =>
        items.filter((item) => item.internal_id !== row.internal_id),
      );
      setPassportTotal((value) => Math.max(0, value - 1));
      if (selected?.internal_id === row.internal_id) {
        setSelected(null);
        setDetail(null);
        setPassportWindowOpen(false);
      }
      showAlert(`Паспорт ${label} удалён.`, "success");
      setPendingPassportDelete(null);
    });
  };

  const passportJobProgress = passportJob?.eligible_count
    ? Math.min(
        100,
        Math.round(
          (passportJob.processed_count / passportJob.eligible_count) * 100,
        ),
      )
    : 100;
  const passportRefreshActive = Boolean(passportRefreshJob && ACTIVE_PASSPORT_JOB_STATUSES.has(passportRefreshJob.status));
  const passportRefreshPercent = Math.max(0, Math.min(100, Number(passportRefreshJob?.progress_percent || 0)));

  return (
    <Panel id="passports">
      {canManagePassports ? (
        <>
          <Disclosure
            title="Загрузить из MP VM"
            meta={form.load_details ? "С деталями" : null}
          >
            <Field label="PDQL запрос">
              <textarea
                className="code-input"
                rows={6}
                value={form.pdql}
                onChange={(event) => update("pdql", event.target.value)}
              />
            </Field>
            <div className="form-grid form-grid--four">
              <Field label="Часовой пояс">
                <input
                  value={form.utc_offset}
                  onChange={(event) => update("utc_offset", event.target.value)}
                />
              </Field>
              <Field label="Группы">
                <input
                  value={form.group_ids}
                  onChange={(event) => update("group_ids", event.target.value)}
                  placeholder="ID через запятую"
                />
              </Field>
              <Field label="Активы">
                <input
                  value={form.asset_ids}
                  onChange={(event) => update("asset_ids", event.target.value)}
                  placeholder="ID через запятую"
                />
              </Field>
              <Field label="Сколько загрузить">
                <input
                  value={form.passport_limit}
                  onChange={(event) =>
                    update("passport_limit", event.target.value)
                  }
                  type="number"
                  min="1"
                  placeholder="Без лимита"
                />
              </Field>
              <Field label="Размер пачки">
                <input
                  value={form.batch_size}
                  onChange={(event) => update("batch_size", event.target.value)}
                  type="number"
                  min="1"
                  max="10000"
                />
              </Field>
              <Toggle
                label="Включая вложенные группы"
                checked={form.include_nested_groups}
                onChange={(value) => update("include_nested_groups", value)}
              />
              <Toggle
                label="Сразу загрузить детали"
                checked={form.load_details}
                onChange={(value) => update("load_details", value)}
              />
            </div>
          </Disclosure>
        </>
      ) : null}
      <div className="action-row">
        {canManagePassports ? (
          <>
            <Button
              busy={busy.passportRefresh}
              disabled={passportRefreshActive || ACTIVE_PASSPORT_JOB_STATUSES.has(passportJob?.status)}
              onClick={refreshAllPassports}
            >
              Обновить
            </Button>
            <Button busy={busy.passportQuery} disabled={passportRefreshActive} onClick={queryPassports}>
              Выполнить PDQL
            </Button>
          </>
        ) : null}
        <Button
          variant="secondary"
          busy={busy.passportLocal}
          onClick={loadAllLocalPassports}
        >
          Сохранённые
        </Button>
        <div className="inline-metric">
          На странице: <span>{formatCount(rows.length)}</span> · всего:{" "}
          <span>{formatCount(passportTotal)}</span>
        </div>
      </div>
      {canManagePassports && passportRefreshJob && passportRefreshJob.status !== "completed" ? (
        <section className={`passport-job passport-job--${passportRefreshJob.status}`} aria-live="polite">
          <div className="passport-job__header">
            <div>
              <strong>Обновление списка паспортов: {passportJobStatusLabel(passportRefreshJob.status)}</strong>
              <span>{passportRefreshPercent}% · {passportRefreshJob.message}</span>
            </div>
            {passportRefreshActive ? (
              <Button variant="tiny-danger" busy={busy.passportRefreshCancel} disabled={passportRefreshJob.status === "cancelling"} onClick={cancelPassportRefresh}>
                Остановить
              </Button>
            ) : null}
          </div>
          <div className="passport-job__track" role="progressbar" aria-label="Обновление списка паспортов" aria-valuemin="0" aria-valuemax="100" aria-valuenow={passportRefreshPercent}>
            <span style={{ width: `${passportRefreshPercent}%` }} />
          </div>
        </section>
      ) : null}
      {canManagePassports && passportJob && passportJob.status !== "completed" ? (
        <section
          className={`passport-job passport-job--${passportJob.status}`}
          aria-live="polite"
        >
          <div className="passport-job__header">
            <div>
              <strong>
                Фоновая загрузка деталей:{" "}
                {passportJobStatusLabel(passportJob.status)}
              </strong>
              <span>
                Обработано {formatCount(passportJob.processed_count)} из{" "}
                {formatCount(passportJob.eligible_count)} · загружено{" "}
                {formatCount(passportJob.loaded_count)} · ошибок{" "}
                {formatCount(passportJob.failed_count)} · свежих в кэше{" "}
                {formatCount(passportJob.skipped_fresh_count)}
              </span>
            </div>
            {ACTIVE_PASSPORT_JOB_STATUSES.has(passportJob.status) ? (
              <Button
                variant="tiny-danger"
                busy={busy.passportJobCancel}
                onClick={cancelPassportJob}
              >
                Остановить
              </Button>
            ) : null}
          </div>
          <div
            className="passport-job__track"
            role="progressbar"
            aria-valuemin="0"
            aria-valuemax="100"
            aria-valuenow={passportJobProgress}
          >
            <span style={{ width: `${passportJobProgress}%` }} />
          </div>
          {passportJob.message ? <small>{passportJob.message}</small> : null}
        </section>
      ) : null}
      <div className="passport-controls">
        <input
          value={passportSearch}
          onChange={(event) => setPassportSearch(event.target.value)}
          onKeyDown={(event) =>
            event.key === "Enter" && loadLocalPassports(1, false)
          }
          placeholder="CVE, название или пакет"
        />
        <Button
          variant="secondary"
          busy={busy.passportLocal}
          onClick={() => loadLocalPassports(1, false)}
        >
          Найти
        </Button>
        <select
          value={safePage}
          onChange={(event) =>
            loadLocalPassports(Number(event.target.value), false)
          }
          disabled={totalPages <= 1}
        >
          {Array.from({ length: totalPages }, (_, index) => (
            <option value={index + 1} key={index + 1}>
              Страница {index + 1} / {totalPages}
            </option>
          ))}
        </select>
      </div>
      <div className="table-shell passport-table-shell">
        <table className="passport-table">
          <thead>
            <tr>
              <SortableHeader
                column="score"
                sort={passportSort}
                onSort={changePassportSort}
                initialDirection="desc"
              >
                Оценка
              </SortableHeader>
              <SortableHeader
                column="name"
                sort={passportSort}
                onSort={changePassportSort}
              >
                Название
              </SortableHeader>
              <SortableHeader
                column="severity"
                sort={passportSort}
                onSort={changePassportSort}
              >
                Критичность
              </SortableHeader>
              <SortableHeader
                column="package"
                sort={passportSort}
                onSort={changePassportSort}
              >
                Пакет
              </SortableHeader>
              <SortableHeader
                column="detail_updated_at"
                sort={passportSort}
                onSort={changePassportSort}
                initialDirection="desc"
              >
                Детали
              </SortableHeader>
              <th>Действия</th>
            </tr>
          </thead>
          <tbody>
            {pageRows.length ? (
              pageRows.map((row, rowIndex) => (
                <tr
                  key={
                    row.internal_id ||
                    row.external_id ||
                    `${row.name}-${rowIndex}`
                  }
                  className={
                    selected?.internal_id === row.internal_id
                      ? "is-selected"
                      : ""
                  }
                >
                  <td>
                    <span className="score-badge">{row.score || "—"}</span>
                  </td>
                  <td className="wide-cell">
                    <strong>
                      {row.name || row.external_id || "Без названия"}
                    </strong>
                    <span>{row.external_id}</span>
                    <small className="table-cell-meta">
                      {(row.cves || [])
                        .map((item) => item.display_name)
                        .filter(Boolean)
                        .join(", ") || "CVE не указан"}
                    </small>
                    {row.short_description ? (
                      <details className="table-row-details">
                        <summary>Описание</summary>
                        <p>{row.short_description}</p>
                      </details>
                    ) : null}
                  </td>
                  <td>
                    <Severity value={row.severity} />
                  </td>
                  <td>
                    {[row.package_id, row.package_version]
                      .filter(Boolean)
                      .join(" / ") || "—"}
                  </td>
                  <td>
                    {row.has_detail || row.raw_detail ? (
                      <FreshnessBadge
                        value={row.detail_updated_at || row.last_seen}
                      />
                    ) : (
                      "нет"
                    )}
                  </td>
                  <td>
                    <div className="row-actions">
                      <Button
                        variant="tiny"
                        busy={
                          busy.passportDetail &&
                          selected?.internal_id === row.internal_id
                        }
                        onClick={() => openPassport(row)}
                      >
                        Открыть
                      </Button>
                      {canManagePassports ? (
                        <ActionMenu label="Ещё">
                          <Button
                            variant="tiny"
                            busy={busy[`passportUpdate:${row.internal_id}`]}
                            onClick={() => updatePassport(row)}
                          >
                            Обновить
                          </Button>
                          <Button
                            variant="tiny-danger"
                            busy={busy[`passportDelete:${row.internal_id}`]}
                            onClick={() => setPendingPassportDelete(row)}
                          >
                            Удалить
                          </Button>
                        </ActionMenu>
                      ) : null}
                    </div>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={6} className="empty-cell">
                  {passportTotal
                    ? "На этой странице нет записей."
                    : "Нажмите «Сохранённые», чтобы показать паспорта."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {passportTotal ? (
        <div className="passport-pagination">
          <span>
            Страница {formatCount(safePage)} из {formatCount(totalPages)} ·
            показано {formatCount(pageRows.length)} из{" "}
            {formatCount(passportTotal)}
          </span>
          <div>
            <Button
              variant="tiny"
              disabled={safePage <= 1 || busy.passportLocal}
              onClick={() => loadLocalPassports(safePage - 1, false)}
            >
              Назад
            </Button>
            <Button
              variant="tiny"
              disabled={safePage >= totalPages || busy.passportLocal}
              onClick={() => loadLocalPassports(safePage + 1, false)}
            >
              Вперёд
            </Button>
          </div>
        </div>
      ) : null}
      {canManagePassports && queryRaw && !rows.length ? (
        <details className="raw-details">
          <summary>Raw-ответ PDQL запроса</summary>
          <pre>{JSON.stringify(queryRaw, null, 2)}</pre>
        </details>
      ) : null}
      {passportWindowOpen ? (
        <PassportModal
          title="Карточка паспорта уязвимости"
          className="asset-modal"
          overlayClassName="asset-modal-overlay"
          closeLabel="Закрыть"
          onClose={() => setPassportWindowOpen(false)}
        >
          <PassportCard
            row={selected}
            detail={detail}
            loading={busy.passportDetail && !detail}
          />
        </PassportModal>
      ) : null}
      <ConfirmDialog
        open={Boolean(pendingPassportDelete)}
        title="Удалить локальный паспорт?"
        description={`Паспорт «${pendingPassportDelete?.external_id || pendingPassportDelete?.name || pendingPassportDelete?.internal_id || ""}» будет удалён только из PostgreSQL.`}
        impact={[
          "Паспорт в MP VM не изменится",
          "Данные можно повторно загрузить через PDQL",
        ]}
        confirmLabel="Удалить из БД"
        busy={Boolean(
          pendingPassportDelete &&
          busy[`passportDelete:${pendingPassportDelete.internal_id}`],
        )}
        onClose={() => setPendingPassportDelete(null)}
        onConfirm={() => deletePassport(pendingPassportDelete)}
      />
    </Panel>
  );
}

function AssetCard({ card, loading, onOpenPassport }) {
  const raw = assetCardRaw(card);
  const root = card?.root || raw.root || {};
  const data = root.data || {};
  const stats = assetCardStats(card);
  const [activeTab, setActiveTab] = useState("summary");
  const tabIdPrefix = React.useId().replaceAll(":", "");
  const assetTabs = [
    ["summary", "Сводка"],
    ["vulnerabilities", "Уязвимости"],
    ["configuration", "Конфигурация"],
    ["history", "История"],
  ];
  const assetId = firstFilled(card?.asset_id, raw.asset_id, root.objectId);
  const assetType = firstFilled(card?.asset_type, raw.asset_type, root.type);
  const hostname = firstFilled(card?.hostname, data.hostname, root.displayName);
  const ipAddress = firstFilled(card?.ip_address, data.ipAddress);
  const fqdn = firstFilled(card?.fqdn, data.fqdn);
  const osLine = [
    firstFilled(card?.os_name, data.osName),
    firstFilled(card?.os_version, data.osVersion),
  ]
    .filter(Boolean)
    .join(" ");

  useEffect(() => {
    if (!card) return;
    setActiveTab("summary");
  }, [card?.asset_id]);

  useEffect(() => {
    if (!card) return undefined;
    const started = performance.now();
    const frame = window.requestAnimationFrame(() => {
      recordFrontendEvent(
        "ui.section.rendered",
        {
          section: `asset-card:${activeTab}`,
          asset_id: assetId,
          duration_ms: Math.round((performance.now() - started) * 100) / 100,
        },
        { section: activeTab },
      );
    });
    return () => window.cancelAnimationFrame(frame);
  }, [activeTab, assetId, card]);

  if (!card) {
    return (
      <div className="passport-placeholder">
        Соберите карточку или откройте сохранённую запись из БД.
      </div>
    );
  }

  return (
    <div className="asset-console">
      <div
        className="asset-tabs"
        role="tablist"
        aria-label="Разделы карточки актива"
      >
        {assetTabs.map(([id, label], index) => (
          <button
            type="button"
            role="tab"
            id={`${tabIdPrefix}-tab-${id}`}
            aria-controls={`${tabIdPrefix}-panel-${id}`}
            aria-selected={activeTab === id}
            tabIndex={activeTab === id ? 0 : -1}
            className={activeTab === id ? "is-active" : ""}
            onClick={() => setActiveTab(id)}
            onKeyDown={(event) => {
              if (
                !["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)
              )
                return;
              event.preventDefault();
              const nextIndex =
                event.key === "Home"
                  ? 0
                  : event.key === "End"
                    ? assetTabs.length - 1
                    : (index +
                        (event.key === "ArrowRight" ? 1 : -1) +
                        assetTabs.length) %
                      assetTabs.length;
              setActiveTab(assetTabs[nextIndex][0]);
              const tabButtons =
                event.currentTarget.parentElement?.querySelectorAll(
                  '[role="tab"]',
                );
              tabButtons?.[nextIndex]?.focus();
            }}
            key={id}
          >
            {label}
          </button>
        ))}
      </div>
      {activeTab === "summary" ? (
        <div
          className="asset-tabpanel"
          role="tabpanel"
          id={`${tabIdPrefix}-panel-summary`}
          aria-labelledby={`${tabIdPrefix}-tab-summary`}
        >
          <AssetSummaryTab
            assetId={assetId}
            assetType={assetType}
            hostname={hostname}
            fqdn={fqdn}
            ipAddress={ipAddress}
            osLine={osLine}
            root={root}
            stats={stats}
            loading={loading}
          />
        </div>
      ) : null}
      {activeTab === "history" ? <AssetHistoryTab assetId={assetId} /> : null}
      {activeTab === "vulnerabilities" ? (
        <div
          className="asset-tabpanel"
          role="tabpanel"
          id={`${tabIdPrefix}-panel-vulnerabilities`}
          aria-labelledby={`${tabIdPrefix}-tab-vulnerabilities`}
        >
          {assetId ? (
            <AssetVulnerabilitiesTabPaged
              assetId={assetId}
              onOpenPassport={onOpenPassport}
            />
          ) : (
            <AssetSectionLoading loading={false} />
          )}
        </div>
      ) : null}
      {activeTab === "configuration" ? (
        <div
          className="asset-tabpanel"
          role="tabpanel"
          id={`${tabIdPrefix}-panel-configuration`}
          aria-labelledby={`${tabIdPrefix}-tab-configuration`}
        >
          {assetId ? (
            <AssetConfigurationTab assetId={assetId} card={card} />
          ) : (
            <AssetSectionLoading loading={false} />
          )}
        </div>
      ) : null}
    </div>
  );
}

function AssetSectionLoading({ loading }) {
  return (
    <div className="passport-placeholder">
      {loading
        ? "Раздел загружается..."
        : "Раздел будет загружен при открытии."}
    </div>
  );
}

function AssetHistoryTab({ assetId }) {
  const [state, setState] = useState({ loading: true, items: [], error: null });
  useEffect(() => {
    let active = true;
    api(`/api/asset-cards/${encodeURIComponent(assetId)}/history`)
      .then(
        (data) =>
          active &&
          setState({ loading: false, items: data.items || [], error: null }),
      )
      .catch(
        (error) => active && setState({ loading: false, items: [], error }),
      );
    return () => {
      active = false;
    };
  }, [assetId]);
  if (state.loading) return <div className="muted-text">Загрузка истории…</div>;
  if (state.error)
    return <div className="error-text">История пока недоступна.</div>;
  return (
    <div className="asset-history-list">
      {state.items.length ? (
        state.items.map((item) => (
          <PassportSection
            key={item.captured_at}
            title={new Date(item.captured_at).toLocaleString()}
          >
            <KeyValue
              label="Качество"
              value={`${item.quality?.status || "—"} (${item.quality?.score ?? "—"})`}
            />
            <KeyValue
              label="Изменений"
              value={formatCount(item.changes?.length || 0)}
            />
          </PassportSection>
        ))
      ) : (
        <span className="muted-text">
          История появится после следующего обновления карточки.
        </span>
      )}
    </div>
  );
}

function AssetSummaryTab({
  assetId,
  assetType,
  hostname,
  fqdn,
  ipAddress,
  osLine,
  root,
  stats,
  loading,
}) {
  const warnings = stats.warnings || [];
  return (
    <div className="asset-summary-grid">
      <div className="asset-summary-main">
        <PassportSection title="Основная информация">
          <KeyValue label="Тип" value={assetType} />
          <KeyValue label="Имя хоста" value={hostname} />
          <KeyValue label="FQDN" value={fqdn} />
          <KeyValue label="IP" value={ipAddress} />
          <KeyValue label="ОС" value={osLine} />
          <KeyValue label="ID актива" value={assetId} />
          {loading ? <KeyValue label="Состояние" value="собирается" /> : null}
        </PassportSection>
        <PassportSection title="Предупреждения">
          {warnings.length ? (
            warnings
              .slice(0, 16)
              .map((warning) => <code key={warning}>{warning}</code>)
          ) : (
            <span className="muted-text">Предупреждений нет.</span>
          )}
        </PassportSection>
      </div>
      <div className="asset-summary-side">
        <div className="asset-summary-card">
          <span>Критичность</span>
          <strong>
            {root?.vulnerabilityLevel
              ? severityLabel(root.vulnerabilityLevel)
              : "—"}
          </strong>
        </div>
      </div>
    </div>
  );
}

function assetFindingPassports(finding) {
  const byId = new Map();
  const summaries = Array.isArray(finding?.passports) ? finding.passports : [];
  summaries.forEach((passport) => {
    if (passport?.internal_id) byId.set(passport.internal_id, passport);
  });
  (finding?.passport_ids || []).forEach((passportId) => {
    if (passportId && !byId.has(passportId))
      byId.set(passportId, { internal_id: passportId });
  });
  const matchPriority = {
    vulner_id: 0,
    cve_os_version: 1,
    cve_os: 2,
    cve_generic: 3,
    cve: 4,
  };
  return Array.from(byId.values()).sort(
    (left, right) =>
      (matchPriority[left.match_method] ?? 99) -
        (matchPriority[right.match_method] ?? 99) ||
      assetPassportLabel(left).localeCompare(assetPassportLabel(right), "ru"),
  );
}

function assetPassportMatchLabel(passport) {
  return {
    vulner_id: "точное совпадение",
    cve_os_version: "CVE, ОС и версия",
    cve_os: "CVE и дистрибутив",
    cve_generic: "совпадение по CVE",
    cve: "совпадение по CVE",
  }[passport?.match_method];
}

function assetPassportLabel(passport) {
  return firstFilled(
    passport?.name,
    passport?.external_id,
    passport?.internal_id,
    "Паспорт",
  );
}

function assetSourceKey(source, index) {
  return (
    source?.source ||
    source?.collection_type ||
    source?.title ||
    `source-${index}`
  );
}

function assetGroupKey(source, group, index) {
  return `${source?.source || group?.source || "source"}:${group?.collection_id || index}`;
}

function dockerPackageSections(rows) {
  const sections = new Map();
  rows.forEach((finding) => {
    const packageName = finding.package_name || "Пакет не определён";
    const packageVersion = finding.package_version || "";
    const fixedVersion = finding.fixed_version || "";
    const key = `${packageName}\u0000${packageVersion}\u0000${fixedVersion}`;
    if (!sections.has(key)) {
      sections.set(key, {
        key,
        package_name: packageName,
        package_version: packageVersion,
        fixed_version: fixedVersion,
        rows: [],
      });
    }
    sections.get(key).rows.push(finding);
  });
  return Array.from(sections.values());
}

function dockerGroupMetadata(group) {
  const containerMetadata = [
    group.docker_engine,
    group.container_id ? `Container ID: ${group.container_id}` : "",
    group.image_id ? `Image ID: ${group.image_id}` : "",
    group.digest && group.digest !== group.image_id
      ? `Digest: ${group.digest}`
      : "",
  ].filter(Boolean);
  const isContainerGroup = Boolean(
    group.container_name ||
    group.container_id ||
    group.docker_engine ||
    group.image_id,
  );

  if (isContainerGroup) {
    return (
      containerMetadata.join(" · ") || "Метаданные контейнера не определены"
    );
  }

  return (
    [
      [group.image_os_name, group.image_os_version].filter(Boolean).join(" "),
      group.digest,
    ]
      .filter(Boolean)
      .join(" · ") || "ОС образа не определена"
  );
}

function AssetVulnerabilitiesTabPaged({ assetId, onOpenPassport }) {
  const [snapshot, setSnapshot] = useState({ header: {}, sources: [] });
  const [loadingGroups, setLoadingGroups] = useState(false);
  const [error, setError] = useState("");
  const [collapsedSources, setCollapsedSources] = useState([]);
  const [expandedGroups, setExpandedGroups] = useState([]);
  const [findingsByGroup, setFindingsByGroup] = useState({});
  const [loadingFindings, setLoadingFindings] = useState({});
  const [tableSort, toggleTableSort] = useTableSort();
  const [vulnerabilityView, setVulnerabilityView] = useState("regular");
  const allSources = Array.isArray(snapshot.sources) ? snapshot.sources : [];
  const dockerSource = allSources.find((source) => source.source === "docker");
  const dockerCount = (dockerSource?.groups || []).reduce(
    (total, group) => total + (Number(group.vulnerabilities_count) || 0),
    0,
  );
  const sources = allSources.filter((source) =>
    vulnerabilityView === "docker"
      ? source.source === "docker"
      : source.source !== "docker",
  );
  const header = snapshot.header || {};
  const collapsedSourceSet = useMemo(
    () => new Set(collapsedSources),
    [collapsedSources],
  );
  const expandedGroupSet = useMemo(
    () => new Set(expandedGroups),
    [expandedGroups],
  );
  const sourceKeys = useMemo(() => sources.map(assetSourceKey), [sources]);
  const loadedFindingCount = sources.reduce(
    (total, source) =>
      total +
      (source.groups || []).reduce(
        (groupTotal, group, groupIndex) =>
          groupTotal +
          (findingsByGroup[assetGroupKey(source, group, groupIndex)]?.rows
            ?.length || 0),
        0,
      ),
    0,
  );
  const sourceCount = (source) =>
    (source.groups || []).reduce(
      (total, group) => total + (Number(group.vulnerabilities_count) || 0),
      0,
    );

  useEffect(() => {
    let alive = true;
    setSnapshot({ header: {}, sources: [] });
    setCollapsedSources([]);
    setExpandedGroups([]);
    setFindingsByGroup({});
    setLoadingFindings({});
    setError("");
    setVulnerabilityView("regular");
    if (!assetId) return undefined;
    setLoadingGroups(true);
    api(
      `/api/asset-cards/${encodeURIComponent(assetId)}/vulnerabilities/groups`,
    )
      .then((result) => {
        if (!alive) return;
        setSnapshot(result.vulnerabilities || { header: {}, sources: [] });
      })
      .catch((requestError) => {
        if (alive) setError(requestError.message || String(requestError));
      })
      .finally(() => {
        if (alive) setLoadingGroups(false);
      });
    return () => {
      alive = false;
    };
  }, [assetId]);

  const loadFindings = useCallback(
    async (source, group, offset = 0) => {
      const key = assetGroupKey(source, group, 0);
      if (!group?.collection_id || !assetId || loadingFindings[key]) return;
      setLoadingFindings((current) => ({ ...current, [key]: true }));
      const params = new URLSearchParams({
        source: source?.source || group.source || "",
        collection_id: group.collection_id,
        limit: String(ASSET_VULNERABILITY_FINDING_LIMIT),
        offset: String(offset),
      });
      try {
        const result = await api(
          `/api/asset-cards/${encodeURIComponent(assetId)}/vulnerabilities/findings?${params.toString()}`,
        );
        setFindingsByGroup((current) => {
          const previousRows = offset ? current[key]?.rows || [] : [];
          return {
            ...current,
            [key]: {
              ...result,
              rows: [...previousRows, ...(result.rows || [])],
            },
          };
        });
      } catch (requestError) {
        setError(requestError.message || String(requestError));
      } finally {
        setLoadingFindings((current) => ({ ...current, [key]: false }));
      }
    },
    [assetId, loadingFindings],
  );

  const toggleSource = useCallback((key) => {
    setCollapsedSources((current) =>
      current.includes(key)
        ? current.filter((item) => item !== key)
        : [...current, key],
    );
  }, []);

  const toggleGroup = useCallback(
    (source, group, groupIndex) => {
      const key = assetGroupKey(source, group, groupIndex);
      setExpandedGroups((current) => {
        if (current.includes(key))
          return current.filter((item) => item !== key);
        return [...current, key];
      });
      if (!expandedGroupSet.has(key) && !findingsByGroup[key]) {
        void loadFindings(source, group, 0);
      }
    },
    [expandedGroupSet, findingsByGroup, loadFindings],
  );

  const expandAll = () => setCollapsedSources([]);
  const collapseAll = () => {
    setCollapsedSources(sourceKeys);
    setExpandedGroups([]);
  };

  return (
    <section
      className="asset-vulnerability-pane"
      aria-label="Уязвимости актива"
    >
      <div
        className="asset-vulnerability-subtabs"
        role="tablist"
        aria-label="Тип уязвимостей"
      >
        <button
          type="button"
          role="tab"
          aria-selected={vulnerabilityView === "regular"}
          className={vulnerabilityView === "regular" ? "is-active" : ""}
          onClick={() => setVulnerabilityView("regular")}
        >
          ОС и ПО
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={vulnerabilityView === "docker"}
          className={vulnerabilityView === "docker" ? "is-active" : ""}
          onClick={() => setVulnerabilityView("docker")}
        >
          Docker-контейнеры · {formatCount(dockerCount)}
        </button>
      </div>
      <div className="asset-vulnerability-toolbar">
        {sources.map((source, index) => (
          <span key={assetSourceKey(source, index)}>
            {source.source === "os"
              ? "Уязвимости ОС"
              : source.source === "docker"
                ? "Docker-контейнеры"
                : "Уязвимости ПО"}
            : <strong>{formatCount(sourceCount(source))}</strong>
          </span>
        ))}
        {vulnerabilityView === "regular" ? (
          <span>
            Сетевые сервисы:{" "}
            <strong>
              {formatCount(header.network_services_vulnerabilities_count || 0)}
            </strong>
          </span>
        ) : null}
      </div>
      <div className="asset-vulnerability-heading">
        <div>
          <strong>
            {vulnerabilityView === "docker"
              ? "Уязвимости Docker-контейнеров"
              : "Уязвимости"}
          </strong>
          <span>
            Загружено {formatCount(loadedFindingCount)} из{" "}
            {formatCount(
              vulnerabilityView === "docker"
                ? dockerCount
                : header.os_soft_vulnerabilities_count || loadedFindingCount,
            )}{" "}
            уязвимостей.
          </span>
          {vulnerabilityView === "docker" &&
          dockerSource?.status === "fallback" ? (
            <span className="asset-docker-source-status">
              Docker-PDQL недоступен — использованы структурированные данные
              карточки.
            </span>
          ) : null}
        </div>
        {sourceKeys.length ? (
          <div className="asset-vulnerability-controls">
            <button type="button" onClick={expandAll}>
              Развернуть все
            </button>
            <button type="button" onClick={collapseAll}>
              Свернуть все
            </button>
          </div>
        ) : null}
      </div>
      {error ? (
        <div className="passport-load-error" role="alert">
          {error}
        </div>
      ) : null}
      <div
        className="asset-vulnerability-table-shell"
        tabIndex="0"
        aria-label="Прокручиваемый список уязвимостей"
      >
        <table className="asset-vulnerability-table">
          <thead>
            <tr>
              <SortableHeader
                column="name"
                sort={tableSort}
                onSort={toggleTableSort}
              >
                Уязвимости
              </SortableHeader>
              <SortableHeader
                column="cvss_score"
                sort={tableSort}
                onSort={toggleTableSort}
                initialDirection="desc"
              >
                Интегральная уязвимость
              </SortableHeader>
              <SortableHeader
                column="cve_name"
                sort={tableSort}
                onSort={toggleTableSort}
              >
                CVE
              </SortableHeader>
            </tr>
          </thead>
          <tbody>
            {sources.map((source, sourceIndex) => {
              const sourceKey = assetSourceKey(source, sourceIndex);
              const sourceCollapsed = collapsedSourceSet.has(sourceKey);
              const groups = sortRows(source.groups || [], tableSort, {
                name: (group) => group.name,
                cve_name: (group) => group.name,
              });
              return (
                <React.Fragment key={sourceKey}>
                  <tr className="asset-vulnerability-source">
                    <td colSpan={3}>
                      <button
                        type="button"
                        className="asset-vulnerability-toggle"
                        aria-expanded={!sourceCollapsed}
                        onClick={() => toggleSource(sourceKey)}
                      >
                        <span
                          className="asset-vulnerability-caret"
                          aria-hidden="true"
                        >
                          {sourceCollapsed ? "›" : "⌄"}
                        </span>
                        <span>
                          {source.source === "docker"
                            ? "Docker-контейнеры"
                            : source.title ||
                              (source.source === "os"
                                ? "Уязвимости ОС"
                                : "Уязвимости программного обеспечения")}{" "}
                          ({formatCount(sourceCount(source))})
                        </span>
                      </button>
                    </td>
                  </tr>
                  {!sourceCollapsed
                    ? groups.map((group, groupIndex) => {
                        const key = assetGroupKey(source, group, groupIndex);
                        const expanded = expandedGroupSet.has(key);
                        const page = findingsByGroup[key] || {
                          rows: [],
                          total: Number(group.vulnerabilities_count) || 0,
                          has_more: false,
                        };
                        const rows = sortRows(page.rows || [], tableSort, {
                          name: (finding) => finding.name || finding.cve_name,
                        });
                        const displayedRows =
                          source.source === "docker"
                            ? dockerPackageSections(rows).flatMap((section) => [
                                { ...section, __dockerPackage: true },
                                ...section.rows,
                              ])
                            : rows;
                        return (
                          <React.Fragment key={key}>
                            <tr className="asset-vulnerability-group">
                              <td>
                                <button
                                  type="button"
                                  className="asset-vulnerability-toggle"
                                  aria-expanded={expanded}
                                  onClick={() =>
                                    toggleGroup(source, group, groupIndex)
                                  }
                                >
                                  <span
                                    className="asset-vulnerability-caret"
                                    aria-hidden="true"
                                  >
                                    {expanded ? "⌄" : "›"}
                                  </span>
                                  <span>
                                    <strong>
                                      {group.container_name ||
                                        group.name ||
                                        group.container_id ||
                                        "Без названия"}
                                    </strong>{" "}
                                    (
                                    {formatCount(
                                      group.vulnerabilities_count ||
                                        page.total ||
                                        0,
                                    )}
                                    )
                                  </span>
                                  {group.truncated ? (
                                    <small>Показана неполная коллекция</small>
                                  ) : null}
                                  {source.source === "docker" ? (
                                    <small className="asset-docker-image-meta">
                                      {dockerGroupMetadata(group)}
                                    </small>
                                  ) : null}
                                </button>
                              </td>
                              <td>
                                {formatVulnerabilityScore(group.cvss_score)}
                              </td>
                              <td />
                            </tr>
                            {expanded
                              ? displayedRows.map((finding, findingIndex) => {
                                  if (finding.__dockerPackage) {
                                    return (
                                      <tr
                                        className="asset-docker-package"
                                        key={`package-${finding.key}`}
                                      >
                                        <td colSpan={3}>
                                          <span className="asset-vulnerability-leaf">
                                            ›
                                          </span>
                                          <strong>
                                            {finding.package_name}
                                          </strong>
                                          {finding.package_version
                                            ? ` ${finding.package_version}`
                                            : ""}
                                          {finding.fixed_version
                                            ? ` → ${finding.fixed_version}`
                                            : ""}
                                          <small>
                                            {formatCount(finding.rows.length)}
                                          </small>
                                        </td>
                                      </tr>
                                    );
                                  }
                                  const passports =
                                    assetFindingPassports(finding);
                                  const passport = passports[0];
                                  return (
                                    <tr
                                      className={
                                        source.source === "docker"
                                          ? "asset-vulnerability-finding asset-docker-finding"
                                          : "asset-vulnerability-finding"
                                      }
                                      key={
                                        finding.vulnerability_instance_id ||
                                        `${group.collection_id}-${findingIndex}`
                                      }
                                    >
                                      <td>
                                        <span className="asset-vulnerability-leaf">
                                          •
                                        </span>
                                        <span>
                                          {finding.name ||
                                            finding.cve_name ||
                                            "Уязвимость без названия"}
                                        </span>
                                        {source.source === "docker" &&
                                        finding.status ? (
                                          <small className="asset-docker-package-meta">
                                            Статус: {finding.status}
                                          </small>
                                        ) : null}
                                        {source.source === "docker" &&
                                        finding.how_to_fix ? (
                                          <details className="asset-docker-package-meta">
                                            <summary>Как исправить</summary>
                                            <span>{finding.how_to_fix}</span>
                                          </details>
                                        ) : null}
                                      </td>
                                      <td>
                                        {formatVulnerabilityScore(
                                          finding.cvss_score,
                                        )}
                                      </td>
                                      <td>
                                        {passport ? (
                                          <span className="asset-vulnerability-passport-auto">
                                            <button
                                              type="button"
                                              className="asset-vulnerability-passport-link"
                                              onClick={() =>
                                                onOpenPassport?.(passport)
                                              }
                                              title={`Открыть паспорт ${assetPassportLabel(passport)}`}
                                            >
                                              {finding.cve_name ||
                                                "Открыть паспорт"}
                                            </button>
                                            {assetPassportMatchLabel(
                                              passport,
                                            ) ? (
                                              <small>
                                                {assetPassportMatchLabel(
                                                  passport,
                                                )}
                                              </small>
                                            ) : null}
                                          </span>
                                        ) : (
                                          finding.cve_name || "—"
                                        )}
                                      </td>
                                    </tr>
                                  );
                                })
                              : null}
                            {expanded && loadingFindings[key] ? (
                              <tr>
                                <td colSpan={3} className="empty-cell">
                                  Загрузка...
                                </td>
                              </tr>
                            ) : null}
                            {expanded && page.has_more ? (
                              <tr>
                                <td colSpan={3} className="table-footer">
                                  <Button
                                    variant="tiny"
                                    busy={loadingFindings[key]}
                                    onClick={() =>
                                      loadFindings(
                                        source,
                                        group,
                                        page.rows.length,
                                      )
                                    }
                                  >
                                    Загрузить ещё
                                  </Button>
                                </td>
                              </tr>
                            ) : null}
                          </React.Fragment>
                        );
                      })
                    : null}
                </React.Fragment>
              );
            })}
            {loadingGroups ? (
              <tr>
                <td colSpan={3} className="empty-cell">
                  Загрузка...
                </td>
              </tr>
            ) : null}
            {!loadingGroups &&
            !sources.some((source) => (source.groups || []).length) ? (
              <tr>
                <td colSpan={3} className="empty-cell">
                  {vulnerabilityView === "docker"
                    ? dockerSource?.status === "unavailable"
                      ? "Docker-PDQL недоступен, структурированные данные о контейнерах не найдены."
                      : "Уязвимости Docker-контейнеров для этого актива не найдены."
                    : "Уязвимостей в сохранённом снимке нет."}
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function normalizeAssetTreeEntry(row) {
  return {
    ...row,
    parentPath: row.parentPath ?? row.parent_path ?? null,
    hasChildren: Boolean(row.hasChildren ?? row.has_children),
    depth: Number(row.depth || 0),
  };
}

function mergeAssetTreeEntries(current, incoming) {
  const byPath = new Map(current.map((entry) => [entry.path, entry]));
  incoming.forEach((entry) => {
    if (!entry?.path) return;
    byPath.set(entry.path, { ...(byPath.get(entry.path) || {}), ...entry });
  });
  return Array.from(byPath.values()).sort((left, right) => {
    if (left.path === "asset") return -1;
    if (right.path === "asset") return 1;
    return String(left.path || "").localeCompare(String(right.path || ""));
  });
}

const WINDOWS_ASSET_CARD_EXCLUDED_BRANCHES = new Set([
  "aclaccesslist",
  "aclaccesslists",
  "accountlockoutpolicy",
  "accountlockoutpolicies",
  "appliedaccesslist",
  "appliedaccesslists",
  "arp",
  "arptable",
  "arptables",
  "auditpolicy",
  "auditpolicies",
  "bios",
  "certificate",
  "certificates",
  "cpu",
  "cpus",
  "centralprocessor",
  "dnscache",
  "dnsclient",
  "dnsclientsettings",
  "dynamicrouting",
  "eventlog",
  "eventlogs",
  "eventlogsettings",
  "gpcredentials",
  "group",
  "groups",
  "hdd",
  "hdds",
  "harddisk",
  "harddisks",
  "hypervisor",
  "hypervisors",
  "ipv6",
  "ipv6settings",
  "lanmanserver",
  "lanmanworkstation",
  "logicaldisk",
  "logicaldisks",
  "motherboard",
  "nattable",
  "nattables",
  "neighbor",
  "neighbors",
  "neighbordevices",
  "networkadapter",
  "networkadapters",
  "networkconnection",
  "networkconnections",
  "oscandidates",
  "operatingsystemcandidates",
  "osfingerprints",
  "operatingsystemfingerprint",
  "passwordpolicy",
  "passwordpolicies",
  "pcidevice",
  "pcidevices",
  "peripheral",
  "peripherals",
  "peripheraldevices",
  "powermanagement",
  "printer",
  "printers",
  "roles",
  "trace",
  "traces",
  "traceroutes",
  "usbdevice",
  "usbdevices",
]);

function normalizeAssetCardBranch(value) {
  return String(value || "")
    .replace(/[_-]/g, "")
    .toLowerCase();
}

function isWindowsAssetCard(card) {
  const raw = card || {};
  const root = raw.root || {};
  const rootData = root.data || {};
  return [
    raw.asset_type,
    raw.assetType,
    raw.os_name,
    raw.osName,
    root.type,
    root.assetType,
    root.osName,
    rootData.osName,
    rootData.os_name,
    rootData.operatingSystem,
  ].some((value) =>
    String(value || "")
      .toLowerCase()
      .includes("windows"),
  );
}

function isExcludedWindowsAssetPath(path) {
  return String(path || "")
    .split(/[.\[]/)
    .some((segment) =>
      WINDOWS_ASSET_CARD_EXCLUDED_BRANCHES.has(
        normalizeAssetCardBranch(segment),
      ),
    );
}

function AssetConfigurationTab({ assetId, card }) {
  const [entries, setEntries] = useState([]);
  const [expandedPaths, setExpandedPaths] = useState(["asset"]);
  const [selectedPath, setSelectedPath] = useState("asset");
  const [loadedParents, setLoadedParents] = useState(new Set());
  const [loadingParents, setLoadingParents] = useState({});
  const [detailsByPath, setDetailsByPath] = useState({});
  const [loadingDetails, setLoadingDetails] = useState({});
  const [error, setError] = useState("");
  const expandedSet = useMemo(() => new Set(expandedPaths), [expandedPaths]);
  const selectedEntry = useMemo(
    () =>
      entries.find((entry) => entry.path === selectedPath) ||
      entries[0] ||
      null,
    [entries, selectedPath],
  );
  const visibleTreeEntries = useMemo(
    () =>
      entries.filter(
        (entry) =>
          (!isWindowsAssetCard(card) ||
            !isExcludedWindowsAssetPath(entry.path)) &&
          isAssetTreeEntryVisible(entry, expandedSet, entries),
      ),
    [card, entries, expandedSet],
  );

  const loadTree = useCallback(
    async (parentPath = null) => {
      if (!assetId) return;
      const key = parentPath || "";
      setLoadingParents((current) => ({ ...current, [key]: true }));
      const params = new URLSearchParams({
        limit: String(ASSET_CONFIG_TREE_LIMIT),
      });
      if (parentPath) params.set("parent_path", parentPath);
      try {
        const result = await api(
          `/api/asset-cards/${encodeURIComponent(assetId)}/configuration/tree?${params.toString()}`,
        );
        const nextEntries = (result.rows || [])
          .filter(
            (entry) =>
              !isWindowsAssetCard(card) ||
              !isExcludedWindowsAssetPath(entry.path),
          )
          .map(normalizeAssetTreeEntry);
        setEntries((current) => mergeAssetTreeEntries(current, nextEntries));
        setLoadedParents((current) => {
          const next = new Set(current);
          next.add(key);
          return next;
        });
      } catch (requestError) {
        setError(requestError.message || String(requestError));
      } finally {
        setLoadingParents((current) => ({ ...current, [key]: false }));
      }
    },
    [assetId, card],
  );

  const loadDetail = useCallback(
    async (entry, offset = 0) => {
      if (!assetId || !entry?.path) return;
      const key = entry.path;
      setLoadingDetails((current) => ({ ...current, [key]: true }));
      const params = new URLSearchParams({
        path: entry.path,
        kind: entry.kind || "",
        limit: String(ASSET_CONFIG_DETAIL_LIMIT),
        offset: String(offset),
      });
      try {
        const result = await api(
          `/api/asset-cards/${encodeURIComponent(assetId)}/configuration/detail?${params.toString()}`,
        );
        setDetailsByPath((current) => {
          const previousRows = offset ? current[key]?.rows || [] : [];
          return {
            ...current,
            [key]: {
              ...result,
              rows: [...previousRows, ...(result.rows || [])],
            },
          };
        });
      } catch (requestError) {
        setError(requestError.message || String(requestError));
      } finally {
        setLoadingDetails((current) => ({ ...current, [key]: false }));
      }
    },
    [assetId],
  );

  useEffect(() => {
    setEntries([]);
    setExpandedPaths(["asset"]);
    setSelectedPath("asset");
    setLoadedParents(new Set());
    setLoadingParents({});
    setDetailsByPath({});
    setLoadingDetails({});
    setError("");
    if (assetId) void loadTree(null);
  }, [assetId, loadTree]);

  useEffect(() => {
    if (!entries.length) return;
    setSelectedPath((current) =>
      entries.some((entry) => entry.path === current)
        ? current
        : entries[0].path,
    );
  }, [entries]);

  useEffect(() => {
    if (
      !selectedEntry ||
      detailsByPath[selectedEntry.path] ||
      loadingDetails[selectedEntry.path]
    )
      return;
    void loadDetail(selectedEntry, 0);
  }, [detailsByPath, loadDetail, loadingDetails, selectedEntry]);

  const toggleTreeEntry = useCallback(
    (path) => {
      const entry = entries.find((item) => item.path === path);
      setExpandedPaths((current) =>
        current.includes(path)
          ? current.filter((item) => item !== path)
          : [...current, path],
      );
      if (
        entry?.hasChildren &&
        !expandedSet.has(path) &&
        !loadedParents.has(path) &&
        !loadingParents[path]
      ) {
        void loadTree(path);
      }
    },
    [entries, expandedSet, loadedParents, loadingParents, loadTree],
  );

  const selectEntry = useCallback(
    (path) => {
      const entry = entries.find((item) => item.path === path);
      setSelectedPath(path);
      if (entry && !detailsByPath[path] && !loadingDetails[path]) {
        void loadDetail(entry, 0);
      }
    },
    [detailsByPath, entries, loadDetail, loadingDetails],
  );

  const detail = selectedEntry ? detailsByPath[selectedEntry.path] : null;
  const loadingDetail = selectedEntry
    ? Boolean(loadingDetails[selectedEntry.path])
    : false;

  return (
    <div className="asset-config-layout">
      {error ? (
        <div className="passport-load-error" role="alert">
          {error}
        </div>
      ) : null}
      <AssetTree
        entries={visibleTreeEntries}
        selectedPath={selectedEntry?.path}
        expandedSet={expandedSet}
        onToggle={toggleTreeEntry}
        onSelect={selectEntry}
      />
      <AssetConfigTablePaged
        entry={selectedEntry}
        detail={detail}
        loading={
          loadingDetail || Boolean(loadingParents[""] && !entries.length)
        }
        onLoadMore={() =>
          selectedEntry &&
          detail &&
          loadDetail(selectedEntry, detail.rows?.length || 0)
        }
      />
    </div>
  );
}

function AssetConfigTablePaged({ entry, detail, loading, onLoadMore }) {
  const [tableSort, toggleTableSort] = useTableSort();
  const table = detail || {
    rows: [],
    columns: [{ key: "value", title: "Value" }],
    total: 0,
    has_more: false,
  };
  const sortedRows = useSortedRows(table.rows || [], tableSort);
  if (!entry) {
    return (
      <section className="asset-detail-pane">
        <div className="empty-cell">
          {loading ? "Загрузка..." : "Выберите раздел слева."}
        </div>
      </section>
    );
  }

  return (
    <section
      className={`asset-detail-pane asset-detail-pane--${table.layout || "table"}`}
      aria-label={entry.label}
    >
      {loading && !detail ? (
        <div className="empty-cell">Загрузка...</div>
      ) : null}
      {table.layout === "properties" ? (
        <AssetPropertyList rows={table.rows || []} />
      ) : (
        <div className="table-shell asset-detail-table-shell">
          <table className="asset-detail-table">
            <thead>
              <tr>
                {(table.columns || []).map((column) => (
                  <SortableHeader
                    key={column.key}
                    column={column.key}
                    sort={tableSort}
                    onSort={toggleTableSort}
                  >
                    {column.title}
                  </SortableHeader>
                ))}
              </tr>
            </thead>
            <tbody>
              {sortedRows.length ? (
                sortedRows.map((row, rowIndex) => (
                  <tr key={row.key || rowIndex}>
                    {(table.columns || []).map((column) => (
                      <td key={column.key}>
                        {formatAssetCell(row[column.key])}
                      </td>
                    ))}
                  </tr>
                ))
              ) : (
                <tr>
                  <td
                    colSpan={(table.columns || []).length || 1}
                    className="empty-cell"
                  >
                    В выбранном разделе нет данных.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
      <div className="table-footer">
        <span>
          Показано {formatCount((table.rows || []).length)} из{" "}
          {formatCount(table.total || (table.rows || []).length)} строк.
        </span>
        {table.has_more ? (
          <Button variant="tiny" busy={loading} onClick={onLoadMore}>
            Загрузить ещё
          </Button>
        ) : null}
      </div>
    </section>
  );
}

function AssetTree({ entries, selectedPath, expandedSet, onToggle, onSelect }) {
  return (
    <aside className="asset-tree-pane">
      <div className="asset-tree">
        {entries.map((entry) => (
          <div
            className={
              selectedPath === entry.path
                ? "asset-tree-row is-selected"
                : "asset-tree-row"
            }
            style={{ "--depth": entry.depth }}
            key={entry.path}
          >
            <button
              type="button"
              className={
                entry.hasChildren
                  ? "asset-tree-toggle"
                  : "asset-tree-toggle is-empty"
              }
              onClick={() => entry.hasChildren && onToggle(entry.path)}
              aria-label={expandedSet.has(entry.path) ? "Свернуть" : "Раскрыть"}
            >
              {entry.hasChildren
                ? expandedSet.has(entry.path)
                  ? "▾"
                  : "›"
                : ""}
            </button>
            <button
              type="button"
              className="asset-tree-label"
              onClick={() => onSelect(entry.path)}
            >
              <span>{entry.label}</span>
              {entry.subtitle ? <small>{entry.subtitle}</small> : null}
            </button>
            {entry.meta ? (
              <span className="asset-tree-meta">{entry.meta}</span>
            ) : (
              <span className="asset-tree-search" aria-hidden="true" />
            )}
          </div>
        ))}
      </div>
    </aside>
  );
}

function AssetPropertyList({ rows }) {
  const [tableSort, toggleTableSort] = useTableSort();
  const visibleRows = useSortedRows(rows, tableSort, {
    title: (row) => row.title || row.name,
  }).slice(0, 1000);
  if (!visibleRows.length) {
    return <div className="empty-cell">В выбранном разделе нет данных.</div>;
  }

  return (
    <div className="table-shell asset-detail-table-shell">
      <table className="asset-detail-table asset-property-list">
        <thead>
          <tr>
            <SortableHeader
              column="title"
              sort={tableSort}
              onSort={toggleTableSort}
            >
              Название
            </SortableHeader>
            <SortableHeader
              column="value"
              sort={tableSort}
              onSort={toggleTableSort}
            >
              Значение
            </SortableHeader>
          </tr>
        </thead>
        <tbody>
          {visibleRows.map((row, index) => (
            <tr
              className="asset-property-row"
              style={{ "--depth": row.depth || 0 }}
              key={row.key || index}
            >
              <td className="asset-property-name">
                <span>{row.title || row.name}</span>
                {row.name && row.name !== row.title ? (
                  <small>{row.name}</small>
                ) : null}
              </td>
              <td>
                <strong>{formatAssetCell(row.value)}</strong>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PassportModal({
  children,
  onClose,
  title = "Паспорт уязвимости",
  className = "",
  overlayClassName = "",
  closeLabel = "Закрыть",
}) {
  const titleId = React.useId();
  const dialogRef = useDialogAccessibility(true, onClose);
  const modal = (
    <div className={`passport-modal ${overlayClassName}`} role="presentation">
      <div className="passport-modal__backdrop" onClick={onClose} />
      <div
        ref={dialogRef}
        className={`passport-modal__window ${className}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <div className="passport-modal__bar">
          <strong id={titleId}>{title}</strong>
          <Button variant="ghost" onClick={onClose}>
            {closeLabel}
          </Button>
        </div>
        {children}
      </div>
    </div>
  );
  return typeof document === "undefined"
    ? modal
    : createPortal(modal, document.body);
}

function PassportCard({ row, detail, loading }) {
  const raw = detail || row?.raw_detail || row?.raw_record || {};
  const model = useMemo(() => buildPassportModel(row, raw), [row, raw]);

  if (!row && !detail) {
    return (
      <div className="passport-placeholder">
        Выберите строку в таблице, чтобы открыть карточку паспорта уязвимости.
      </div>
    );
  }

  return (
    <div className="asset-console">
      <div
        className="asset-tabs"
        role="tablist"
        aria-label="Разделы карточки паспорта"
      >
        <button
          type="button"
          role="tab"
          id="passport-summary-tab"
          aria-controls="passport-summary-panel"
          className="is-active"
          aria-selected="true"
        >
          Сводка
        </button>
      </div>
      <div
        className="passport-summary-scroll"
        role="tabpanel"
        id="passport-summary-panel"
        aria-labelledby="passport-summary-tab"
      >
        <PassportSummaryTab model={model} row={row} loading={loading} />
      </div>
    </div>
  );
}

function PassportSummaryTab({ model, row, loading }) {
  return (
    <div className="asset-summary-grid">
      <div className="asset-summary-main">
        <PassportSection title="Основная информация">
          <KeyValue label="Критичность" value={severityLabel(model.severity)} />
          <KeyValue label="Оценка" value={model.score} />
          <KeyValue label="Внешний ID" value={row?.external_id} />
          <KeyValue label="ID паспорта" value={row?.internal_id} />
          <KeyValue label="Пакет" value={model.packageLine} />
          <KeyValue
            label="Дата публикации"
            value={formatPassportDateTime(model.issueTime)}
          />
        </PassportSection>
        <PassportSection title="Описание">
          <p>
            {model.description ||
              "Описания нет."}
          </p>
        </PassportSection>
        <PassportSection title="Как исправить">
          <p>
            {model.remediation ||
              "Рекомендации нет."}
          </p>
        </PassportSection>
      </div>
      <div className="asset-summary-side">
        <div className="asset-summary-card">
          <span>CVE</span>
          <strong>{formatCount(model.cves.length)}</strong>
        </div>
        <div className="asset-summary-card">
          <span>Деталь</span>
          <strong>
            {loading
              ? "загрузка"
              : row?.has_detail || row?.raw_detail
                ? "в БД"
                : "нет"}
          </strong>
        </div>
        <PassportSection title="CVE">
          {model.cves.length ? (
            model.cves.slice(0, 16).map((item) =>
              item.url ? (
                <a
                  href={item.url}
                  target="_blank"
                  rel="noreferrer"
                  key={item.display_name || item.url}
                >
                  {item.display_name || item.url}
                </a>
              ) : (
                <code key={item.display_name}>{item.display_name}</code>
              ),
            )
          ) : (
            <span className="muted-text">CVE не найдены.</span>
          )}
        </PassportSection>
        <PassportSection title="Ссылки">
          {model.links.length ? (
            model.links.slice(0, 12).map((link) => (
              <a href={link} target="_blank" rel="noreferrer" key={link}>
                {link}
              </a>
            ))
          ) : (
            <span className="muted-text">Ссылки не найдены.</span>
          )}
        </PassportSection>
        <PassportSection title="Идентификаторы">
          {model.identifiers.length ? (
            model.identifiers.map((id) => <code key={id}>{id}</code>)
          ) : (
            <span className="muted-text">Идентификаторы не найдены.</span>
          )}
        </PassportSection>
      </div>
    </div>
  );
}

function buildPassportModel(row, raw) {
  const title = firstFilled(
    readPath(raw, "name"),
    readPath(raw, "displayName"),
    readPath(raw, "title"),
    readPath(raw, "vulnerability.name"),
    row?.name,
  );
  const score = firstFilled(
    readPath(raw, "score"),
    readPath(raw, "cvss3Score"),
    readPath(raw, "cvss.score"),
    row?.score,
  );
  const severity = firstFilled(
    readPath(raw, "severityRating"),
    readPath(raw, "severity"),
    row?.severity,
  );
  const cves = mergeCves(row?.cves || [], collectCves(raw));
  const links = collectLinks(raw, cves);
  const identifiers = collectIdentifiers(raw, cves, row);
  const description = firstText(
    readPath(raw, "description"),
    readPath(raw, "vulnerabilityDescription"),
    readPath(raw, "details.description"),
    readPath(raw, "localizedDescription"),
  );
  const remediation = firstText(
    readPath(raw, "howToFix"),
    readPath(raw, "solution"),
    readPath(raw, "recommendation"),
    readPath(raw, "remediation"),
    readPath(raw, "fixDescription"),
  );
  const issueTime = firstFilled(
    readPath(raw, "issueTime"),
    readPath(raw, "publishedAt"),
    row?.issue_time,
  );
  const packageLine = [
    firstFilled(readPath(raw, "packageId"), row?.package_id),
    firstFilled(readPath(raw, "packageVersion"), row?.package_version),
  ]
    .filter(Boolean)
    .join(" / ");

  return {
    title,
    score,
    severity,
    cves,
    links,
    identifiers,
    description,
    remediation,
    issueTime,
    packageLine,
  };
}

function PassportSection({ title, children }) {
  return (
    <section className="passport-section">
      <h4>{title}</h4>
      {children}
    </section>
  );
}

function KeyValue({ label, value }) {
  if (!value) return null;
  return (
    <div className="kv-row">
      <span>{label}</span>
      <strong>{String(value)}</strong>
    </div>
  );
}

function filterAssetCandidates(rows, query) {
  const normalizedQuery = normalizeSearchText(query);
  if (!normalizedQuery) return rows;
  return rows.filter((row) =>
    buildAssetCandidateSearchText(row).includes(normalizedQuery),
  );
}

function buildAssetCandidateSearchText(row) {
  return normalizeSearchText(
    [
      row.asset_id,
      row.display_name,
      row.os_name,
      row.creation_time,
      row.update_time,
      JSON.stringify(row.raw_record || {}),
    ]
      .filter(Boolean)
      .join(" "),
  );
}

function assetCardRaw(card) {
  return card || {};
}

function assetCardStats(card) {
  const raw = assetCardRaw(card);
  return card?.stats || raw.stats || {};
}

function formatVulnerabilityScore(value) {
  if (value === null || value === undefined || value === "") return "—";
  const number = Number(value);
  return Number.isFinite(number)
    ? number.toLocaleString("ru-RU", { maximumFractionDigits: 1 })
    : String(value);
}

function isAssetTreeEntryVisible(entry, expandedSet, entries) {
  if (!entry.parentPath) return true;
  const byPath = new Map(entries.map((item) => [item.path, item]));
  let parentPath = entry.parentPath;
  while (parentPath) {
    if (!expandedSet.has(parentPath)) return false;
    parentPath = byPath.get(parentPath)?.parentPath;
  }
  return true;
}

function isHiddenAssetTechnicalField(key) {
  const normalized = String(key || "")
    .replace(/[_-]/g, "")
    .toLowerCase();
  return (
    normalized === "type" ||
    normalized === "objectid" ||
    normalized.startsWith("raw")
  );
}

function buildAssetPropertyRows({
  name,
  title,
  value,
  path,
  type = "",
  depth = 0,
}) {
  if (isAssetExpandableContainer(value)) {
    return buildNestedAssetPropertyRows({
      value,
      path,
      name,
      title,
      depth: depth + 1,
    });
  }
  const row = {
    key: path,
    title,
    name,
    type,
    value,
    path,
    depth,
  };
  return [row];
}

function buildNestedAssetPropertyRows({ value, path, name, title, depth }) {
  if (depth > 8 || value === undefined || value === null) return [];
  if (Array.isArray(value)) {
    return value.flatMap((item, index) =>
      buildAssetPropertyRows({
        name: `${name}[${index}]`,
        title: `${title} ${index + 1}`,
        value: item,
        path: `${path}[${index}]`,
        depth,
      }),
    );
  }
  if (typeof value !== "object" || "hasItems" in value) return [];

  const nested =
    value.data && typeof value.data === "object" ? value.data : value;
  return Object.entries(nested)
    .filter(([key]) => !isHiddenAssetTechnicalField(key))
    .flatMap(([key, item]) =>
      buildAssetPropertyRows({
        name: `${name}.${key}`,
        title: labelizeAssetKey(key),
        value: item,
        path: `${path}.${key}`,
        depth,
      }),
    );
}

function isAssetExpandableContainer(value) {
  if (Array.isArray(value)) return value.length > 0;
  return Boolean(value && typeof value === "object" && !("hasItems" in value));
}

function labelizeAssetKey(key) {
  const labels = {
    ipAddress: "IP-адрес",
    fqdn: "Полное имя узла",
    hostname: "Имя узла",
    hostType: "Тип узла",
    macAddress: "MAC-адрес",
    osName: "Название ОС",
    osVersion: "Версия ОС",
    isVirtual: "Виртуальное устройство",
    displayName: "Название",
    objectId: "Идентификатор",
    type: "Тип",
  };
  return (
    labels[key] || String(key || "").replace(/([a-zа-яё])([A-ZА-ЯЁ])/g, "$1 $2")
  );
}

function formatAssetCell(value) {
  if (value === undefined || value === null || value === "") return "—";
  if (typeof value === "boolean") return value ? "Да" : "Нет";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(formatAssetCell).join(", ");
  if (typeof value === "object") {
    if ("hasItems" in value) return value.hasItems ? "Есть" : "Нет";
    return firstFilled(
      value.displayName,
      value.name,
      value.title,
      value.value,
      "—",
    );
  }
  return String(value);
}

function normalizeSearchText(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/ё/g, "е")
    .trim();
}

function clampNumber(value, fallback, min, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(parsed)));
}

function optionalPositiveInteger(value, label) {
  const text = String(value ?? "").trim();
  if (!text) return null;
  const parsed = Number(text);
  if (!Number.isFinite(parsed) || parsed < 1) {
    throw new Error(`${label} должен быть целым числом больше нуля.`);
  }
  return Math.floor(parsed);
}

function passportJobStatusLabel(status) {
  return (
    {
      queued: "в очереди",
      running: "выполняется",
      cancelling: "останавливается",
      cancelled: "остановлена",
      completed: "завершена",
      completed_with_errors: "завершена с ошибками",
      failed: "ошибка",
      interrupted: "прервана перезапуском",
    }[status] ||
    status ||
    "неизвестно"
  );
}

function assetCardJobStatusLabel(status) {
  return (
    {
      queued: "в очереди",
      running: "выполняется",
      cancelling: "останавливается",
      cancelled: "остановлена",
      completed: "завершена",
      failed: "ошибка",
      interrupted: "прервана перезапуском",
    }[status] ||
    status ||
    "неизвестно"
  );
}

function assetCardJobStageLabel(stage) {
  return (
    {
      queued: "ожидание",
      starting: "подготовка",
      collecting: "сбор данных",
      timeline: "timeline token",
      root: "корневой объект",
      tree_and_vulnerabilities: "дерево и уязвимости",
      tree_ready: "дерево собрано, загружаются уязвимости",
      vulnerabilities_ready: "уязвимости собраны, загружается дерево",
      assembling: "сборка результата",
      saving: "сохранение",
      cancelling: "остановка",
      cancelled: "остановлено",
      completed: "готово",
      failed: "ошибка",
      interrupted: "прервано",
    }[stage] ||
    stage ||
    "неизвестно"
  );
}

const ASSET_DEFAULT_FILTERS = { q: "", severity: "" };
const ASSET_DEFAULT_SORT = { key: "severity", direction: "asc" };
const ASSET_SORT_OPTIONS = [
  ["severity", "Критичности"],
  ["created_at", "Свежести данных"],
  ["ip_address", "IP-адресу"],
  ["fqdn", "FQDN"],
  ["software_name", "Названию ПО"],
  ["software_version", "Версии ПО"],
  ["vulnerability_name", "Названию уязвимости"],
  ["cve", "CVE"],
];

function readPath(source, path) {
  if (!source || typeof source !== "object") return undefined;
  return path.split(".").reduce((value, key) => {
    if (!value || typeof value !== "object") return undefined;
    return value[key];
  }, source);
}

function firstFilled(...values) {
  return values.find(
    (value) => value !== undefined && value !== null && value !== "",
  );
}

function firstText(...values) {
  for (const value of values) {
    const text = textValue(value);
    if (text) return text;
  }
  return "";
}

function textValue(value) {
  if (value === undefined || value === null || value === "") return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean")
    return String(value);
  if (Array.isArray(value))
    return value.map(textValue).filter(Boolean).join("\n");
  if (typeof value === "object") {
    return (
      firstFilled(
        value.displayName,
        value.name,
        value.title,
        value.value,
        value.text,
        value.description,
      ) || ""
    );
  }
  return "";
}

function formatPassportDateTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("ru-RU");
}

function normalizeCveItem(item) {
  if (!item) return null;
  if (typeof item === "string") return { display_name: item, url: null };
  if (typeof item !== "object") return null;
  const displayName = firstFilled(
    item.display_name,
    item.displayName,
    item.name,
    item.id,
    item.value,
  );
  return displayName || item.url
    ? { display_name: displayName, url: item.url || null }
    : null;
}

function mergeCves(...groups) {
  const seen = new Set();
  const result = [];
  for (const group of groups) {
    for (const item of group || []) {
      const normalized = normalizeCveItem(item);
      if (!normalized) continue;
      const key = `${normalized.display_name || ""}|${normalized.url || ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      result.push(normalized);
    }
  }
  return result;
}

function collectCves(raw) {
  const candidates = [
    readPath(raw, "cves"),
    readPath(raw, "CVEs"),
    readPath(raw, "cve"),
    readPath(raw, "cveIds"),
    readPath(raw, "identifiers"),
    readPath(raw, "databaseIdentifiers"),
    readPath(raw, "vulnerability.cves"),
  ];
  const result = [];
  for (const value of candidates) {
    if (Array.isArray(value)) {
      result.push(...value);
    } else if (value) {
      result.push(value);
    }
  }
  return result;
}

function collectLinks(raw, cves) {
  const urls = new Set();
  for (const cve of cves || []) {
    if (cve.url) urls.add(cve.url);
  }
  collectUrls(raw, urls);
  return Array.from(urls);
}

function collectUrls(value, urls, depth = 0) {
  if (depth > 8 || value === undefined || value === null) return;
  if (typeof value === "string") {
    if (/^https?:\/\//i.test(value)) urls.add(value);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item) => collectUrls(item, urls, depth + 1));
    return;
  }
  if (typeof value === "object") {
    Object.values(value).forEach((item) => collectUrls(item, urls, depth + 1));
  }
}

function collectIdentifiers(raw, cves, row) {
  const values = new Set();
  [row?.external_id, row?.internal_id]
    .filter(Boolean)
    .forEach((value) => values.add(String(value)));
  for (const cve of cves || []) {
    if (cve.display_name) values.add(cve.display_name);
  }
  const rawIds = [
    readPath(raw, "id"),
    readPath(raw, "internalId"),
    readPath(raw, "cwe"),
    readPath(raw, "cwes"),
    readPath(raw, "identifiers"),
    readPath(raw, "databaseIdentifiers"),
  ];
  for (const value of rawIds) {
    if (Array.isArray(value)) {
      value
        .map(textValue)
        .filter(Boolean)
        .forEach((item) => values.add(item));
    } else {
      const text = textValue(value);
      if (text) values.add(text);
    }
  }
  return Array.from(values).slice(0, 40);
}

function Severity({ value }) {
  const normalized = (value || "empty").toLowerCase();
  return (
    <span className={`severity severity--${normalized}`}>
      {severityLabel(value)}
    </span>
  );
}

function FreshnessBadge({
  value,
  freshForHours = 24,
  staleAfterHours = 7 * 24,
}) {
  const timestamp = value ? new Date(value).getTime() : Number.NaN;
  const ageHours = Number.isFinite(timestamp)
    ? Math.max(0, (Date.now() - timestamp) / 3600000)
    : null;
  const state =
    ageHours == null
      ? "unknown"
      : ageHours <= freshForHours
        ? "fresh"
        : ageHours <= staleAfterHours
          ? "aging"
          : "stale";
  const label =
    state === "fresh"
      ? "свежие"
      : state === "aging"
        ? "требуют обновления"
        : state === "stale"
          ? "устарели"
          : "время неизвестно";
  return (
    <span
      className={`freshness freshness--${state}`}
      title={value ? formatDateTime(value) : "Время обновления отсутствует"}
    >
      <strong>{label}</strong>
      {value ? <small>{formatDateTime(value)}</small> : null}
    </span>
  );
}

export {
  AssetCard,
  AssetCardsPanel,
  ConnectionPanel,
  ExportPanel,
  TaskBuilderPanel,
  VulnerabilityPassportsPanel,
  PassportCard,
  PassportModal,
  FreshnessBadge,
  buildAssetPropertyRows,
  formatAssetCell,
};
