import { useEffect, useMemo, useState } from "react";
import { api, createIdempotencyKey } from "../../api/client.js";
import { useTaskForm } from "./useTaskForm.js";
import {
  filterOptions,
  optionLabel,
  splitTokens,
} from "../../shared/format.js";
import { Button, Disclosure, Field, Panel, Toggle } from "../../shared/ui.jsx";

const WEEKDAYS = [
  ["monday", "Пн"],
  ["tuesday", "Вт"],
  ["wednesday", "Ср"],
  ["thursday", "Чт"],
  ["friday", "Пт"],
  ["saturday", "Сб"],
  ["sunday", "Вс"],
];

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

export function TaskBuilderPanel({
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
