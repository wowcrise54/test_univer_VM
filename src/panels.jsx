import React, { useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { api } from "./api/client.js";
import { recordFrontendEvent } from "./diagnostics.js";
import { filterOptions, formatCount, optionLabel, splitTokens } from "./shared/format.js";
import { Button, Field, Panel, Toggle } from "./shared/ui.jsx";
import { ProgressiveAssetCard, invalidateAssetCardCache } from "./features/asset-cards/ProgressiveAssetCard.jsx";

const ACTIVE_PASSPORT_JOB_STATUSES = new Set(["queued", "running", "cancelling"]);
const ACTIVE_ASSET_CARD_JOB_STATUSES = new Set(["queued", "running", "cancelling"]);
const ACTIVE_SCAN_POSTPROCESS_STATUSES = new Set(["monitoring", "resolving", "processing", "waiting"]);

function ConnectionPanel({
  connectionDraft: form,
  setConnectionDraft: setForm,
  session,
  setSession,
  lookups,
  setLookups,
  busy,
  runBusy,
  showAlert,
}) {

  const update = (key, value) => setForm((current) => ({ ...current, [key]: value }));

  const connect = () =>
    runBusy("connect", async () => {
      const payload = Object.fromEntries(Object.entries(form).map(([key, value]) => [key, value === "" ? null : value]));
      const result = await api("/api/session/connect", { method: "POST", body: JSON.stringify(payload) });
      setSession(result);
      setForm((current) => ({
        ...current,
        api_url: result.api_url || current.api_url,
        token_url: result.token_url || current.token_url,
        username: result.username ?? current.username,
        verify_tls: result.verify_tls ?? current.verify_tls,
      }));
      showAlert("Подключение к MP VM установлено.", "success");
      void loadLookups();
    });

  const disconnect = () =>
    runBusy("disconnect", async () => {
      const result = await api("/api/session/disconnect", { method: "POST" });
      setSession(result);
      showAlert("Сессия MP VM отключена.", "info");
    });

  const loadLookups = () =>
    runBusy("lookups", async () => {
      const result = await api("/api/mpvm/lookups");
      setLookups(result);
      showAlert("Справочники загружены: credentials, scopes, scanner profiles.", "success");
    });

  return (
    <Panel
      id="connection"
      eyebrow="01"
      title="Подключение к MP VM"
      description="Пароль и Bearer token используются только в памяти процесса приложения. После подключения загрузите справочники для выбора scope, профиля и учётной записи."
      action={<Button variant="secondary" busy={busy.lookups} onClick={loadLookups}>Загрузить справочники</Button>}
    >
      <div className="form-grid form-grid--four">
        <Field label="Корневой URL API">
          <input value={form.api_url} onChange={(event) => update("api_url", event.target.value)} placeholder="https://srv-siem.local" />
        </Field>
        <Field label="Token URL">
          <input value={form.token_url} onChange={(event) => update("token_url", event.target.value)} placeholder="https://srv-siem.local:3334/connect/token" />
        </Field>
        <Field label="Username">
          <input value={form.username} onChange={(event) => update("username", event.target.value)} autoComplete="username" />
        </Field>
        <Field label="Password">
          <input value={form.password} onChange={(event) => update("password", event.target.value)} type="password" autoComplete="current-password" />
        </Field>
        <Field label="Client ID">
          <input value={form.client_id} onChange={(event) => update("client_id", event.target.value)} />
        </Field>
        <Field label="Client Secret">
          <input value={form.client_secret} onChange={(event) => update("client_secret", event.target.value)} type="password" />
        </Field>
        <Field label="Scope" wide>
          <input value={form.scope} onChange={(event) => update("scope", event.target.value)} />
        </Field>
        <Field label="Bearer token" wide>
          <input value={form.access_token} onChange={(event) => update("access_token", event.target.value)} type="password" placeholder="Можно вместо username/password/client_secret" />
        </Field>
        <Toggle label="Проверять TLS-сертификат" checked={form.verify_tls} onChange={(value) => update("verify_tls", value)} />
      </div>
      <div className="action-row">
        <Button busy={busy.connect} onClick={connect}>Подключиться</Button>
        <Button variant="ghost" busy={busy.disconnect} onClick={disconnect}>Отключиться</Button>
        <div className="inline-metric">
          <span>{lookups.credentials.length}</span> credentials · <span>{lookups.scopes.length}</span> scopes · <span>{lookups.scanner_profiles.length}</span> profiles
        </div>
        <div className={session.connected ? "mini-state mini-state--ok" : "mini-state"}>{session.connected ? session.api_url : "Ожидает подключения"}</div>
      </div>
    </Panel>
  );
}

function ProfileSelect({ value, onChange, profiles, emptyLabel, searchLabel = "Поиск профиля по имени или ID" }) {
  const [query, setQuery] = useState("");
  const normalizedQuery = query.trim().toLocaleLowerCase("ru-RU");
  const filteredProfiles = useMemo(() => filterOptions(profiles, normalizedQuery), [normalizedQuery, profiles]);
  const selectedProfile = useMemo(
    () => profiles.find((item) => String(item.id || "") === String(value || "")),
    [profiles, value],
  );
  const visibleProfiles = useMemo(() => {
    if (!selectedProfile || filteredProfiles.some((item) => item.id === selectedProfile.id)) return filteredProfiles;
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
          <option value={item.id || ""} key={item.id || item.name}>{optionLabel(item)}</option>
        ))}
        {normalizedQuery && !filteredProfiles.length ? <option disabled>Профили не найдены</option> : null}
      </select>
      {normalizedQuery ? <small>Найдено: {filteredProfiles.length}</small> : null}
    </div>
  );
}

function TaskBuilderPanel({ defaults, lookups, selectedTask, selectedTaskId, setSelectedTaskId, refreshTasks, busy, runBusy, showAlert }) {
  const emptyForm = useMemo(
    () => ({
      name: "",
      description: "Windows audit vulnerability collection",
      scope_id: "",
      profile_id: "",
      credential_id: "",
      host_discovery_profile_id: "",
      include_targets: "",
      exclude_targets: "",
      agent_ids: "",
      host_discovery_enabled: false,
      is_fqdn_priority: true,
      time_zone: defaults?.utc_offset || "+05:00",
      precheck_enabled: false,
      precheck_profile_id: "",
      precheck_timeout_minutes: "10",
      precheck_max_runtime_minutes: "5",
      precheck_poll_seconds: "10",
      task_timeout_minutes: "120",
      task_poll_seconds: "15",
      require_clean_jobs: false,
    }),
    [defaults?.utc_offset],
  );
  const [form, setForm] = useState(emptyForm);

  useEffect(() => {
    setForm((value) => ({ ...value, time_zone: value.time_zone || defaults?.utc_offset || "+05:00" }));
  }, [defaults?.utc_offset]);

  useEffect(() => {
    if (!selectedTask) return;
    const payload = selectedTask.payload || {};
    setForm((current) => ({
      name: payload.name || selectedTask.name || "",
      description: payload.description || "",
      scope_id: payload.scope || "",
      profile_id: payload.profile || "",
      credential_id: selectedTask.credential_id || "",
      host_discovery_profile_id: payload.hostDiscovery?.profile || "",
      include_targets: (payload.include?.targets || []).join("\n"),
      exclude_targets: (payload.exclude?.targets || []).join("\n"),
      agent_ids: (payload.agents?.agentIds || []).join("\n"),
      host_discovery_enabled: Boolean(payload.hostDiscovery?.enabled),
      is_fqdn_priority: payload.isFqdnPriority !== false,
      time_zone: payload.triggerParameters?.timeZone || defaults?.utc_offset || "+05:00",
      precheck_enabled: current.precheck_enabled,
      precheck_profile_id: current.precheck_profile_id,
      precheck_timeout_minutes: current.precheck_timeout_minutes,
      precheck_max_runtime_minutes: current.precheck_max_runtime_minutes,
      precheck_poll_seconds: current.precheck_poll_seconds,
      task_timeout_minutes: current.task_timeout_minutes,
      task_poll_seconds: current.task_poll_seconds,
      require_clean_jobs: current.require_clean_jobs,
    }));
  }, [selectedTask, defaults?.utc_offset]);

  const update = (key, value) => setForm((current) => ({ ...current, [key]: value }));
  const payload = () => ({
    name: form.name.trim(),
    description: form.description.trim(),
    scope_id: form.scope_id,
    profile_id: form.profile_id,
    credential_id: form.credential_id || null,
    host_discovery_profile_id: form.host_discovery_profile_id || null,
    include_targets: splitTokens(form.include_targets),
    exclude_targets: splitTokens(form.exclude_targets),
    agent_ids: splitTokens(form.agent_ids),
    host_discovery_enabled: form.host_discovery_enabled,
    is_fqdn_priority: form.is_fqdn_priority,
    time_zone: form.time_zone || "+05:00",
  });
  const startPayload = () => ({
    precheck_enabled: form.precheck_enabled,
    precheck_profile_id: form.precheck_profile_id || null,
    precheck_timeout_minutes: Number(form.precheck_timeout_minutes || 10),
    precheck_max_runtime_minutes: Number(form.precheck_max_runtime_minutes || 0),
    precheck_poll_seconds: Number(form.precheck_poll_seconds || 10),
    wait_for_finish: false,
    task_timeout_minutes: Number(form.task_timeout_minutes || 120),
    task_poll_seconds: Number(form.task_poll_seconds || 15),
    require_clean_jobs: form.require_clean_jobs,
  });

  const createTask = () =>
    runBusy("createTask", async () => {
      const result = await api("/api/scanner-tasks", { method: "POST", body: JSON.stringify(payload()) });
      setSelectedTaskId(result.mp_task_id);
      showAlert(`Задача создана: ${result.mp_task_id}`, "success");
      await refreshTasks();
    });

  const updateTask = () =>
    runBusy("updateTask", async () => {
      if (!selectedTaskId) throw new Error("Сначала выберите задачу.");
      await api(`/api/scanner-tasks/${encodeURIComponent(selectedTaskId)}`, { method: "PUT", body: JSON.stringify(payload()) });
      showAlert(`Задача изменена: ${selectedTaskId}`, "success");
      await refreshTasks();
    });

  const actionTask = (action, key, successText, body = null) =>
    runBusy(key, async () => {
      if (!selectedTaskId) throw new Error("Сначала выберите задачу.");
      const options = body ? { method: "POST", body: JSON.stringify(body) } : { method: "POST" };
      const result = await api(`/api/scanner-tasks/${encodeURIComponent(selectedTaskId)}/${action}`, options);
      showAlert(successText(result), "success");
      await refreshTasks();
    });

  return (
    <Panel
      id="task-builder"
      title="Конструктор задачи сканирования"
      description="Создание и повторное изменение задач через REST API. Учётные записи выбираются из справочника credentials."
    >
      <div className="form-grid form-grid--two">
        <Field label="Название задачи">
          <input value={form.name} onChange={(event) => update("name", event.target.value)} placeholder="Windows audit 10.104.103.0/24" />
        </Field>
        <Field label="Time zone">
          <input value={form.time_zone} onChange={(event) => update("time_zone", event.target.value)} />
        </Field>
        <Field label="Описание" wide>
          <input value={form.description} onChange={(event) => update("description", event.target.value)} />
        </Field>
        <Field label="Инфраструктура / scope">
          <select value={form.scope_id} onChange={(event) => update("scope_id", event.target.value)}>
            <option value="">Выберите scope</option>
            {lookups.scopes.map((item) => <option value={item.id || ""} key={item.id || item.name}>{optionLabel(item)}</option>)}
          </select>
        </Field>
        <Field label="Профиль сканирования">
          <ProfileSelect
            value={form.profile_id}
            onChange={(value) => update("profile_id", value)}
            profiles={lookups.scanner_profiles}
            emptyLabel="Выберите профиль"
          />
        </Field>
        <Field label="Учётная запись Windows">
          <select value={form.credential_id} onChange={(event) => update("credential_id", event.target.value)}>
            <option value="">Без credential override</option>
            {lookups.credentials.map((item) => <option value={item.id || ""} key={item.id || item.name}>{optionLabel(item)}</option>)}
          </select>
        </Field>
        <Field label="HostDiscovery profile">
          <ProfileSelect
            value={form.host_discovery_profile_id}
            onChange={(value) => update("host_discovery_profile_id", value)}
            profiles={lookups.scanner_profiles}
            emptyLabel="Без HostDiscovery profile"
            searchLabel="Поиск HostDiscovery-профиля"
          />
        </Field>
        <Field label="Коллекторы / agents" wide>
          <textarea rows={3} value={form.agent_ids} onChange={(event) => update("agent_ids", event.target.value)} placeholder="UUID коллекторов через запятую или с новой строки" />
        </Field>
        <Field label="Include targets">
          <textarea rows={4} value={form.include_targets} onChange={(event) => update("include_targets", event.target.value)} placeholder="10.104.103.0/24" />
        </Field>
        <Field label="Exclude targets">
          <textarea rows={4} value={form.exclude_targets} onChange={(event) => update("exclude_targets", event.target.value)} placeholder="Опционально" />
        </Field>
        <Toggle label="Включить hostDiscovery" checked={form.host_discovery_enabled} onChange={(value) => update("host_discovery_enabled", value)} />
        <Toggle label="FQDN priority" checked={form.is_fqdn_priority} onChange={(value) => update("is_fqdn_priority", value)} />
      </div>
      <div className="options-card">
        <div>
          <h3>Precheck и таймер выполнения</h3>
          <p>Precheck запускает connection check, оставляет для основной задачи только успешные targets и затем стартует сканирование.</p>
        </div>
        <div className="form-grid form-grid--two">
          <Toggle label="Выполнить precheck перед запуском" checked={form.precheck_enabled} onChange={(value) => update("precheck_enabled", value)} />
          <div className="mini-state mini-state--ok">Мониторинг, карточки и удаление выполняются в фоне</div>
          <Field label="Precheck profile">
            <ProfileSelect
              value={form.precheck_profile_id}
              onChange={(value) => update("precheck_profile_id", value)}
              profiles={lookups.scanner_profiles}
              emptyLabel="Использовать профиль основной задачи"
              searchLabel="Поиск Precheck-профиля"
            />
          </Field>
          <Field label="Таймаут задачи, минут">
            <input type="number" min="1" value={form.task_timeout_minutes} onChange={(event) => update("task_timeout_minutes", event.target.value)} />
          </Field>
          <Field label="Precheck timeout, минут">
            <input type="number" min="1" value={form.precheck_timeout_minutes} onChange={(event) => update("precheck_timeout_minutes", event.target.value)} />
          </Field>
          <Field label="Остановить precheck через, минут">
            <input type="number" min="0" value={form.precheck_max_runtime_minutes} onChange={(event) => update("precheck_max_runtime_minutes", event.target.value)} />
          </Field>
          <Field label="Poll precheck, секунд">
            <input type="number" min="1" value={form.precheck_poll_seconds} onChange={(event) => update("precheck_poll_seconds", event.target.value)} />
          </Field>
          <Field label="Poll задачи, секунд">
            <input type="number" min="1" value={form.task_poll_seconds} onChange={(event) => update("task_poll_seconds", event.target.value)} />
          </Field>
          <Toggle label="Считать warning/job_errors ошибкой запуска" checked={form.require_clean_jobs} onChange={(value) => update("require_clean_jobs", value)} />
        </div>
      </div>
      <div className="action-row">
        <Button busy={busy.createTask} onClick={createTask}>Создать</Button>
        <Button variant="secondary" busy={busy.updateTask} onClick={updateTask}>Изменить выбранную</Button>
        <Button variant="ghost" busy={busy.validateTask} onClick={() => actionTask("validate", "validateTask", (result) => (result.valid ? "Validation пройдена." : `Validation failed: ${result.error}`))}>Проверить</Button>
        <Button variant="success" busy={busy.startTask} onClick={() => actionTask("start", "startTask", startSuccessText, startPayload())}>Запустить</Button>
        <Button variant="ghost" busy={busy.stopTask} onClick={() => actionTask("stop", "stopTask", () => `Остановка запрошена для ${selectedTaskId}`)}>Остановить</Button>
      </div>
    </Panel>
  );
}

function startSuccessText(result) {
  const precheck = result.precheck?.successful_target_count;
  const precheckText = typeof precheck === "number" ? ` Precheck targets: ${precheck}.` : "";
  if (result.status === "finished") return `Задача завершена успешно.${precheckText}`;
  if (result.status === "timeout_stop_requested") return `Таймер истёк, отправлена остановка задачи.${precheckText}`;
  if (result.status === "precheck_failed") return `Precheck не нашёл успешных targets.`;
  if (result.status === "validation_failed") return `Validation failed: ${result.error || "unknown error"}`;
  if (result.postprocess_run_id) return `Сканирование запущено. Фоновая обработка: ${result.postprocess_run_id}.${precheckText}`;
  return `Старт запрошен для ${result.id}.${precheckText}`;
}

function TaskListPanel({ tasks, lookups, selectedTaskId, setSelectedTaskId, refreshTasks, busy, showAlert }) {
  const [mode, setMode] = useState("delete_v3");
  const [deletingId, setDeletingId] = useState(null);
  const [postprocessDetail, setPostprocessDetail] = useState(null);
  const profilesById = useMemo(() => mapById(lookups.scanner_profiles), [lookups.scanner_profiles]);
  const credentialsById = useMemo(() => mapById(lookups.credentials), [lookups.credentials]);
  const selectedTask = useMemo(
    () => tasks.find((task) => task.mp_task_id === selectedTaskId) || null,
    [selectedTaskId, tasks],
  );
  const loadPostprocessDetail = useCallback(async () => {
    if (!selectedTaskId) return null;
    try {
      const result = await api(`/api/scanner-tasks/${encodeURIComponent(selectedTaskId)}/postprocess-runs/latest`);
      setPostprocessDetail(result);
      return result;
    } catch (error) {
      if (!String(error?.message || error).includes("404")) console.warn(error);
      setPostprocessDetail(null);
      return null;
    }
  }, [selectedTaskId]);
  const visiblePostprocess = postprocessDetail || selectedTask?.postprocess || null;
  const postprocessActive = ACTIVE_SCAN_POSTPROCESS_STATUSES.has(visiblePostprocess?.status);

  useEffect(() => {
    setPostprocessDetail(null);
    if (selectedTaskId && selectedTask?.postprocess) loadPostprocessDetail();
  }, [loadPostprocessDetail, selectedTask?.postprocess, selectedTaskId]);

  useEffect(() => {
    if (!postprocessActive) return undefined;
    const timer = window.setInterval(() => {
      Promise.all([refreshTasks(), loadPostprocessDetail()]).catch((error) => console.warn(error));
    }, 5000);
    return () => window.clearInterval(timer);
  }, [loadPostprocessDetail, postprocessActive, refreshTasks]);

  const deleteTask = async (taskId) => {
    if (!taskId) return;
    if (!window.confirm(`Удалить задачу ${taskId} в MP VM и убрать её из локального списка?`)) return;
    setDeletingId(taskId);
    try {
      await api(`/api/scanner-tasks/${encodeURIComponent(taskId)}/delete`, { method: "POST", body: JSON.stringify({ mode }) });
      if (selectedTaskId === taskId) setSelectedTaskId(null);
      await refreshTasks();
      showAlert(`Задача удалена: ${taskId}`, "success");
    } catch (error) {
      showAlert(error.message || String(error), "error");
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <Panel
      id="tasks"
      eyebrow="02"
      title="Все задачи"
      description="Таблица локально сохранённых задач MP VM. Строка удаляется из списка только после успешного удаления задачи в MP VM."
      action={<TaskToolbar mode={mode} setMode={setMode} refreshTasks={refreshTasks} busy={busy.refreshTasks} />}
      className="task-list-panel"
    >
      <div className="mpvm-table-shell">
        <table className="mpvm-task-table">
          <thead>
            <tr>
              <th>Название</th>
              <th>Цели</th>
              <th>Профиль</th>
              <th>Создана</th>
              <th>Коллектор</th>
              <th>Учётные записи</th>
              <th>Последний запуск</th>
              <th>Следующий запуск</th>
              <th>Статус</th>
              <th>Обработка</th>
              <th>Собираемые данные</th>
            </tr>
          </thead>
          <tbody>
            {tasks.length ? tasks.map((task) => {
              const taskId = task.mp_task_id;
              const isSelected = taskId === selectedTaskId;
              const profile = labelFromMap(profilesById, task.profile_id);
              const credential = labelFromMap(credentialsById, task.credential_id);
              return (
                <tr className={isSelected ? "is-selected" : ""} key={taskId} onClick={() => setSelectedTaskId(taskId)}>
                  <td className="task-name-cell" title={taskId}>
                    <strong>{task.name || taskId}</strong>
                    <span>{taskId}</span>
                  </td>
                  <td>{formatList(task.include_targets)}</td>
                  <td>{profile || task.profile_id || "—"}</td>
                  <td>{formatDateTime(task.created_at)}</td>
                  <td>{formatList(task.agent_ids)}</td>
                  <td>{credential || task.credential_id || "—"}</td>
                  <td>{lastRunText(task)}</td>
                  <td>—</td>
                  <td><TaskStatus status={task.status} /></td>
                  <td><PostprocessSummary run={task.postprocess} /></td>
                  <td>Активы</td>
                </tr>
              );
            }) : (
              <tr><td colSpan={11} className="empty-cell">Локально сохранённых задач пока нет.</td></tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="task-table-footer">
        <span>Выбранная задача: <strong>{selectedTaskId || "нет"}</strong></span>
        <Button variant="danger" busy={Boolean(deletingId && deletingId === selectedTaskId)} disabled={!selectedTaskId} onClick={() => deleteTask(selectedTaskId)}>
          Удалить выбранную
        </Button>
      </div>
      {visiblePostprocess ? <TaskPostprocessPanel run={visiblePostprocess} /> : null}
    </Panel>
  );
}

function PostprocessSummary({ run }) {
  if (!run) return <span className="muted-text">—</span>;
  return (
    <div className="postprocess-summary" title={run.message || run.error || run.stage}>
      <TaskStatus status={run.status} />
      <small>{formatCount(run.completed_count)} / {formatCount(run.asset_count)}</small>
    </div>
  );
}

function TaskPostprocessPanel({ run }) {
  const items = Array.isArray(run.items) ? run.items : [];
  return (
    <section className="task-postprocess" aria-live="polite">
      <div className="task-postprocess__header">
        <div>
          <span className="eyebrow">Фоновая обработка</span>
          <h3>{postprocessStageLabel(run.stage)}</h3>
          <p>{run.message || run.error || `Run ${run.run_id}`}</p>
        </div>
        <div className="task-postprocess__metrics">
          <span>Jobs <strong>{formatCount(run.successful_job_count)} / {formatCount(run.total_job_count)}</strong></span>
          <span>Assets <strong>{formatCount(run.completed_count)} / {formatCount(run.asset_count)}</strong></span>
          <span>Ошибки <strong>{formatCount(run.failed_count)}</strong></span>
        </div>
      </div>
      {items.length ? (
        <div className="mpvm-table-shell">
          <table className="postprocess-item-table">
            <thead><tr><th>Target</th><th>Asset ID</th><th>Scan job</th><th>Карточка</th><th>Удаление MP VM</th><th>Статус / ошибка</th></tr></thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id || item.item_key}>
                  <td>{item.target || "—"}</td>
                  <td className="mono-cell">{item.asset_id || "—"}</td>
                  <td className="mono-cell">{item.mp_job_id || "—"}</td>
                  <td className="mono-cell">{item.build_job_id || postprocessCardLabel(item.status)}</td>
                  <td className="mono-cell">{item.removal_operation_id || postprocessRemovalLabel(item.status)}</td>
                  <td><TaskStatus status={item.status} />{item.error ? <small className="error-text">{item.error}</small> : null}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : <div className="empty-cell">Ожидаем завершения сканирования и появления успешных устройств.</div>}
    </section>
  );
}

function postprocessStageLabel(stage) {
  const labels = {
    waiting_for_run: "Ожидание запуска MP VM",
    scanning: "Сканирование выполняется",
    watching_jobs: "Ожидание успешных scan jobs",
    scan_finished: "Сканирование завершено",
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

function TaskToolbar({ mode, setMode, refreshTasks, busy }) {
  return (
    <div className="task-toolbar">
      <select value={mode} onChange={(event) => setMode(event.target.value)} title="Метод удаления в MP VM">
        <option value="delete_v3">DELETE v3</option>
        <option value="put_v4">PUT v4</option>
      </select>
      <Button variant="icon" onClick={refreshTasks} busy={busy} title="Обновить">↻</Button>
    </div>
  );
}

function TaskStatus({ status }) {
  const normalized = String(status || "").toLowerCase();
  let kind = "neutral";
  let icon = "•";
  if (["started", "precheck_started", "monitoring", "resolving", "processing", "building", "deleting", "queued", "waiting"].some((item) => normalized.includes(item))) {
    kind = "running";
    icon = "◔";
  } else if (normalized.includes("with_errors")) {
    kind = "danger";
    icon = "⚠";
  } else if (["finished", "valid", "created", "updated", "completed", "card_saved"].some((item) => normalized.includes(item))) {
    kind = "success";
    icon = "✓";
  } else if (["failed", "timeout", "stop", "deleted"].some((item) => normalized.includes(item))) {
    kind = "danger";
    icon = "⚠";
  }
  return <span className={`task-status task-status--${kind}`}><span>{icon}</span>{status || "unknown"}</span>;
}

function mapById(items) {
  return new Map((items || []).filter((item) => item.id).map((item) => [item.id, item.name || item.id]));
}

function labelFromMap(map, id) {
  return id ? map.get(id) : "";
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

function lastRunText(task) {
  const status = String(task.status || "");
  if (["created", "updated", "valid"].includes(status)) return "—";
  return formatDateTime(task.updated_at);
}

function ExportPanel({ defaults, busy, runBusy, refreshAssets, showAlert }) {
  const [form, setForm] = useState({
    pdql: "",
    utc_offset: "+05:00",
    group_ids: "",
    asset_ids: "",
    include_nested_groups: true,
    import_results: true,
    delete_assets_after_export: true,
  });
  const [result, setResult] = useState("");

  useEffect(() => {
    if (!defaults) return;
    setForm((value) => ({
      ...value,
      pdql: value.pdql || defaults.software_vuln_pdql || "",
      utc_offset: value.utc_offset || defaults.utc_offset || "+05:00",
    }));
  }, [defaults]);

  const update = (key, value) => setForm((current) => ({ ...current, [key]: value }));
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
      const response = await api("/api/exports/pdql", { method: "POST", body: JSON.stringify(payload) });
      setResult(JSON.stringify(response, null, 2));
      showAlert("PDQL экспорт завершён.", "success");
      await refreshAssets();
    });

  const importSample = () =>
    runBusy("sample", async () => {
      const response = await api("/api/import/sample", { method: "POST" });
      setResult(JSON.stringify(response, null, 2));
      showAlert("Пример CSV импортирован в PostgreSQL.", "success");
      await refreshAssets();
    });

  const importCsvFile = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const body = new FormData();
    body.append("file", file);
    const response = await api("/api/import/csv-file", { method: "POST", body });
    setResult(JSON.stringify(response, null, 2));
    showAlert(`CSV импортирован: ${file.name}`, "success");
    await refreshAssets();
    event.target.value = "";
  };

  return (
    <Panel
      id="export"
      eyebrow="03"
      title="PDQL экспорт и сохранение в PostgreSQL"
      description="Запрос создаёт PDQL token, скачивает CSV, импортирует строки в PostgreSQL и при необходимости удаляет активы из MP VM."
      action={<Button variant="secondary" busy={busy.sample} onClick={importSample}>Импортировать пример CSV</Button>}
    >
      <Field label="PDQL запрос">
        <textarea className="code-input" rows={8} value={form.pdql} onChange={(event) => update("pdql", event.target.value)} />
      </Field>
      <div className="form-grid form-grid--four form-grid--spaced">
        <Field label="UTC offset">
          <input value={form.utc_offset} onChange={(event) => update("utc_offset", event.target.value)} />
        </Field>
        <Field label="Group IDs">
          <input value={form.group_ids} onChange={(event) => update("group_ids", event.target.value)} placeholder="uuid, uuid" />
        </Field>
        <Field label="Asset IDs">
          <input value={form.asset_ids} onChange={(event) => update("asset_ids", event.target.value)} placeholder="uuid, uuid" />
        </Field>
        <Toggle label="Include nested groups" checked={form.include_nested_groups} onChange={(value) => update("include_nested_groups", value)} />
        <Toggle label="Сохранить в БД" checked={form.import_results} onChange={(value) => update("import_results", value)} />
        <Toggle label="Удалить активы в MP VM после импорта" checked={form.delete_assets_after_export} onChange={(value) => update("delete_assets_after_export", value)} />
      </div>
      <div className="action-row">
        <Button busy={busy.export} onClick={runExport}>Выполнить экспорт</Button>
        <label className="upload-button">
          Импорт CSV файла
          <input type="file" accept=".csv,text/csv" onChange={importCsvFile} />
        </label>
      </div>
      {result ? <pre className="result-box">{result}</pre> : null}
    </Panel>
  );
}

function AssetCardsPanel({ defaults, busy, runBusy, showAlert }) {
  const [form, setForm] = useState({
    pdql: "",
    utc_offset: "+05:00",
    group_ids: "",
    asset_ids: "",
    asset_limit: "1001",
    batch_size: "5000",
    include_nested_groups: true,
    selected_asset_id: "",
    timeline_timestamp: "",
    limit_per_collection: "5000",
    max_items_per_collection: "5000",
    max_depth: "8",
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

  const refreshLocalCards = useCallback(async () => {
    const params = new URLSearchParams({ limit: String(clampNumber(form.asset_limit, 1000, 1, 50000)) });
    if (cardSearch.trim()) params.set("q", cardSearch.trim());
    const result = await api(`/api/asset-cards/local?${params.toString()}`);
    setCards(result.rows || []);
    return result;
  }, [cardSearch, form.asset_limit]);

  useEffect(() => {
    if (!defaults) return;
    setForm((value) => ({
      ...value,
      pdql: value.pdql || defaults.asset_card_pdql || "",
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
    api("/api/asset-cards/build-jobs/active")
      .then((result) => {
        if (alive && result.job) setAssetCardJob(result.job);
      })
      .catch((error) => {
        if (alive) showAlert(error.message || String(error), "error");
      });
    return () => {
      alive = false;
    };
  }, [showAlert]);

  useEffect(() => {
    if (!assetCardJob?.job_id || !ACTIVE_ASSET_CARD_JOB_STATUSES.has(assetCardJob.status)) return undefined;
    let alive = true;
    let timerId;
    const poll = async () => {
      try {
        const nextJob = await api(`/api/asset-cards/build-jobs/${encodeURIComponent(assetCardJob.job_id)}`);
        if (!alive) return;
        setAssetCardJob(nextJob);
        if (ACTIVE_ASSET_CARD_JOB_STATUSES.has(nextJob.status)) {
          timerId = window.setTimeout(poll, 1000);
          return;
        }
        if (nextJob.status === "completed") {
          invalidateAssetCardCache(nextJob.asset_id);
          await refreshLocalCards();
          if (!alive) return;
          const card = { asset_id: nextJob.asset_id, display_name: nextJob.asset_id, _progressive: true };
          setSelectedCard(card);
          setAssetWindowOpen(true);
          showAlert(`Карточка актива ${card.display_name || card.asset_id} собрана.`, "success");
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
  }, [assetCardJob?.job_id, assetCardJob?.status, refreshLocalCards, showAlert]);

  const update = (key, value) => setForm((current) => ({ ...current, [key]: value }));
  const filteredCandidates = useMemo(
    () => filterAssetCandidates(candidates, candidateSearch),
    [candidates, candidateSearch],
  );

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
      showAlert(`Получено активов: ${formatCount(records.length)}.`, records.length ? "success" : "info");
    });

  const buildCard = () =>
    runBusy("assetCardBuild", async () => {
      const assetId = form.selected_asset_id.trim();
      if (!assetId) throw new Error("Введите asset_id или выберите актив из списка.");
      const payload = {
        asset_id: assetId,
        timeline_timestamp: form.timeline_timestamp ? Number(form.timeline_timestamp) : null,
        limit_per_collection: clampNumber(form.limit_per_collection, 5000, 1, 5000),
        max_items_per_collection: clampNumber(form.max_items_per_collection, 5000, 1, 50000),
        max_depth: clampNumber(form.max_depth, 8, 0, 8),
      };
      if (form.save_to_db) {
        const result = await api("/api/asset-cards/build-jobs", {
          method: "POST",
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
        setCards((items) => [nextCard, ...items.filter((item) => item.asset_id !== nextCard.asset_id)]);
      }
      const stats = assetCardStats(nextCard);
      showAlert(
        `Карточка собрана: ${formatCount(stats.table_rows)} строк data, ${formatCount(stats.collections)} коллекций.`,
        "success",
      );
    });

  const loadLocalCards = () =>
    runBusy("assetCardsLocal", async () => {
      const result = await refreshLocalCards();
      showAlert(`Загружено карточек из БД: ${formatCount(result.rows?.length || 0)} из ${formatCount(result.total)}.`, "success");
    });

  const openLocalCard = (row) => {
    setSelectedCard({ ...row, _progressive: true });
    setAssetWindowOpen(true);
  };

  const updateLocalCard = (row) =>
    runBusy(`assetCardUpdate:${row.asset_id}`, async () => {
      const result = await api("/api/asset-cards/build-jobs", {
        method: "POST",
        body: JSON.stringify({
          asset_id: row.asset_id,
          timeline_timestamp: form.timeline_timestamp ? Number(form.timeline_timestamp) : null,
          limit_per_collection: clampNumber(form.limit_per_collection, 5000, 1, 5000),
          max_items_per_collection: clampNumber(form.max_items_per_collection, 5000, 1, 50000),
          max_depth: clampNumber(form.max_depth, 8, 0, 8),
        }),
      });
      setAssetCardJob(result.job);
      showAlert(`Обновление карточки ${row.display_name || row.asset_id} запущено в фоне.`, "info");
    });

  const cancelAssetCardJob = () => {
    if (!assetCardJob?.job_id) return;
    runBusy("assetCardJobCancel", async () => {
      const result = await api(`/api/asset-cards/build-jobs/${encodeURIComponent(assetCardJob.job_id)}/cancel`, {
        method: "POST",
      });
      setAssetCardJob(result);
      showAlert("Остановка сборки карточки запрошена.", "info");
    });
  };

  const deleteLocalCard = (row) => {
    const label = row.display_name || row.hostname || row.asset_id;
    if (!window.confirm(`Удалить карточку актива «${label}» из локальной БД?`)) return;
    runBusy(`assetCardDelete:${row.asset_id}`, async () => {
      await api(`/api/asset-cards/${encodeURIComponent(row.asset_id)}`, { method: "DELETE" });
      invalidateAssetCardCache(row.asset_id);
      setCards((items) => items.filter((item) => item.asset_id !== row.asset_id));
      if (selectedCard?.asset_id === row.asset_id) {
        setSelectedCard(null);
        setAssetWindowOpen(false);
      }
      showAlert(`Карточка актива ${label} удалена.`, "success");
    });
  };

  const openAssetPassport = (passport) =>
    runBusy("assetCardPassportDetail", async () => {
      const passportSummary = typeof passport === "string" ? { internal_id: passport } : passport || {};
      const passportId = passportSummary.internal_id;
      if (!passportId) throw new Error("Для этой уязвимости ещё не найден локальный паспорт.");
      setSelectedPassport(passportSummary);
      setAssetPassportDetail(null);
      setAssetPassportError("");
      setAssetPassportWindowOpen(true);
      try {
        const result = await api(`/api/vulnerability-passports/${encodeURIComponent(passportId)}`);
        const nextPassport = result.passport || { ...passportSummary, internal_id: passportId, raw_detail: result.raw || null, has_detail: Boolean(result.raw) };
        setSelectedPassport(nextPassport);
        setAssetPassportDetail(result.raw || nextPassport.raw_detail || {});
      } catch (error) {
        setAssetPassportError(error.message || String(error));
        throw error;
      }
    });

  const assetCardJobProgress = Math.max(0, Math.min(100, Number(assetCardJob?.progress_percent) || 0));
  const assetCardJobActive = ACTIVE_ASSET_CARD_JOB_STATUSES.has(assetCardJob?.status);

  return (
    <Panel
      id="asset-cards"
      eyebrow="04"
      title="Карточки активов"
      description="Сборка карточки создаёт timeline token по asset_id, забирает root, metadata, вложенные узлы и коллекции asset tree, затем сохраняет полный снимок в PostgreSQL."
      action={<Button variant="secondary" busy={busy.assetCardsLocal} onClick={loadLocalCards}>Из БД</Button>}
    >
      <Field label="PDQL для получения asset_id">
        <textarea className="code-input" rows={4} value={form.pdql} onChange={(event) => update("pdql", event.target.value)} />
      </Field>
      <div className="form-grid form-grid--four form-grid--spaced">
        <Field label="UTC offset">
          <input value={form.utc_offset} onChange={(event) => update("utc_offset", event.target.value)} />
        </Field>
        <Field label="Group IDs">
          <input value={form.group_ids} onChange={(event) => update("group_ids", event.target.value)} placeholder="uuid, uuid" />
        </Field>
        <Field label="Asset filter IDs">
          <input value={form.asset_ids} onChange={(event) => update("asset_ids", event.target.value)} placeholder="uuid, uuid" />
        </Field>
        <Field label="Сколько загрузить">
          <input value={form.asset_limit} onChange={(event) => update("asset_limit", event.target.value)} type="number" min="1" max="50000" />
        </Field>
        <Field label="Размер пачки">
          <input value={form.batch_size} onChange={(event) => update("batch_size", event.target.value)} type="number" min="1" max="10000" />
        </Field>
        <Toggle label="Include nested groups" checked={form.include_nested_groups} onChange={(value) => update("include_nested_groups", value)} />
      </div>
      <div className="action-row">
        <Button busy={busy.assetCandidateQuery} onClick={queryAssets}>Получить asset_id</Button>
        <div className="inline-metric">Найдено: <span>{formatCount(filteredCandidates.length)}</span></div>
      </div>

      <div className="asset-card-builder">
        <div className="form-grid form-grid--two">
          <Field label="Выбранный asset_id">
            <input value={form.selected_asset_id} onChange={(event) => update("selected_asset_id", event.target.value)} placeholder="1e41d857-9d80-0001-0000-000000000009" />
          </Field>
          <Field label="Timeline datetime, Unix timestamp">
            <input value={form.timeline_timestamp} onChange={(event) => update("timeline_timestamp", event.target.value)} type="number" placeholder="пусто = сейчас" />
          </Field>
          <Field label="Лимит запроса коллекции">
            <input value={form.limit_per_collection} onChange={(event) => update("limit_per_collection", event.target.value)} type="number" min="1" max="5000" />
          </Field>
          <Field label="Максимум элементов коллекции">
            <input value={form.max_items_per_collection} onChange={(event) => update("max_items_per_collection", event.target.value)} type="number" min="1" max="50000" />
          </Field>
          <Field label="Глубина обхода">
            <input value={form.max_depth} onChange={(event) => update("max_depth", event.target.value)} type="number" min="0" max="8" />
          </Field>
          <Toggle label="Сохранить карточку в БД" checked={form.save_to_db} onChange={(value) => update("save_to_db", value)} />
        </div>
        <div className="action-row">
          <Button busy={busy.assetCardBuild} disabled={assetCardJobActive} onClick={buildCard}>Собрать карточку</Button>
        </div>
      </div>

      {assetCardJob ? (
        <section className={`passport-job asset-card-job passport-job--${assetCardJob.status}${assetCardJobActive ? " asset-card-job--active" : ""}`} aria-live="polite">
          <div className="passport-job__header">
            <div>
              <strong>
                Сборка карточки {assetCardJob.asset_id}: {assetCardJobStatusLabel(assetCardJob.status)}
              </strong>
              <span>
                Этап: {assetCardJobStageLabel(assetCardJob.stage)} · {formatCount(assetCardJobProgress)}% · запросов {formatCount(assetCardJob.completed_requests)} / {formatCount(assetCardJob.discovered_requests)} ·
                узлов {formatCount(assetCardJob.node_count)} · коллекций {formatCount(assetCardJob.collection_count)} ·
                уязвимостей {formatCount(assetCardJob.finding_count)} · предупреждений {formatCount(assetCardJob.warning_count)}
              </span>
            </div>
            {assetCardJobActive ? (
              <Button variant="tiny-danger" busy={busy.assetCardJobCancel} onClick={cancelAssetCardJob}>Остановить</Button>
            ) : null}
          </div>
          {assetCardJob.trace_id ? <small>Trace ID: <code>{assetCardJob.trace_id}</code></small> : null}
          <div className="passport-job__track" role="progressbar" aria-label="Прогресс сборки карточки" aria-valuemin="0" aria-valuemax="100" aria-valuenow={assetCardJobProgress} aria-valuetext={`${assetCardJobProgress}% — ${assetCardJobStageLabel(assetCardJob.stage)}`}>
            <span style={{ width: `${assetCardJobProgress}%` }} />
          </div>
          {assetCardJob.message ? <small>{assetCardJob.message}</small> : null}
        </section>
      ) : null}

      {candidates.length ? (
        <>
          <div className="passport-controls">
            <input value={candidateSearch} onChange={(event) => setCandidateSearch(event.target.value)} placeholder="Поиск по asset_id, имени, ОС" />
            <select value={form.selected_asset_id} onChange={(event) => update("selected_asset_id", event.target.value)}>
              <option value="">Выберите актив</option>
              {filteredCandidates.slice(0, 1000).map((row, index) => (
                <option value={row.asset_id || ""} key={row.asset_id || `${row.display_name}-${index}`}>
                  {[row.display_name, row.os_name, row.asset_id].filter(Boolean).join(" · ")}
                </option>
              ))}
            </select>
          </div>
          <div className="table-shell asset-candidates-shell">
            <table className="asset-candidates-table">
              <thead>
                <tr>
                  <th>Актив</th>
                  <th>ОС</th>
                  <th>Создан</th>
                  <th>Обновлён</th>
                  <th>asset_id</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {filteredCandidates.slice(0, 300).map((row, index) => (
                  <tr key={row.asset_id || `${row.display_name}-${index}`}>
                    <td>{row.display_name || "—"}</td>
                    <td>{row.os_name || "—"}</td>
                    <td>{formatDateTime(row.creation_time)}</td>
                    <td>{formatDateTime(row.update_time)}</td>
                    <td><code>{row.asset_id || "n/a"}</code></td>
                    <td><Button variant="tiny" disabled={!row.asset_id} onClick={() => update("selected_asset_id", row.asset_id || "")}>Выбрать</Button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : queryRaw ? (
        <details className="raw-details">
          <summary>Raw-ответ PDQL запроса активов</summary>
          <pre>{JSON.stringify(queryRaw, null, 2)}</pre>
        </details>
      ) : null}

      <div className="asset-local-header">
        <input value={cardSearch} onChange={(event) => setCardSearch(event.target.value)} onKeyDown={(event) => event.key === "Enter" && loadLocalCards()} placeholder="Поиск сохранённых карточек по IP, FQDN, hostname, ОС, asset_id" />
        <Button variant="secondary" busy={busy.assetCardsLocal} onClick={loadLocalCards}>Показать сохранённые</Button>
      </div>
      <div className="table-shell">
        <table className="asset-card-list-table">
          <thead>
            <tr>
              <th>Актив</th>
              <th>IP / FQDN</th>
              <th>ОС</th>
              <th>Type</th>
              <th>Data</th>
              <th>Обновлено</th>
              <th>Действия</th>
            </tr>
          </thead>
          <tbody>
            {cards.length ? cards.map((row) => {
              const stats = assetCardStats(row);
              return (
                <tr key={row.asset_id}>
                  <td className="wide-cell">
                    <strong>{row.display_name || row.hostname || row.asset_id}</strong>
                    <span><code>{row.asset_id}</code></span>
                  </td>
                  <td>{[row.ip_address, row.fqdn].filter(Boolean).join(" / ") || "—"}</td>
                  <td>{[row.os_name, row.os_version].filter(Boolean).join(" ") || "—"}</td>
                  <td>{row.asset_type || "—"}</td>
                  <td>{formatCount(stats.table_rows)} строк · {formatCount(stats.collections)} коллекций</td>
                  <td>{formatDateTime(row.last_seen)}</td>
                  <td>
                    <div className="row-actions">
                      <Button variant="tiny" busy={busy.assetCardOpen && selectedCard?.asset_id === row.asset_id} onClick={() => openLocalCard(row)}>Открыть</Button>
                      <Button variant="tiny" disabled={assetCardJobActive} busy={busy[`assetCardUpdate:${row.asset_id}`]} onClick={() => updateLocalCard(row)}>Обновить</Button>
                      <Button variant="tiny-danger" busy={busy[`assetCardDelete:${row.asset_id}`]} onClick={() => deleteLocalCard(row)}>Удалить</Button>
                    </div>
                  </td>
                </tr>
              );
            }) : (
              <tr><td colSpan={7} className="empty-cell">Соберите карточку или загрузите сохранённые из БД.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {assetWindowOpen ? (
        <PassportModal
          title="Карточка актива"
          className="asset-modal"
          overlayClassName="asset-modal-overlay"
          closeLabel="Назад"
          onClose={() => setAssetWindowOpen(false)}
        >
          {selectedCard?._progressive ? (
            <ProgressiveAssetCard assetId={selectedCard.asset_id} onOpenPassport={openAssetPassport} />
          ) : (
            <AssetCard
              card={selectedCard}
              loading={busy.assetCardBuild || busy.assetCardOpen}
              onOpenPassport={openAssetPassport}
            />
          )}
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
          {assetPassportError ? <div className="passport-load-error" role="alert">Не удалось загрузить паспорт: {assetPassportError}</div> : null}
          <PassportCard
            row={selectedPassport}
            detail={assetPassportDetail}
            loading={busy.assetCardPassportDetail && !assetPassportDetail}
          />
        </PassportModal>
      ) : null}
    </Panel>
  );
}

function VulnerabilityPassportsPanel({ defaults, busy, runBusy, showAlert }) {
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
  const [passportWindowOpen, setPassportWindowOpen] = useState(false);
  const passportPageSize = 50;

  useEffect(() => {
    if (!defaults) return;
    setForm((value) => ({
      ...value,
      pdql: value.pdql || defaults.vulnerability_passport_pdql || "",
      utc_offset: value.utc_offset || defaults.utc_offset || "+05:00",
    }));
  }, [defaults]);

  const update = (key, value) => setForm((current) => ({ ...current, [key]: value }));
  const totalPages = Math.max(1, Math.ceil(passportTotal / passportPageSize));
  const safePage = Math.min(passportPage, totalPages);
  const pageRows = rows;

  const fetchPassportPage = useCallback(async (
    page,
    search = passportSearch,
    pdqlToken = passportSourceToken,
  ) => {
    const safeRequestedPage = Math.max(1, page);
    const params = new URLSearchParams({
      limit: String(passportPageSize),
      offset: String((safeRequestedPage - 1) * passportPageSize),
    });
    if (search.trim()) params.set("q", search.trim());
    if (pdqlToken) params.set("pdql_token", pdqlToken);
    const result = await api(`/api/vulnerability-passports/local?${params.toString()}`);
    setRows(result.rows || []);
    setPassportTotal(result.total || 0);
    setPassportPage(safeRequestedPage);
    return result;
  }, [passportSearch, passportSourceToken]);

  useEffect(() => {
    if (!passportWindowOpen) return;
    const closeOnEscape = (event) => {
      if (event.key === "Escape") setPassportWindowOpen(false);
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [passportWindowOpen]);

  useEffect(() => {
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
  }, [showAlert]);

  useEffect(() => {
    if (!passportJob?.job_id || !ACTIVE_PASSPORT_JOB_STATUSES.has(passportJob.status)) return undefined;
    let alive = true;
    let timerId;
    const poll = async () => {
      try {
        const nextJob = await api(`/api/vulnerability-passports/detail-jobs/${encodeURIComponent(passportJob.job_id)}`);
        if (!alive) return;
        setPassportJob(nextJob);
        if (ACTIVE_PASSPORT_JOB_STATUSES.has(nextJob.status)) {
          timerId = window.setTimeout(poll, 1000);
          return;
        }
        await fetchPassportPage(passportPage, passportSearch);
        const message = nextJob.status === "completed"
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
  }, [fetchPassportPage, passportJob?.job_id, passportJob?.status, passportPage, passportSearch, showAlert]);

  const queryPassports = () =>
    runBusy("passportQuery", async () => {
      const requestedLimit = optionalPositiveInteger(form.passport_limit, "Лимит паспортов");
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
        showAlert(`Получено паспортов: ${formatCount(result.total)}${saved == null ? "" : `, сохранено в БД: ${formatCount(saved)}`}${detailsLine}.`, "success");
      } else {
        showAlert("Паспорта не найдены в ответе /assets_grid/data. Raw-ответ показан под таблицей.", "info");
      }
    });

  const loadLocalPassports = (page = 1, announce = true, pdqlToken = passportSourceToken) =>
    runBusy("passportLocal", async () => {
      const result = await fetchPassportPage(page, passportSearch, pdqlToken);
      setSelected(null);
      setDetail(null);
      setPassportWindowOpen(false);
      setQueryRaw(null);
      if (announce) {
        showAlert(`Загружено из локальной БД: ${formatCount(result.rows?.length || 0)} из ${formatCount(result.total)}.`, "success");
      }
    });

  const loadAllLocalPassports = () => {
    setPassportSourceToken(null);
    loadLocalPassports(1, true, null);
  };

  const cancelPassportJob = () => {
    if (!passportJob?.job_id) return;
    runBusy("passportJobCancel", async () => {
      const result = await api(`/api/vulnerability-passports/detail-jobs/${encodeURIComponent(passportJob.job_id)}/cancel`, {
        method: "POST",
      });
      setPassportJob(result);
      showAlert("Остановка фоновой загрузки запрошена.", "info");
    });
  };

  const openPassport = (row) =>
    runBusy("passportDetail", async () => {
      if (!row.internal_id) throw new Error("У записи нет @VulnerPassport.internalId.");
      setSelected(row);
      setPassportWindowOpen(true);
      if (row.raw_detail) {
        setDetail(row.raw_detail);
        return;
      }
      setDetail(null);
      const result = await api(`/api/vulnerability-passports/${encodeURIComponent(row.internal_id)}`);
      const nextRow = result.passport || { ...row, raw_detail: result.raw || null, has_detail: Boolean(result.raw) };
      setRows((items) => items.map((item) => (item.internal_id === row.internal_id ? nextRow : item)));
      setSelected(nextRow);
      setDetail(result.raw || nextRow.raw_detail || {});
    });

  const updatePassport = (row) =>
    runBusy(`passportUpdate:${row.internal_id}`, async () => {
      if (!row.internal_id) throw new Error("У записи нет @VulnerPassport.internalId.");
      const result = await api(`/api/vulnerability-passports/${encodeURIComponent(row.internal_id)}`, {
        method: "PUT",
      });
      const nextRow = result.passport || { ...row, raw_detail: result.raw || null, has_detail: Boolean(result.raw) };
      setRows((items) => items.map((item) => (item.internal_id === row.internal_id ? nextRow : item)));
      if (selected?.internal_id === row.internal_id) {
        setSelected(nextRow);
        setDetail(result.raw || nextRow.raw_detail || {});
      }
      showAlert(`Паспорт ${row.external_id || row.internal_id} обновлён.`, "success");
    });

  const deletePassport = (row) => {
    const label = row.external_id || row.name || row.internal_id;
    if (!window.confirm(`Удалить паспорт уязвимости «${label}» из локальной БД?`)) return;
    runBusy(`passportDelete:${row.internal_id}`, async () => {
      if (!row.internal_id) throw new Error("У записи нет @VulnerPassport.internalId.");
      await api(`/api/vulnerability-passports/${encodeURIComponent(row.internal_id)}`, { method: "DELETE" });
      setRows((items) => items.filter((item) => item.internal_id !== row.internal_id));
      setPassportTotal((value) => Math.max(0, value - 1));
      if (selected?.internal_id === row.internal_id) {
        setSelected(null);
        setDetail(null);
        setPassportWindowOpen(false);
      }
      showAlert(`Паспорт ${label} удалён.`, "success");
    });
  };

  const passportJobProgress = passportJob?.eligible_count
    ? Math.min(100, Math.round((passportJob.processed_count / passportJob.eligible_count) * 100))
    : 100;

  return (
    <Panel
      id="passports"
      eyebrow="05"
      title="Паспорта уязвимостей"
      description="PDQL получает список паспортов, затем карточка открывается прямым REST API запросом по internalId."
      action={<Button variant="secondary" busy={busy.passportQuery} onClick={queryPassports}>Получить паспорта</Button>}
    >
      <Field label="PDQL запрос">
        <textarea className="code-input" rows={6} value={form.pdql} onChange={(event) => update("pdql", event.target.value)} />
      </Field>
      <div className="form-grid form-grid--four form-grid--spaced">
        <Field label="UTC offset">
          <input value={form.utc_offset} onChange={(event) => update("utc_offset", event.target.value)} />
        </Field>
        <Field label="Group IDs">
          <input value={form.group_ids} onChange={(event) => update("group_ids", event.target.value)} placeholder="uuid, uuid" />
        </Field>
        <Field label="Asset IDs">
          <input value={form.asset_ids} onChange={(event) => update("asset_ids", event.target.value)} placeholder="uuid, uuid" />
        </Field>
        <Field label="Сколько загрузить (пусто = все)">
          <input value={form.passport_limit} onChange={(event) => update("passport_limit", event.target.value)} type="number" min="1" placeholder="Без лимита" />
        </Field>
        <Field label="Размер пачки">
          <input value={form.batch_size} onChange={(event) => update("batch_size", event.target.value)} type="number" min="1" max="10000" />
        </Field>
        <Toggle label="Include nested groups" checked={form.include_nested_groups} onChange={(value) => update("include_nested_groups", value)} />
        <Toggle label="Сразу загрузить детали в БД" checked={form.load_details} onChange={(value) => update("load_details", value)} />
      </div>
      <div className="action-row">
        <Button busy={busy.passportQuery} onClick={queryPassports}>Выполнить PDQL</Button>
        <Button variant="secondary" busy={busy.passportLocal} onClick={loadAllLocalPassports}>Из БД</Button>
        <div className="inline-metric">На странице: <span>{formatCount(rows.length)}</span> · всего: <span>{formatCount(passportTotal)}</span></div>
      </div>
      {passportJob ? (
        <section className={`passport-job passport-job--${passportJob.status}`} aria-live="polite">
          <div className="passport-job__header">
            <div>
              <strong>Фоновая загрузка деталей: {passportJobStatusLabel(passportJob.status)}</strong>
              <span>
                Обработано {formatCount(passportJob.processed_count)} из {formatCount(passportJob.eligible_count)} ·
                загружено {formatCount(passportJob.loaded_count)} · ошибок {formatCount(passportJob.failed_count)} ·
                свежих в кэше {formatCount(passportJob.skipped_fresh_count)}
              </span>
            </div>
            {ACTIVE_PASSPORT_JOB_STATUSES.has(passportJob.status) ? (
              <Button variant="tiny-danger" busy={busy.passportJobCancel} onClick={cancelPassportJob}>Остановить</Button>
            ) : null}
          </div>
          <div className="passport-job__track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow={passportJobProgress}>
            <span style={{ width: `${passportJobProgress}%` }} />
          </div>
          {passportJob.message ? <small>{passportJob.message}</small> : null}
        </section>
      ) : null}
      <div className="passport-controls">
        <input
          value={passportSearch}
          onChange={(event) => setPassportSearch(event.target.value)}
          onKeyDown={(event) => event.key === "Enter" && loadLocalPassports(1, false)}
          placeholder="Поиск по CVE, названию, internalId, package"
        />
        <Button variant="secondary" busy={busy.passportLocal} onClick={() => loadLocalPassports(1, false)}>Найти</Button>
        <select
          value={safePage}
          onChange={(event) => loadLocalPassports(Number(event.target.value), false)}
          disabled={totalPages <= 1}
        >
          {Array.from({ length: totalPages }, (_, index) => (
            <option value={index + 1} key={index + 1}>Страница {index + 1} / {totalPages}</option>
          ))}
        </select>
      </div>
      <div className="table-shell passport-table-shell">
        <table className="passport-table">
          <thead>
            <tr>
              <th>Score</th>
              <th>Название</th>
              <th>CVE</th>
              <th>Severity</th>
              <th>Package</th>
              <th>Детали</th>
              <th>internalId</th>
              <th>Действия</th>
            </tr>
          </thead>
          <tbody>
            {pageRows.length ? pageRows.map((row, rowIndex) => (
              <tr key={row.internal_id || row.external_id || `${row.name}-${rowIndex}`} className={selected?.internal_id === row.internal_id ? "is-selected" : ""}>
                <td><span className="score-badge">{row.score || "n/a"}</span></td>
                <td className="wide-cell">
                  <strong>{row.name || row.external_id || "Без названия"}</strong>
                  <span>{row.external_id}</span>
                </td>
                <td>{(row.cves || []).map((item) => item.display_name).filter(Boolean).join(", ") || "n/a"}</td>
                <td><Severity value={row.severity} /></td>
                <td>{[row.package_id, row.package_version].filter(Boolean).join(" / ") || "n/a"}</td>
                <td>{row.has_detail || row.raw_detail ? "в БД" : "нет"}</td>
                <td><code>{row.internal_id || "n/a"}</code></td>
                <td>
                  <div className="row-actions">
                    <Button variant="tiny" busy={busy.passportDetail && selected?.internal_id === row.internal_id} onClick={() => openPassport(row)}>Открыть</Button>
                    <Button variant="tiny" busy={busy[`passportUpdate:${row.internal_id}`]} onClick={() => updatePassport(row)}>Обновить</Button>
                    <Button variant="tiny-danger" busy={busy[`passportDelete:${row.internal_id}`]} onClick={() => deletePassport(row)}>Удалить</Button>
                  </div>
                </td>
              </tr>
            )) : (
              <tr><td colSpan={8} className="empty-cell">{passportTotal ? "На этой странице нет записей." : "Выполните PDQL или загрузите паспорта из БД."}</td></tr>
            )}
          </tbody>
        </table>
      </div>
      {passportTotal ? (
        <div className="passport-pagination">
          <span>
            Страница {formatCount(safePage)} из {formatCount(totalPages)} · показано {formatCount(pageRows.length)} из {formatCount(passportTotal)}
          </span>
          <div>
            <Button variant="tiny" disabled={safePage <= 1 || busy.passportLocal} onClick={() => loadLocalPassports(safePage - 1, false)}>Назад</Button>
            <Button variant="tiny" disabled={safePage >= totalPages || busy.passportLocal} onClick={() => loadLocalPassports(safePage + 1, false)}>Вперёд</Button>
          </div>
        </div>
      ) : null}
      {queryRaw && !rows.length ? (
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
          closeLabel="Назад"
          onClose={() => setPassportWindowOpen(false)}
        >
          <PassportCard row={selected} detail={detail} loading={busy.passportDetail && !detail} />
        </PassportModal>
      ) : null}
    </Panel>
  );
}

function AssetCard({ card, loading, onOpenPassport }) {
  const raw = assetCardRaw(card);
  const root = card?.root || raw.root || {};
  const data = root.data || {};
  const stats = assetCardStats(card);
  const treeEntries = useMemo(() => buildAssetConfigTree(card), [card]);
  const [activeTab, setActiveTab] = useState("configuration");
  const [expandedPaths, setExpandedPaths] = useState(["asset"]);
  const [selectedPath, setSelectedPath] = useState("asset");
  const expandedSet = useMemo(() => new Set(expandedPaths), [expandedPaths]);
  const visibleTreeEntries = useMemo(
    () => treeEntries.filter((entry) => isAssetTreeEntryVisible(entry, expandedSet, treeEntries)),
    [treeEntries, expandedSet],
  );
  const selectedEntry = useMemo(
    () => treeEntries.find((entry) => entry.path === selectedPath) || treeEntries[0] || null,
    [treeEntries, selectedPath],
  );
  const title = firstFilled(card?.display_name, raw.display_name, root.displayName, data.hostname, card?.asset_id, raw.asset_id);
  const assetId = firstFilled(card?.asset_id, raw.asset_id, root.objectId);
  const assetType = firstFilled(card?.asset_type, raw.asset_type, root.type);
  const ipAddress = firstFilled(card?.ip_address, data.ipAddress);
  const fqdn = firstFilled(card?.fqdn, data.fqdn);
  const osLine = [firstFilled(card?.os_name, data.osName), firstFilled(card?.os_version, data.osVersion)].filter(Boolean).join(" ");

  useEffect(() => {
    if (!card || !treeEntries.length) return;
    setExpandedPaths(defaultAssetTreeExpandedPaths(treeEntries));
    setSelectedPath(treeEntries[0].path);
    setActiveTab("configuration");
  }, [card, treeEntries]);

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
          tree_entry_count: treeEntries.length,
        },
        { section: activeTab },
      );
    });
    return () => window.cancelAnimationFrame(frame);
  }, [activeTab, assetId, card, treeEntries.length]);

  const toggleTreeEntry = useCallback((path) => {
    setExpandedPaths((current) => (
      current.includes(path)
        ? current.filter((item) => item !== path)
        : [...current, path]
    ));
  }, []);

  if (!card) {
    return <div className="passport-placeholder">Соберите карточку или откройте сохранённую запись из БД.</div>;
  }

  return (
    <div className="asset-console">
      <div className="asset-tabs" role="tablist" aria-label="Разделы карточки актива">
        {[
          ["summary", "Сводка"],
          ["vulnerabilities", "Уязвимости"],
          ["configuration", "Конфигурация"],
        ].map(([id, label]) => (
          <button
            type="button"
            className={activeTab === id ? "is-active" : ""}
            onClick={() => setActiveTab(id)}
            key={id}
          >
            {label}
          </button>
        ))}
      </div>
      {activeTab === "summary" ? (
        <AssetSummaryTab
          assetId={assetId}
          assetType={assetType}
          fqdn={fqdn}
          ipAddress={ipAddress}
          osLine={osLine}
          root={root}
          stats={stats}
          loading={loading}
        />
      ) : null}
      {activeTab === "vulnerabilities" ? (
        <AssetVulnerabilitiesTab card={card} onOpenPassport={onOpenPassport} />
      ) : null}
      {activeTab === "configuration" ? (
        <div className="asset-config-layout">
          <AssetTree
            entries={visibleTreeEntries}
            selectedPath={selectedEntry?.path}
            expandedSet={expandedSet}
            onToggle={toggleTreeEntry}
            onSelect={setSelectedPath}
          />
          <AssetConfigTable card={card} entry={selectedEntry} />
        </div>
      ) : null}
    </div>
  );
}

function AssetSummaryTab({ assetId, assetType, fqdn, ipAddress, osLine, root, stats, loading }) {
  const warnings = stats.warnings || [];
  return (
    <div className="asset-summary-grid">
      <div className="asset-summary-main">
        <PassportSection title="Основная информация">
          <KeyValue label="asset_id" value={assetId} />
          <KeyValue label="Type" value={assetType} />
          <KeyValue label="Hostname" value={firstFilled(root?.data?.hostname, root?.displayName)} />
          <KeyValue label="FQDN" value={fqdn} />
          <KeyValue label="IP" value={ipAddress} />
          <KeyValue label="ОС" value={osLine} />
        </PassportSection>
        <PassportSection title="Сборка">
          <KeyValue label="Состояние" value={loading ? "собирается" : "готово"} />
          <KeyValue label="Metadata" value={formatCount(stats.metadata_requests)} />
          <KeyValue label="Node requests" value={formatCount(stats.node_requests)} />
          <KeyValue label="Collection requests" value={formatCount(stats.collection_requests)} />
        </PassportSection>
        <PassportSection title="Предупреждения">
          {warnings.length ? warnings.slice(0, 16).map((warning) => <code key={warning}>{warning}</code>) : <span className="muted-text">Предупреждений нет.</span>}
        </PassportSection>
      </div>
      <div className="asset-summary-side">
        <div className="asset-summary-card">
          <span>Коллекции</span>
          <strong>{formatCount(stats.collections)}</strong>
        </div>
        <div className="asset-summary-card">
          <span>Узлы</span>
          <strong>{formatCount(stats.nodes)}</strong>
        </div>
        <div className="asset-summary-card">
          <span>Строки data</span>
          <strong>{formatCount(stats.table_rows)}</strong>
        </div>
        <div className="asset-summary-card">
          <span>Уровень уязвимости</span>
          <strong>{firstFilled(root?.vulnerabilityLevel, "n/a")}</strong>
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
    if (passportId && !byId.has(passportId)) byId.set(passportId, { internal_id: passportId });
  });
  return Array.from(byId.values());
}

function assetPassportLabel(passport) {
  return firstFilled(passport?.name, passport?.external_id, passport?.internal_id, "Паспорт");
}

function AssetVulnerabilitiesTab({ card, onOpenPassport }) {
  const snapshot = assetCardVulnerabilities(card);
  const sources = Array.isArray(snapshot.sources) ? snapshot.sources : [];
  const header = snapshot.header || {};
  const [collapsedSources, setCollapsedSources] = useState([]);
  const [collapsedGroups, setCollapsedGroups] = useState([]);
  const collapsedSourceSet = useMemo(() => new Set(collapsedSources), [collapsedSources]);
  const collapsedGroupSet = useMemo(() => new Set(collapsedGroups), [collapsedGroups]);
  const sourceKeys = useMemo(
    () => sources.map((source, index) => source.source || source.collection_type || source.title || `source-${index}`),
    [sources],
  );
  const groupKeys = useMemo(
    () => sources.flatMap((source, sourceIndex) => {
      const sourceKey = source.source || source.collection_type || source.title || `source-${sourceIndex}`;
      return (source.groups || []).map((group, groupIndex) => `${sourceKey}:${group.collection_id || groupIndex}`);
    }),
    [sources],
  );
  const findingCount = sources.reduce(
    (total, source) => total + (source.groups || []).reduce((sum, group) => sum + (group.items || []).length, 0),
    0,
  );
  const sourceCount = (source) => (source.groups || []).reduce(
    (total, group) => total + (Number(group.vulnerabilities_count) || (group.items || []).length),
    0,
  );

  useEffect(() => {
    setCollapsedSources([]);
    setCollapsedGroups([]);
  }, [card?.asset_id]);

  const toggleSource = useCallback((key) => {
    setCollapsedSources((current) => (
      current.includes(key) ? current.filter((item) => item !== key) : [...current, key]
    ));
  }, []);

  const toggleGroup = useCallback((key) => {
    setCollapsedGroups((current) => (
      current.includes(key) ? current.filter((item) => item !== key) : [...current, key]
    ));
  }, []);

  const expandAll = () => {
    setCollapsedSources([]);
    setCollapsedGroups([]);
  };

  const collapseAll = () => {
    setCollapsedSources(sourceKeys);
    setCollapsedGroups(groupKeys);
  };

  return (
    <section className="asset-vulnerability-pane" aria-label="Уязвимости актива">
      <div className="asset-vulnerability-toolbar">
        {sources.map((source) => (
          <span key={source.source || source.collection_type}>
            {source.source === "os" ? "Уязвимости ОС" : "Уязвимости ПО"}: <strong>{formatCount(sourceCount(source))}</strong>
          </span>
        ))}
        <span>Сетевые сервисы: <strong>{formatCount(header.network_services_vulnerabilities_count || 0)}</strong></span>
      </div>
      <div className="asset-vulnerability-heading">
        <div>
          <strong>Уязвимости</strong>
          <span>Загружено {formatCount(findingCount)} из {formatCount(header.os_soft_vulnerabilities_count || findingCount)} уязвимостей.</span>
        </div>
        {sourceKeys.length ? (
          <div className="asset-vulnerability-controls">
            <button type="button" onClick={expandAll}>Развернуть все</button>
            <button type="button" onClick={collapseAll}>Свернуть все</button>
          </div>
        ) : null}
      </div>
      <div className="asset-vulnerability-table-shell" tabIndex="0" aria-label="Прокручиваемый список уязвимостей">
        <table className="asset-vulnerability-table">
          <thead>
            <tr>
              <th>Уязвимости</th>
              <th>Интегральная уязвимость</th>
              <th>CVE</th>
            </tr>
          </thead>
          <tbody>
            {sources.flatMap((source, sourceIndex) => {
              const groups = source.groups || [];
              const sourceKey = source.source || source.collection_type || source.title || `source-${sourceIndex}`;
              const sourceCollapsed = collapsedSourceSet.has(sourceKey);
              const sourceRow = (
                <tr className="asset-vulnerability-source" key={`${sourceKey}-source`}>
                  <td colSpan={3}>
                    <button
                      type="button"
                      className="asset-vulnerability-toggle"
                      aria-expanded={!sourceCollapsed}
                      onClick={() => toggleSource(sourceKey)}
                    >
                      <span className="asset-vulnerability-caret" aria-hidden="true">{sourceCollapsed ? "›" : "⌄"}</span>
                      <span>{source.title || (source.source === "os" ? "Уязвимости ОС" : "Уязвимости программного обеспечения")} ({formatCount(sourceCount(source))})</span>
                    </button>
                  </td>
                </tr>
              );
              if (sourceCollapsed) return [sourceRow];
              return [
                sourceRow,
                ...groups.flatMap((group, groupIndex) => {
                  const groupKey = `${sourceKey}:${group.collection_id || groupIndex}`;
                  const groupCollapsed = collapsedGroupSet.has(groupKey);
                  const groupRow = (
                    <tr className="asset-vulnerability-group" key={groupKey}>
                    <td>
                      <button
                        type="button"
                        className="asset-vulnerability-toggle"
                        aria-expanded={!groupCollapsed}
                        onClick={() => toggleGroup(groupKey)}
                      >
                        <span className="asset-vulnerability-caret" aria-hidden="true">{groupCollapsed ? "›" : "⌄"}</span>
                        <span><strong>{group.name || "Без названия"}</strong> ({formatCount(group.vulnerabilities_count || (group.items || []).length)})</span>
                        {group.truncated ? <small>Показана неполная коллекция</small> : null}
                      </button>
                    </td>
                    <td>{formatVulnerabilityScore(group.cvss_score)}</td>
                    <td />
                    </tr>
                  );
                  if (groupCollapsed) return [groupRow];
                  return [groupRow, ...(group.items || []).map((finding, findingIndex) => {
                    const passports = assetFindingPassports(finding);
                    const passport = passports[0];
                    return (
                      <tr className="asset-vulnerability-finding" key={finding.vulnerability_instance_id || `${group.collection_id}-${findingIndex}`}>
                        <td>
                          <span className="asset-vulnerability-leaf">•</span>
                          <span>{finding.name || finding.cve_name || "Уязвимость без названия"}</span>
                        </td>
                        <td>{formatVulnerabilityScore(finding.cvss_score)}</td>
                        <td>
                          {passports.length === 1 ? (
                            <button
                              type="button"
                              className="asset-vulnerability-passport-link"
                              onClick={() => onOpenPassport?.(passport)}
                              title={`Открыть паспорт ${assetPassportLabel(passport)}`}
                            >
                              {finding.cve_name || "Открыть паспорт"}
                            </button>
                          ) : passports.length > 1 ? (
                            <details className="asset-vulnerability-passport-picker">
                              <summary>Паспорта: {formatCount(passports.length)}</summary>
                              <div className="asset-vulnerability-passport-options">
                                {passports.map((item) => (
                                  <button
                                    type="button"
                                    key={item.internal_id}
                                    onClick={() => onOpenPassport?.(item)}
                                  >
                                    <strong>{assetPassportLabel(item)}</strong>
                                    <span>{[item.severity, item.external_id, item.internal_id].filter(Boolean).join(" · ")}</span>
                                  </button>
                                ))}
                              </div>
                            </details>
                          ) : (
                            finding.cve_name || "—"
                          )}
                        </td>
                      </tr>
                    );
                  })];
                }),
              ];
            })}
            {!sources.some((source) => (source.groups || []).length) ? (
              <tr><td colSpan={3} className="empty-cell">Уязвимостей в сохранённом снимке нет.</td></tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function AssetFilteredRows({ title, rows }) {
  const visibleRows = rows.slice(0, 1000);
  return (
    <div className="asset-filtered-pane">
      <div className="asset-detail-heading">
        <div>
          <strong>{title}</strong>
          <span>Показано {formatCount(visibleRows.length)} из {formatCount(rows.length)}</span>
        </div>
      </div>
      <AssetRowsTable rows={visibleRows} />
    </div>
  );
}

function AssetTree({ entries, selectedPath, expandedSet, onToggle, onSelect }) {
  return (
    <aside className="asset-tree-pane">
      <div className="asset-tree">
        {entries.map((entry) => (
          <div
            className={selectedPath === entry.path ? "asset-tree-row is-selected" : "asset-tree-row"}
            style={{ "--depth": entry.depth }}
            key={entry.path}
          >
            <button
              type="button"
              className={entry.hasChildren ? "asset-tree-toggle" : "asset-tree-toggle is-empty"}
              onClick={() => entry.hasChildren && onToggle(entry.path)}
              aria-label={expandedSet.has(entry.path) ? "Свернуть" : "Раскрыть"}
            >
              {entry.hasChildren ? (expandedSet.has(entry.path) ? "▾" : "›") : ""}
            </button>
            <button type="button" className="asset-tree-label" onClick={() => onSelect(entry.path)}>
              <span>{entry.label}</span>
              {entry.subtitle ? <small>{entry.subtitle}</small> : null}
            </button>
            {entry.meta ? <span className="asset-tree-meta">{entry.meta}</span> : <span className="asset-tree-search" aria-hidden="true" />}
          </div>
        ))}
      </div>
    </aside>
  );
}

function AssetConfigTable({ card, entry }) {
  if (!entry) {
    return (
      <section className="asset-detail-pane">
        <div className="empty-cell">Выберите раздел слева.</div>
      </section>
    );
  }

  const table = buildAssetDetailTable(card, entry);
  return (
    <section className={`asset-detail-pane asset-detail-pane--${table.layout || "table"}`} aria-label={entry.label}>
      {table.layout === "properties" ? (
        <AssetPropertyList rows={table.rows} />
      ) : (
        <div className="table-shell asset-detail-table-shell">
          <table className="asset-detail-table">
            <thead>
              <tr>
                {table.columns.map((column) => <th key={column.key}>{column.title}</th>)}
              </tr>
            </thead>
            <tbody>
              {table.rows.length ? table.rows.slice(0, 1000).map((row, rowIndex) => (
                <tr key={row.key || rowIndex}>
                  {table.columns.map((column) => <td key={column.key}>{formatAssetCell(row[column.key])}</td>)}
                </tr>
              )) : (
                <tr><td colSpan={table.columns.length} className="empty-cell">В выбранном разделе нет данных.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
      {table.rows.length > 1000 ? <div className="table-footer">Показано 1000 из {formatCount(table.rows.length)} строк.</div> : null}
    </section>
  );
}

function AssetPropertyList({ rows }) {
  const visibleRows = rows.slice(0, 1000);
  if (!visibleRows.length) {
    return <div className="empty-cell">В выбранном разделе нет данных.</div>;
  }

  return (
    <div className="asset-property-list">
      {visibleRows.map((row, index) => (
        <div className="asset-property-row" style={{ "--depth": row.depth || 0 }} key={row.key || index}>
          <div className="asset-property-name">
            <span>{row.title || row.name}</span>
            {row.name && row.name !== row.title ? <small>{row.name}</small> : null}
          </div>
          <strong>{formatAssetCell(row.value)}</strong>
        </div>
      ))}
    </div>
  );
}

function AssetRowsTable({ rows }) {
  return (
    <div className="table-shell asset-detail-table-shell">
      <table className="asset-detail-table">
        <thead>
          <tr>
            <th>Path</th>
            <th>Название</th>
            <th>Значение</th>
          </tr>
        </thead>
        <tbody>
          {rows.length ? rows.map((row, index) => (
            <tr key={`${row.path}-${index}`}>
              <td><code>{row.path}</code></td>
              <td>{row.title || row.name}</td>
              <td>{row.value || "—"}</td>
            </tr>
          )) : (
            <tr><td colSpan={3} className="empty-cell">Данных для этого раздела нет.</td></tr>
          )}
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
  const modal = (
    <div className={`passport-modal ${overlayClassName}`} role="dialog" aria-modal="true">
      <div className="passport-modal__backdrop" onClick={onClose} />
      <div className={`passport-modal__window ${className}`}>
        <div className="passport-modal__bar">
          <strong>{title}</strong>
          <Button variant="ghost" onClick={onClose}>{closeLabel}</Button>
        </div>
        {children}
      </div>
    </div>
  );
  return typeof document === "undefined" ? modal : createPortal(modal, document.body);
}

function PassportCard({ row, detail, loading }) {
  const raw = detail || row?.raw_detail || row?.raw_record || {};
  const model = useMemo(() => buildPassportModel(row, raw), [row, raw]);

  if (!row && !detail) {
    return <div className="passport-placeholder">Выберите строку в таблице, чтобы открыть карточку паспорта уязвимости.</div>;
  }

  return (
    <div className="asset-console">
      <div className="asset-tabs" role="tablist" aria-label="Разделы карточки паспорта">
        <button type="button" className="is-active" aria-selected="true">Сводка</button>
      </div>
      <div className="passport-summary-scroll">
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
          <KeyValue label="internalId" value={row?.internal_id} />
          <KeyValue label="Внешний ID" value={row?.external_id} />
          <KeyValue label="Опасность" value={model.severity} />
          <KeyValue label="Score" value={model.score} />
          <KeyValue label="Пакет" value={model.packageLine} />
          <KeyValue label="Дата публикации" value={formatPassportDateTime(model.issueTime)} />
        </PassportSection>
        <PassportSection title="Описание">
          <p>{model.description || "В сохранённой детали паспорта нет отдельного поля описания."}</p>
        </PassportSection>
        <PassportSection title="Как исправить">
          <p>{model.remediation || "Рекомендация не найдена в нормализованных полях паспорта."}</p>
        </PassportSection>
      </div>
      <div className="asset-summary-side">
        <div className="asset-summary-card">
          <span>Score</span>
          <strong>{model.score || "n/a"}</strong>
        </div>
        <div className="asset-summary-card">
          <span>Severity</span>
          <strong>{model.severity || "n/a"}</strong>
        </div>
        <div className="asset-summary-card">
          <span>CVE</span>
          <strong>{formatCount(model.cves.length)}</strong>
        </div>
        <div className="asset-summary-card">
          <span>Деталь</span>
          <strong>{loading ? "загрузка" : row?.has_detail || row?.raw_detail ? "в БД" : "нет"}</strong>
        </div>
        <PassportSection title="CVE">
          {model.cves.length ? model.cves.slice(0, 16).map((item) => (
            item.url
              ? <a href={item.url} target="_blank" rel="noreferrer" key={item.display_name || item.url}>{item.display_name || item.url}</a>
              : <code key={item.display_name}>{item.display_name}</code>
          )) : <span className="muted-text">CVE не найдены.</span>}
        </PassportSection>
        <PassportSection title="Ссылки">
          {model.links.length ? model.links.slice(0, 12).map((link) => (
            <a href={link} target="_blank" rel="noreferrer" key={link}>{link}</a>
          )) : <span className="muted-text">Ссылки не найдены.</span>}
        </PassportSection>
        <PassportSection title="Идентификаторы">
          {model.identifiers.length ? model.identifiers.map((id) => <code key={id}>{id}</code>) : <span className="muted-text">Идентификаторы не найдены.</span>}
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
  const score = firstFilled(readPath(raw, "score"), readPath(raw, "cvss3Score"), readPath(raw, "cvss.score"), row?.score);
  const severity = firstFilled(readPath(raw, "severityRating"), readPath(raw, "severity"), row?.severity);
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
  const issueTime = firstFilled(readPath(raw, "issueTime"), readPath(raw, "publishedAt"), row?.issue_time);
  const packageLine = [firstFilled(readPath(raw, "packageId"), row?.package_id), firstFilled(readPath(raw, "packageVersion"), row?.package_version)]
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

function filterPassportRows(rows, query) {
  const normalizedQuery = normalizeSearchText(query);
  if (!normalizedQuery) return rows;
  return rows.filter((row) => buildPassportSearchText(row).includes(normalizedQuery));
}

function filterAssetCandidates(rows, query) {
  const normalizedQuery = normalizeSearchText(query);
  if (!normalizedQuery) return rows;
  return rows.filter((row) => buildAssetCandidateSearchText(row).includes(normalizedQuery));
}

function buildAssetCandidateSearchText(row) {
  return normalizeSearchText([
    row.asset_id,
    row.display_name,
    row.os_name,
    row.creation_time,
    row.update_time,
    JSON.stringify(row.raw_record || {}),
  ].filter(Boolean).join(" "));
}

function assetCardRaw(card) {
  return card || {};
}

function assetCardStats(card) {
  const raw = assetCardRaw(card);
  return card?.stats || raw.stats || {};
}

function assetCardRows(card) {
  const raw = assetCardRaw(card);
  return card?.table_rows || raw.table_rows || [];
}

function assetCardCollections(card) {
  const raw = assetCardRaw(card);
  return card?.collections || raw.collections || [];
}

function assetCardVulnerabilities(card) {
  const raw = assetCardRaw(card);
  return card?.vulnerabilities || raw.vulnerabilities || {};
}

function formatVulnerabilityScore(value) {
  if (value === null || value === undefined || value === "") return "—";
  const number = Number(value);
  return Number.isFinite(number) ? number.toLocaleString("ru-RU", { maximumFractionDigits: 1 }) : String(value);
}

function assetCardNodes(card) {
  const raw = assetCardRaw(card);
  return card?.nodes || raw.nodes || [];
}

function buildAssetConfigTree(card) {
  if (!card) return [];
  const raw = assetCardRaw(card);
  const root = card?.root || raw.root || {};
  const collections = assetCardCollections(card);
  const nodes = assetCardNodes(card);
  const entries = [];
  const byPath = new Map();

  const addEntry = (entry) => {
    const existing = byPath.get(entry.path);
    if (existing) {
      Object.assign(existing, entry, { source: entry.source || existing.source });
      return existing;
    }
    byPath.set(entry.path, entry);
    entries.push(entry);
    return entry;
  };

  const ensureAncestors = (path) => {
    const parentPath = assetTreeParentPath(path);
    if (!parentPath || byPath.has(parentPath)) return;
    ensureAncestors(parentPath);
    addEntry({
      path: parentPath,
      parentPath: assetTreeParentPath(parentPath),
      label: assetPathLabel(parentPath),
      subtitle: assetPathKey(parentPath),
      kind: "group",
      source: null,
    });
  };

  addEntry({
    path: "asset",
    parentPath: null,
    label: firstFilled(root.displayName, card.display_name, raw.display_name, card.asset_id, raw.asset_id, "Актив"),
    subtitle: firstFilled(root.type, card.asset_type, raw.asset_type, "asset"),
    kind: "root",
    source: root,
  });

  [...nodes]
    .sort((left, right) => String(left.path || "").localeCompare(String(right.path || "")))
    .forEach((node) => {
      if (!node.path) return;
      ensureAncestors(node.path);
      addEntry({
        path: node.path,
        parentPath: assetTreeParentPath(node.path) || "asset",
        label: firstFilled(node.title, node.display_name, assetPathLabel(node.path)),
        subtitle: assetPathKey(node.path) || node.type || "",
        kind: "node",
        source: node,
      });
    });

  [...collections]
    .sort((left, right) => String(left.path || "").localeCompare(String(right.path || "")))
    .forEach((collection) => {
      if (!collection.path) return;
      ensureAncestors(collection.path);
      addEntry({
        path: collection.path,
        parentPath: assetTreeParentPath(collection.path) || "asset",
        label: firstFilled(collection.title, collection.name, assetPathLabel(collection.path)),
        subtitle: firstFilled(collection.name, assetPathKey(collection.path), collection.type),
        meta: formatAssetCollectionMeta(collection),
        kind: "collection",
        source: collection,
      });
      (collection.items || []).slice(0, 250).forEach((item, index) => {
        const itemPath = item.path || `${collection.path}[${index}]`;
        addEntry({
          path: itemPath,
          parentPath: collection.path,
          label: firstFilled(item.display_name, item.value, item.object_id, `Элемент ${index + 1}`),
          subtitle: firstFilled(item.type, item.object_id, assetPathKey(itemPath)),
          kind: "item",
          source: item,
        });
      });
    });

  const hasChildren = new Set(entries.map((entry) => entry.parentPath).filter(Boolean));
  entries.forEach((entry) => {
    entry.depth = assetTreeDepth(entry, byPath);
    entry.hasChildren = hasChildren.has(entry.path);
  });
  return entries;
}

function defaultAssetTreeExpandedPaths(entries) {
  return entries.some((entry) => entry.path === "asset") ? ["asset"] : [];
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

function buildAssetDetailTable(card, entry) {
  if (!entry) return { columns: [{ key: "value", title: "Значение" }], rows: [] };
  if (entry.kind === "collection") return buildAssetCollectionTable(card, entry.source);
  if (entry.kind === "root") return buildAssetObjectPropertyTable(card, entry.source, "asset");
  if (entry.kind === "node") return buildAssetObjectPropertyTable(card, entry.source, entry.path);
  if (entry.kind === "item") return buildAssetObjectPropertyTable(card, entry.source?.node || entry.source, entry.path);

  const rows = assetCardRows(card).filter((row) => row.path === entry.path || row.path?.startsWith(`${entry.path}.`));
  return buildAssetRowsDetailTable(rows);
}

function buildAssetCollectionTable(card, collection) {
  const items = collection?.items || [];
  if (!items.length) {
    return { columns: [{ key: "value", title: "Значение" }], rows: [] };
  }
  if (items.every((item) => item && Object.prototype.hasOwnProperty.call(item, "value"))) {
    return {
      columns: [{ key: "value", title: collection?.title || "Значение" }],
      rows: items.map((item, index) => ({ key: item.path || index, value: item.value })),
    };
  }

  const dataKeys = collectAssetCollectionDataKeys(items);
  const sampleType = firstFilled(...items.map((item) => item.type));
  const props = metadataPropertiesForType(card, sampleType || collection?.type);
  const columns = assetCollectionColumns(items, dataKeys, props);

  const rows = items.map((item, index) => {
    const row = { key: item.path || item.object_id || index };
    const data = item.data || {};
    row.display_name = firstFilled(item.display_name, item.displayName);
    row.object_id = firstFilled(item.object_id, item.objectId);
    row.type = item.type;
    columns.forEach((column) => {
      row[column.key] = firstFilled(row[column.key], item[column.key], data[column.key]);
    });
    return row;
  });
  return { columns, rows };
}

function buildAssetObjectPropertyTable(card, object, basePath) {
  const data = object?.data || {};
  const props = metadataPropertiesForType(card, object?.type);
  const baseRows = [
    ["displayName", "Название", object?.displayName || object?.display_name],
    ["vulnerabilityLevel", "Уровень уязвимости", object?.vulnerabilityLevel || object?.vulnerability_level],
  ]
    .filter(([, , value]) => value !== undefined && value !== null && value !== "")
    .map(([key, title, value]) => ({
      key,
      title,
      name: key,
      type: "",
      value,
      path: basePath,
    }));

  const dataRows = Object.entries(data)
    .filter(([key]) => !isHiddenAssetTechnicalField(key))
    .flatMap(([key, value]) => buildAssetPropertyRows({
      name: key,
      title: firstFilled(props[key]?.title, labelizeAssetKey(key)),
      value,
      path: `${basePath}.${key}`,
      type: props[key]?.type || "",
    }));

  return {
    columns: [
      { key: "title", title: "Название" },
      { key: "value", title: "Значение" },
    ],
    rows: [...baseRows, ...dataRows],
    layout: "properties",
  };
}

function buildAssetRowsDetailTable(rows) {
  return {
    columns: [
      { key: "path", title: "Path" },
      { key: "title", title: "Название" },
      { key: "value", title: "Значение" },
    ],
    rows: rows.map((row, index) => ({ ...row, key: `${row.path}-${index}` })),
  };
}

function collectAssetCollectionDataKeys(items) {
  const seen = new Set();
  const preferred = ["ipAddress", "address", "hostname", "fqdn", "macAddress", "name", "displayName", "version", "status"];
  items.forEach((item) => {
    const data = item.data || {};
    Object.keys(data).forEach((key) => {
      if (!isHiddenAssetTechnicalField(key) && !isVerboseAssetValue(data[key])) seen.add(key);
    });
  });
  const keys = Array.from(seen);
  return keys.sort((left, right) => {
    const leftIndex = preferred.indexOf(left);
    const rightIndex = preferred.indexOf(right);
    if (leftIndex !== -1 || rightIndex !== -1) {
      return (leftIndex === -1 ? 999 : leftIndex) - (rightIndex === -1 ? 999 : rightIndex);
    }
    return left.localeCompare(right);
  }).slice(0, 12);
}

function assetCollectionColumns(items, dataKeys, props) {
  const columns = [];
  const addColumn = (key, title) => {
    if (!key || isHiddenAssetTechnicalField(key) || columns.some((column) => column.key === key)) return;
    columns.push({ key, title: title || firstFilled(props[key]?.title, labelizeAssetKey(key)) });
  };

  if (dataKeys.length) {
    dataKeys.forEach((key) => addColumn(key));
    if (columns.length) return columns.slice(0, 14);
  }

  if (items.some((item) => item?.display_name || item?.displayName)) addColumn("display_name", "Имя");
  if (items.some((item) => item?.name || item?.data?.name)) addColumn("name", "Имя");

  if (!columns.length) {
    addColumn("display_name", "Название");
  }

  return columns.slice(0, 14);
}

function metadataPropertiesForType(card, type) {
  const raw = assetCardRaw(card);
  const metadata = card?.metadata || raw.metadata || {};
  const typeMetadata = type ? metadata[type] : null;
  const properties = typeMetadata?.properties;
  if (!Array.isArray(properties)) return {};
  return Object.fromEntries(properties.filter((prop) => prop?.name).map((prop) => [prop.name, prop]));
}

function isHiddenAssetTechnicalField(key) {
  const normalized = String(key || "").replace(/[_-]/g, "").toLowerCase();
  return normalized === "type" || normalized === "objectid";
}

function buildAssetPropertyRows({ name, title, value, path, type = "", depth = 0 }) {
  const row = {
    key: path,
    title,
    name,
    type,
    value,
    path,
    depth,
  };
  return [row, ...buildNestedAssetPropertyRows({ value, path, name, title, depth: depth + 1 })];
}

function buildNestedAssetPropertyRows({ value, path, name, title, depth }) {
  if (depth > 4 || value === undefined || value === null) return [];
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => buildAssetPropertyRows({
      name: `${name}[${index}]`,
      title: `${title} ${index + 1}`,
      value: item,
      path: `${path}[${index}]`,
      depth,
    }));
  }
  if (typeof value !== "object" || "hasItems" in value) return [];

  const nested = value.data && typeof value.data === "object" ? value.data : value;
  return Object.entries(nested)
    .filter(([key]) => !isHiddenAssetTechnicalField(key))
    .flatMap(([key, item]) => buildAssetPropertyRows({
      name: `${name}.${key}`,
      title: labelizeAssetKey(key),
      value: item,
      path: `${path}.${key}`,
      depth,
    }));
}

function assetTreeParentPath(path) {
  if (!path || path === "asset") return null;
  const itemMatch = path.match(/^(.*)\[\d+\]$/);
  if (itemMatch) return itemMatch[1];
  const dotIndex = path.lastIndexOf(".");
  if (dotIndex <= 0) return "asset";
  return path.slice(0, dotIndex);
}

function assetTreeDepth(entry, byPath) {
  let depth = 0;
  let parentPath = entry.parentPath;
  while (parentPath) {
    depth += 1;
    parentPath = byPath.get(parentPath)?.parentPath;
  }
  return depth;
}

function assetPathLabel(path) {
  const itemMatch = path.match(/\[(\d+)\]$/);
  if (itemMatch) return `Элемент ${Number(itemMatch[1]) + 1}`;
  const value = String(path || "").split(".").pop() || path;
  return labelizeAssetKey(value);
}

function assetPathKey(path) {
  const value = String(path || "");
  const itemMatch = value.match(/^(.*)\[\d+\]$/);
  const normalized = itemMatch ? itemMatch[1] : value;
  return normalized.split(".").pop() || normalized;
}

function formatAssetCollectionMeta(collection) {
  const fetched = collection?.fetched_count;
  const total = collection?.count;
  if (fetched == null && total == null) return "";
  return total != null && total !== fetched
    ? `${formatCount(fetched)} / ${formatCount(total)}`
    : formatCount(firstFilled(fetched, total));
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
  return labels[key] || String(key || "").replace(/([a-zа-яё])([A-ZА-ЯЁ])/g, "$1 $2");
}

function filterAssetRowsByNeedle(rows, ...needles) {
  const normalizedNeedles = needles.map(normalizeSearchText).filter(Boolean);
  if (!normalizedNeedles.length) return rows;
  return rows.filter((row) => {
    const haystack = normalizeSearchText(JSON.stringify(row));
    return normalizedNeedles.some((needle) => haystack.includes(needle));
  });
}

function isVerboseAssetValue(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value) && value.objectId && value.type);
}

function formatAssetCell(value) {
  if (value === undefined || value === null || value === "") return "—";
  if (typeof value === "boolean") return value ? "Да" : "Нет";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(formatAssetCell).join(", ");
  if (typeof value === "object") {
    if ("hasItems" in value) return value.hasItems ? "Есть" : "Нет";
    return firstFilled(value.displayName, value.name, value.title, value.value, value.objectId, JSON.stringify(value));
  }
  return String(value);
}

function formatEpoch(value) {
  if (!value) return "";
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return String(value);
  return new Date(numeric * 1000).toLocaleString("ru-RU");
}

function buildPassportSearchText(row) {
  const cves = (row.cves || [])
    .map((item) => [item.display_name, item.url, item.raw?.displayName, item.raw?.url].filter(Boolean).join(" "))
    .join(" ");
  return normalizeSearchText([
    row.name,
    row.external_id,
    row.internal_id,
    row.severity,
    row.score,
    row.issue_time,
    row.package_id,
    row.package_version,
    cves,
    row.metrics?.displayName,
    JSON.stringify(row.raw_record || {}),
    JSON.stringify(row.raw_detail || {}),
  ].filter(Boolean).join(" "));
}

function normalizeSearchText(value) {
  return String(value || "").toLowerCase().replace(/ё/g, "е").trim();
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
  return {
    queued: "в очереди",
    running: "выполняется",
    cancelling: "останавливается",
    cancelled: "остановлена",
    completed: "завершена",
    completed_with_errors: "завершена с ошибками",
    failed: "ошибка",
    interrupted: "прервана перезапуском",
  }[status] || status || "неизвестно";
}

function assetCardJobStatusLabel(status) {
  return {
    queued: "в очереди",
    running: "выполняется",
    cancelling: "останавливается",
    cancelled: "остановлена",
    completed: "завершена",
    failed: "ошибка",
    interrupted: "прервана перезапуском",
  }[status] || status || "неизвестно";
}

function assetCardJobStageLabel(stage) {
  return {
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
  }[stage] || stage || "неизвестно";
}

function AssetsPanel({ summary, rows, total, refreshAssets, busy, runBusy, showAlert }) {
  const [filters, setFilters] = useState({ q: "", severity: "" });
  const applyFilters = () => runBusy("assets", () => refreshAssets(filters));
  const cards = [
    ["Активы", summary?.assets],
    ["ПО", summary?.software],
    ["Findings", summary?.findings],
    ["CVE rows", summary?.cve_rows],
  ];
  return (
    <Panel
      id="assets"
      eyebrow="06"
      title="Актуальный снимок активов и уязвимостей"
      description="Таблица строится из локальной PostgreSQL после CSV/PDQL импорта. Устранённые уязвимости пропадают при следующей перезаписи данных по активу."
      action={<Button variant="secondary" busy={busy.assets} onClick={applyFilters}>Обновить</Button>}
    >
      <div className="metric-grid">
        {cards.map(([label, value]) => (
          <div className="metric-card" key={label}>
            <span>{label}</span>
            <strong>{formatCount(value)}</strong>
          </div>
        ))}
      </div>
      <div className="filters">
        <input value={filters.q} onChange={(event) => setFilters((value) => ({ ...value, q: event.target.value }))} onKeyDown={(event) => event.key === "Enter" && applyFilters()} placeholder="Поиск по IP, FQDN, ПО, CVE, уязвимости" />
        <select value={filters.severity} onChange={(event) => setFilters((value) => ({ ...value, severity: event.target.value }))}>
          <option value="">Все критичности</option>
          <option value="critical">critical</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
          <option value="none">none</option>
        </select>
        <Button variant="secondary" busy={busy.assets} onClick={applyFilters}>Применить</Button>
      </div>
      <div className="table-shell">
        <table>
          <thead>
            <tr>
              <th>IP</th>
              <th>FQDN</th>
              <th>ПО</th>
              <th>Версия</th>
              <th>Уязвимость</th>
              <th>CVE</th>
              <th>Severity</th>
            </tr>
          </thead>
          <tbody>
            {rows.length ? rows.map((row) => (
              <tr key={row.id}>
                <td>{row.ip_address}</td>
                <td>{row.fqdn}</td>
                <td>{row.software_name}</td>
                <td>{row.software_version}</td>
                <td>{row.vulnerability_name}</td>
                <td>{row.cve}</td>
                <td><Severity value={row.severity} /></td>
              </tr>
            )) : (
              <tr><td colSpan={7} className="empty-cell">Нет данных. Импортируйте CSV или выполните PDQL export.</td></tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="table-footer">Показано {formatCount(rows.length)} из {formatCount(total)} строк</div>
    </Panel>
  );
}

function readPath(source, path) {
  if (!source || typeof source !== "object") return undefined;
  return path.split(".").reduce((value, key) => {
    if (!value || typeof value !== "object") return undefined;
    return value[key];
  }, source);
}

function firstFilled(...values) {
  return values.find((value) => value !== undefined && value !== null && value !== "");
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
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.map(textValue).filter(Boolean).join("\n");
  if (typeof value === "object") {
    return firstFilled(value.displayName, value.name, value.title, value.value, value.text, value.description) || "";
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
  const displayName = firstFilled(item.display_name, item.displayName, item.name, item.id, item.value);
  return displayName || item.url ? { display_name: displayName, url: item.url || null } : null;
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
  [row?.external_id, row?.internal_id].filter(Boolean).forEach((value) => values.add(String(value)));
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
      value.map(textValue).filter(Boolean).forEach((item) => values.add(item));
    } else {
      const text = textValue(value);
      if (text) values.add(text);
    }
  }
  return Array.from(values).slice(0, 40);
}

function Severity({ value }) {
  const normalized = (value || "empty").toLowerCase();
  return <span className={`severity severity--${normalized}`}>{value || "empty"}</span>;
}

export {
  AssetsPanel,
  AssetCardsPanel,
  ConnectionPanel,
  ExportPanel,
  TaskBuilderPanel,
  TaskListPanel,
  VulnerabilityPassportsPanel,
};
