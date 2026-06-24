import React, { useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const DEFAULT_STATE = {
  lookups: {
    credentials: [],
    scopes: [],
    scanner_profiles: [],
  },
};

const navItems = [
  ["connection", "Подключение"],
  ["tasks", "Задачи"],
  ["export", "PDQL экспорт"],
  ["passports", "Паспорта"],
  ["assets", "Активы"],
];

function api(path, options = {}) {
  const headers = options.body instanceof FormData ? {} : { "Content-Type": "application/json" };
  return fetch(path, { ...options, headers: { ...headers, ...(options.headers || {}) } }).then(async (response) => {
    const contentType = response.headers.get("content-type") || "";
    const body = contentType.includes("application/json") ? await response.json() : await response.text();
    if (!response.ok) {
      const message = typeof body === "string" ? body : body.detail || JSON.stringify(body);
      throw new Error(message);
    }
    return body;
  });
}

function splitTokens(value) {
  return (value || "")
    .split(/[\n,;]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function formatCount(value) {
  return new Intl.NumberFormat("ru-RU").format(Number(value || 0));
}

function optionLabel(item) {
  if (!item) return "";
  return item.name ? `${item.name}${item.id ? ` · ${item.id}` : ""}` : item.id || "";
}

function Button({ children, variant = "primary", busy, ...props }) {
  return (
    <button className={`button ${variant}`} disabled={busy || props.disabled} {...props}>
      {busy ? "Выполняю..." : children}
    </button>
  );
}

function Field({ label, children, wide }) {
  return (
    <label className={wide ? "field field--wide" : "field"}>
      <span>{label}</span>
      {children}
    </label>
  );
}

function Toggle({ label, checked, onChange }) {
  return (
    <label className="toggle">
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      <span>{label}</span>
    </label>
  );
}

function Panel({ id, eyebrow, title, description, action, children, className = "" }) {
  return (
    <section id={id} className={`panel ${className}`}>
      <div className="panel__header">
        <div>
          {eyebrow ? <div className="section-number">{eyebrow}</div> : null}
          <h2>{title}</h2>
          {description ? <p>{description}</p> : null}
        </div>
        {action ? <div className="panel__action">{action}</div> : null}
      </div>
      {children}
    </section>
  );
}

function App() {
  const [defaults, setDefaults] = useState(null);
  const [session, setSession] = useState({ connected: false });
  const [lookups, setLookups] = useState(DEFAULT_STATE.lookups);
  const [tasks, setTasks] = useState([]);
  const [selectedTaskId, setSelectedTaskId] = useState(null);
  const [summary, setSummary] = useState(null);
  const [assetRows, setAssetRows] = useState([]);
  const [assetTotal, setAssetTotal] = useState(0);
  const [alerts, setAlerts] = useState([]);
  const [busy, setBusy] = useState({});

  const showAlert = useCallback((message, type = "info") => {
    const id = `${Date.now()}-${Math.random()}`;
    setAlerts((items) => [{ id, message, type }, ...items].slice(0, 4));
    window.setTimeout(() => setAlerts((items) => items.filter((item) => item.id !== id)), 9000);
  }, []);

  const runBusy = useCallback(
    async (key, fn) => {
      setBusy((value) => ({ ...value, [key]: true }));
      try {
        return await fn();
      } catch (error) {
        showAlert(error.message || String(error), "error");
        return null;
      } finally {
        setBusy((value) => ({ ...value, [key]: false }));
      }
    },
    [showAlert],
  );

  const refreshTasks = useCallback(async () => {
    const items = await api("/api/scanner-tasks");
    setTasks(items);
  }, []);

  const refreshAssets = useCallback(async (filters = {}) => {
    const params = new URLSearchParams({ limit: "300" });
    if (filters.q) params.set("q", filters.q);
    if (filters.severity) params.set("severity", filters.severity);
    const [summaryResult, assetsResult] = await Promise.all([api("/api/assets/summary"), api(`/api/assets?${params.toString()}`)]);
    setSummary(summaryResult);
    setAssetRows(assetsResult.rows || []);
    setAssetTotal(assetsResult.total || 0);
  }, []);

  useEffect(() => {
    let alive = true;
    Promise.all([api("/api/defaults"), api("/api/session"), api("/api/scanner-tasks"), api("/api/assets/summary"), api("/api/assets?limit=300")])
      .then(([defaultsResult, sessionResult, taskResult, summaryResult, assetsResult]) => {
        if (!alive) return;
        setDefaults(defaultsResult);
        setSession(sessionResult);
        setTasks(taskResult);
        setSummary(summaryResult);
        setAssetRows(assetsResult.rows || []);
        setAssetTotal(assetsResult.total || 0);
      })
      .catch((error) => showAlert(error.message || String(error), "error"));
    return () => {
      alive = false;
    };
  }, [showAlert]);

  const selectedTask = useMemo(() => tasks.find((task) => task.mp_task_id === selectedTaskId) || null, [tasks, selectedTaskId]);

  return (
    <div className="app-shell">
      <Sidebar session={session} />
      <main className="workspace">
        <Topbar session={session} />
        <AlertStack alerts={alerts} />
        <ConnectionPanel
          defaults={defaults}
          session={session}
          setSession={setSession}
          lookups={lookups}
          setLookups={setLookups}
          busy={busy}
          runBusy={runBusy}
          showAlert={showAlert}
        />
        <TaskListPanel
          tasks={tasks}
          lookups={lookups}
          selectedTaskId={selectedTaskId}
          setSelectedTaskId={setSelectedTaskId}
          refreshTasks={refreshTasks}
          busy={busy}
          showAlert={showAlert}
        />
        <TaskBuilderPanel
          defaults={defaults}
          lookups={lookups}
          tasks={tasks}
          selectedTask={selectedTask}
          selectedTaskId={selectedTaskId}
          setSelectedTaskId={setSelectedTaskId}
          refreshTasks={refreshTasks}
          busy={busy}
          runBusy={runBusy}
          showAlert={showAlert}
        />
        <ExportPanel
          defaults={defaults}
          busy={busy}
          runBusy={runBusy}
          refreshAssets={refreshAssets}
          showAlert={showAlert}
        />
        <VulnerabilityPassportsPanel defaults={defaults} busy={busy} runBusy={runBusy} showAlert={showAlert} />
        <AssetsPanel summary={summary} rows={assetRows} total={assetTotal} refreshAssets={refreshAssets} busy={busy} runBusy={runBusy} showAlert={showAlert} />
      </main>
    </div>
  );
}

function Sidebar({ session }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand__mark">MP</div>
        <div>
          <strong>MP VM Client</strong>
          <span>REST API · PostgreSQL</span>
        </div>
      </div>
      <nav className="nav">
        {navItems.map(([href, label]) => (
          <a href={`#${href}`} key={href}>
            {label}
          </a>
        ))}
      </nav>
      <div className="sidebar-card">
        <span className={session.connected ? "pulse pulse--ok" : "pulse"} />
        <div>
          <strong>{session.connected ? "Сессия активна" : "Нет подключения"}</strong>
          <p>{session.connected ? session.api_url : "Подключите MP VM, затем загрузите справочники."}</p>
        </div>
      </div>
    </aside>
  );
}

function Topbar({ session }) {
  return (
    <header className="topbar">
      <div>
        <h1>MP VM REST Client</h1>
        <p>Единая панель для задач сканирования, PDQL-экспорта и локального снимка уязвимостей.</p>
      </div>
      <div className={session.connected ? "status-chip status-chip--ok" : "status-chip"}>
        <span />
        {session.connected ? "Подключено" : "Не подключено"}
      </div>
    </header>
  );
}

function AlertStack({ alerts }) {
  if (!alerts.length) return null;
  return (
    <div className="alerts">
      {alerts.map((alert) => (
        <div className={`alert alert--${alert.type}`} key={alert.id}>
          {alert.message}
        </div>
      ))}
    </div>
  );
}

function ConnectionPanel({ defaults, session, setSession, lookups, setLookups, busy, runBusy, showAlert }) {
  const [form, setForm] = useState({
    api_url: "",
    token_url: "",
    username: "",
    password: "",
    client_id: "mpx",
    client_secret: "",
    scope: "",
    access_token: "",
    verify_tls: true,
  });

  useEffect(() => {
    if (!defaults) return;
    setForm((value) => ({
      ...value,
      api_url: value.api_url || defaults.api_url || "",
      client_id: value.client_id || defaults.client_id || "mpx",
      scope: value.scope || defaults.scope || "",
    }));
  }, [defaults]);

  const update = (key, value) => setForm((current) => ({ ...current, [key]: value }));

  const connect = () =>
    runBusy("connect", async () => {
      const payload = Object.fromEntries(Object.entries(form).map(([key, value]) => [key, value === "" ? null : value]));
      const result = await api("/api/session/connect", { method: "POST", body: JSON.stringify(payload) });
      setSession(result);
      showAlert("Подключение к MP VM установлено.", "success");
      await loadLookups();
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
      wait_for_finish: true,
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
      wait_for_finish: current.wait_for_finish,
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
    wait_for_finish: form.wait_for_finish,
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
          <select value={form.profile_id} onChange={(event) => update("profile_id", event.target.value)}>
            <option value="">Выберите профиль</option>
            {lookups.scanner_profiles.map((item) => <option value={item.id || ""} key={item.id || item.name}>{optionLabel(item)}</option>)}
          </select>
        </Field>
        <Field label="Учётная запись Windows">
          <select value={form.credential_id} onChange={(event) => update("credential_id", event.target.value)}>
            <option value="">Без credential override</option>
            {lookups.credentials.map((item) => <option value={item.id || ""} key={item.id || item.name}>{optionLabel(item)}</option>)}
          </select>
        </Field>
        <Field label="HostDiscovery profile">
          <select value={form.host_discovery_profile_id} onChange={(event) => update("host_discovery_profile_id", event.target.value)}>
            <option value="">Без HostDiscovery profile</option>
            {lookups.scanner_profiles.map((item) => <option value={item.id || ""} key={item.id || item.name}>{optionLabel(item)}</option>)}
          </select>
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
          <Toggle label="Ждать завершения задачи и остановить по таймеру" checked={form.wait_for_finish} onChange={(value) => update("wait_for_finish", value)} />
          <Field label="Precheck profile">
            <select value={form.precheck_profile_id} onChange={(event) => update("precheck_profile_id", event.target.value)}>
              <option value="">Использовать профиль основной задачи</option>
              {lookups.scanner_profiles.map((item) => <option value={item.id || ""} key={item.id || item.name}>{optionLabel(item)}</option>)}
            </select>
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
  return `Старт запрошен для ${result.id}.${precheckText}`;
}

function TaskListPanel({ tasks, lookups, selectedTaskId, setSelectedTaskId, refreshTasks, busy, showAlert }) {
  const [mode, setMode] = useState("delete_v3");
  const [deletingId, setDeletingId] = useState(null);
  const profilesById = useMemo(() => mapById(lookups.scanner_profiles), [lookups.scanner_profiles]);
  const credentialsById = useMemo(() => mapById(lookups.credentials), [lookups.credentials]);

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
                  <td>Активы</td>
                </tr>
              );
            }) : (
              <tr><td colSpan={10} className="empty-cell">Локально сохранённых задач пока нет.</td></tr>
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
    </Panel>
  );
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
  if (["started", "precheck_started"].some((item) => normalized.includes(item))) {
    kind = "running";
    icon = "◔";
  } else if (["finished", "valid", "created", "updated"].some((item) => normalized.includes(item))) {
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

function VulnerabilityPassportsPanel({ defaults, busy, runBusy, showAlert }) {
  const [form, setForm] = useState({
    pdql: "",
    utc_offset: "+05:00",
    group_ids: "",
    asset_ids: "",
    passport_limit: "1001",
    batch_size: "5000",
    include_nested_groups: true,
  });
  const [rows, setRows] = useState([]);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [queryRaw, setQueryRaw] = useState(null);
  const [passportSearch, setPassportSearch] = useState("");
  const [passportPage, setPassportPage] = useState(1);
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
  const filteredRows = useMemo(
    () => filterPassportRows(rows, passportSearch),
    [rows, passportSearch],
  );
  const totalPages = Math.max(1, Math.ceil(filteredRows.length / passportPageSize));
  const safePage = Math.min(passportPage, totalPages);
  const pageRows = filteredRows.slice((safePage - 1) * passportPageSize, safePage * passportPageSize);

  useEffect(() => {
    if (!passportWindowOpen) return;
    const closeOnEscape = (event) => {
      if (event.key === "Escape") setPassportWindowOpen(false);
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [passportWindowOpen]);

  const queryPassports = () =>
    runBusy("passportQuery", async () => {
      const requestedLimit = clampNumber(form.passport_limit, 1001, 1, 50000);
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
        }),
      });
      const records = result.records || [];
      setRows(records);
      setSelected(null);
      setDetail(null);
      setPassportPage(1);
      setPassportWindowOpen(false);
      setQueryRaw(result.raw || null);
      if (records.length) {
        const saved = result.db?.saved;
        showAlert(`Получено паспортов: ${formatCount(records.length)}${saved == null ? "" : `, сохранено в БД: ${formatCount(saved)}`}.`, "success");
      } else {
        showAlert("Паспорта не найдены в ответе /assets_grid/data. Raw-ответ показан под таблицей.", "info");
      }
    });

  const loadLocalPassports = () =>
    runBusy("passportLocal", async () => {
      const localLimit = clampNumber(form.passport_limit, 1000, 1, 50000);
      const result = await api(`/api/vulnerability-passports/local?limit=${encodeURIComponent(localLimit)}`);
      const records = result.rows || [];
      setRows(records);
      setSelected(null);
      setDetail(null);
      setPassportPage(1);
      setPassportWindowOpen(false);
      setQueryRaw(null);
      showAlert(`Загружено из локальной БД: ${formatCount(records.length)} из ${formatCount(result.total)}.`, "success");
    });

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
      setDetail(result.raw || {});
    });

  return (
    <Panel
      id="passports"
      eyebrow="04"
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
        <Field label="Сколько загрузить">
          <input value={form.passport_limit} onChange={(event) => update("passport_limit", event.target.value)} type="number" min="1" max="50000" />
        </Field>
        <Field label="Размер пачки">
          <input value={form.batch_size} onChange={(event) => update("batch_size", event.target.value)} type="number" min="1" max="10000" />
        </Field>
        <Toggle label="Include nested groups" checked={form.include_nested_groups} onChange={(value) => update("include_nested_groups", value)} />
      </div>
      <div className="action-row">
        <Button busy={busy.passportQuery} onClick={queryPassports}>Выполнить PDQL</Button>
        <Button variant="secondary" busy={busy.passportLocal} onClick={loadLocalPassports}>Из БД</Button>
        <div className="inline-metric">Загружено: <span>{formatCount(rows.length)}</span> · найдено: <span>{formatCount(filteredRows.length)}</span></div>
      </div>
      <div className="passport-controls">
        <input
          value={passportSearch}
          onChange={(event) => {
            setPassportSearch(event.target.value);
            setPassportPage(1);
          }}
          placeholder="Поиск по CVE, названию, internalId, package"
        />
        <select
          value={safePage}
          onChange={(event) => setPassportPage(Number(event.target.value))}
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
              <th>internalId</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {filteredRows.length ? pageRows.map((row, rowIndex) => (
              <tr key={row.internal_id || row.external_id || `${row.name}-${rowIndex}`} className={selected?.internal_id === row.internal_id ? "is-selected" : ""}>
                <td><span className="score-badge">{row.score || "n/a"}</span></td>
                <td className="wide-cell">
                  <strong>{row.name || row.external_id || "Без названия"}</strong>
                  <span>{row.external_id}</span>
                </td>
                <td>{(row.cves || []).map((item) => item.display_name).filter(Boolean).join(", ") || "n/a"}</td>
                <td><Severity value={row.severity} /></td>
                <td>{[row.package_id, row.package_version].filter(Boolean).join(" / ") || "n/a"}</td>
                <td><code>{row.internal_id || "n/a"}</code></td>
                <td><Button variant="tiny" busy={busy.passportDetail && selected?.internal_id === row.internal_id} onClick={() => openPassport(row)}>Открыть</Button></td>
              </tr>
            )) : (
              <tr><td colSpan={7} className="empty-cell">{rows.length ? "По текущему поиску ничего не найдено." : "Выполните PDQL, чтобы получить internalId паспортов."}</td></tr>
            )}
          </tbody>
        </table>
      </div>
      {rows.length ? (
        <div className="passport-pagination">
          <span>
            Показано {formatCount(pageRows.length)} из {formatCount(filteredRows.length)}
            {rows.length !== filteredRows.length ? ` · всего загружено ${formatCount(rows.length)}` : ""}
          </span>
          <div>
            <Button variant="tiny" disabled={safePage <= 1} onClick={() => setPassportPage((value) => Math.max(1, value - 1))}>Назад</Button>
            <Button variant="tiny" disabled={safePage >= totalPages} onClick={() => setPassportPage((value) => Math.min(totalPages, value + 1))}>Вперёд</Button>
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
        <PassportModal onClose={() => setPassportWindowOpen(false)}>
          <PassportCard row={selected} detail={detail} loading={busy.passportDetail && !detail} />
        </PassportModal>
      ) : null}
    </Panel>
  );
}

function PassportModal({ children, onClose }) {
  return (
    <div className="passport-modal" role="dialog" aria-modal="true">
      <div className="passport-modal__backdrop" onClick={onClose} />
      <div className="passport-modal__window">
        <div className="passport-modal__bar">
          <strong>Паспорт уязвимости</strong>
          <Button variant="ghost" onClick={onClose}>Закрыть</Button>
        </div>
        {children}
      </div>
    </div>
  );
}

function PassportCard({ row, detail, loading }) {
  const raw = detail || row?.raw_record || {};
  const title = firstFilled(
    readPath(raw, "name"),
    readPath(raw, "displayName"),
    readPath(raw, "title"),
    readPath(raw, "vulnerability.name"),
    row?.name,
  );
  const score = firstFilled(readPath(raw, "score"), readPath(raw, "cvss3Score"), readPath(raw, "cvss.score"), row?.score);
  const severity = firstFilled(readPath(raw, "severityRating"), readPath(raw, "severity"), row?.severity);
  const metrics = firstObject(row?.metrics, readPath(raw, "metrics"), readPath(raw, "Metrics"));
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

  if (!row && !detail) {
    return (
      <div className="passport-placeholder">
        Выберите строку в таблице, чтобы открыть карточку паспорта уязвимости.
      </div>
    );
  }

  return (
    <div className="passport-card">
      <div className="passport-card__header">
        <span className="score-badge score-badge--large">{score || "n/a"}</span>
        <div>
          <h3>{title || "Паспорт уязвимости"}</h3>
          <div className="passport-card__meta">
            {cves.slice(0, 3).map((item) => item.url ? (
              <a href={item.url} target="_blank" rel="noreferrer" key={item.display_name || item.url}>{item.display_name || item.url}</a>
            ) : <span key={item.display_name}>{item.display_name}</span>)}
          </div>
        </div>
      </div>
      <div className="passport-badges">
        <span>Severity: {severity || "n/a"}</span>
        {metrics.exploitable ? <span>Exploit: {String(metrics.exploitable)}</span> : null}
        {metrics.hasFix ? <span>Fix: {String(metrics.hasFix)}</span> : null}
        {metrics.hasNetworkAttackVector ? <span>Network vector: {String(metrics.hasNetworkAttackVector)}</span> : null}
      </div>
      <div className="passport-card__body">
        <div className="passport-card__main">
          <PassportSection title="Основная информация">
            <KeyValue label="Опасность" value={severity} />
            <KeyValue label="Score" value={score} />
            <KeyValue label="Пакет" value={packageLine} />
            <KeyValue label="Дата публикации" value={formatPassportDateTime(issueTime)} />
          </PassportSection>
          <PassportSection title="Описание">
            <p>{description || "В ответе MP VM нет отдельного поля описания. Полный raw-ответ доступен справа."}</p>
          </PassportSection>
          <PassportSection title="Как исправить">
            <p>{remediation || "Рекомендация не найдена в нормализованных полях. Проверьте raw-ответ справа."}</p>
          </PassportSection>
          <PassportSection title="Ссылки">
            {links.length ? links.slice(0, 12).map((link) => (
              <a href={link} target="_blank" rel="noreferrer" key={link}>{link}</a>
            )) : <span className="muted-text">Ссылки не найдены.</span>}
          </PassportSection>
          <PassportSection title="Идентификаторы">
            {identifiers.length ? identifiers.map((id) => <code key={id}>{id}</code>) : <span className="muted-text">Идентификаторы не найдены.</span>}
          </PassportSection>
        </div>
        <aside className="passport-card__side">
          <div className="green-note">{loading ? "Загружаю детальный ответ из MP VM..." : "Детальный ответ получен напрямую из MP VM по internalId паспорта."}</div>
          <details className="raw-details" open>
            <summary>Полный JSON ответа</summary>
            <pre>{JSON.stringify(detail || row?.raw_record || {}, null, 2)}</pre>
          </details>
        </aside>
      </div>
    </div>
  );
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
      eyebrow="05"
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

function firstObject(...values) {
  return values.find((value) => value && typeof value === "object" && !Array.isArray(value)) || {};
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

createRoot(document.getElementById("root")).render(<App />);
