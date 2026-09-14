import { useQuery } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { api } from "../api/client.js";
import { Button, Disclosure, Field, Panel, Toggle } from "../shared/ui.jsx";

const DEFAULT_SCHEDULE = {
  task_id: "",
  name: "",
  cron_expression: "0 2 * * *",
  timezone: "Asia/Yekaterinburg",
  enabled: true,
};

export function AutomationsPage({ showAlert }) {
  const [tab, setTab] = useState("schedules");
  const [busy, setBusy] = useState({});
  const busyRef = useRef(new Set());
  const [scheduleForm, setScheduleForm] = useState(DEFAULT_SCHEDULE);
  const [selectedRun, setSelectedRun] = useState(null);

  const runbooksQuery = useQuery({
    queryKey: ["automations", "runbooks"],
    queryFn: () => api("/api/automations/runbooks"),
  });
  const schedulesQuery = useQuery({
    queryKey: ["automations", "schedules"],
    queryFn: () => api("/api/automations/schedules"),
  });
  const runsQuery = useQuery({
    queryKey: ["automations", "runs"],
    queryFn: () => api("/api/automations/runs"),
    refetchInterval: (query) =>
      (query.state.data?.rows || []).some((item) =>
        ["queued", "running", "cancelling"].includes(item.status),
      )
        ? 2000
        : false,
  });
  const notificationsQuery = useQuery({
    queryKey: ["automations", "notifications"],
    queryFn: () => api("/api/notifications"),
  });
  const scannerTasksQuery = useQuery({
    queryKey: ["automations", "scanner-tasks"],
    queryFn: () => api("/api/scanner-tasks"),
  });

  const runbooks = runbooksQuery.data?.rows || [];
  const schedules = schedulesQuery.data?.rows || [];
  const runs = runsQuery.data?.rows || [];
  const notifications = notificationsQuery.data || { rows: [], unread: 0 };
  const scannerTaskData = scannerTasksQuery.data;
  const scannerTasks = Array.isArray(scannerTaskData)
    ? scannerTaskData
    : scannerTaskData?.rows || [];
  const queries = [
    runbooksQuery,
    schedulesQuery,
    runsQuery,
    notificationsQuery,
    scannerTasksQuery,
  ];

  const refreshAll = () =>
    Promise.allSettled(queries.map((query) => query.refetch()));

  const perform = async (key, action, success) => {
    if (busyRef.current.has(key)) return false;
    busyRef.current.add(key);
    setBusy((current) => ({ ...current, [key]: true }));
    try {
      await action();
      await refreshAll();
      if (success) showAlert(success, "success");
      return true;
    } catch (error) {
      showAlert(error.message, "error");
      return false;
    } finally {
      busyRef.current.delete(key);
      setBusy((current) => ({ ...current, [key]: false }));
    }
  };

  const createSchedule = async () => {
    const required = [
      [scheduleForm.task_id, "Выберите задачу сканирования MP VM."],
      [scheduleForm.name.trim(), "Введите название расписания."],
      [scheduleForm.cron_expression.trim(), "Введите cron-выражение."],
      [scheduleForm.timezone.trim(), "Введите часовой пояс."],
    ];
    const invalid = required.find(([value]) => !value);
    if (invalid) {
      showAlert(invalid[1], "error");
      return;
    }

    const task = scannerTasks.find(
      (item) => item.mp_task_id === scheduleForm.task_id,
    );
    const created = await perform(
      "schedule:create",
      async () => {
        let runbook;
        try {
          runbook = await api("/api/automations/runbooks", {
            method: "POST",
            body: JSON.stringify({
              name: scheduleForm.name.trim(),
              description:
                "Служебный сценарий для запуска задачи MP VM по расписанию.",
              steps: [
                {
                  step_id: "scheduled-scan",
                  type: "scanner_task_start",
                  config: {
                    task_id: scheduleForm.task_id,
                    wait: true,
                    timeout_seconds: 7200,
                    options: {
                      precheck_enabled: false,
                      task_timeout_minutes: 120,
                      require_clean_jobs: false,
                    },
                  },
                  condition: null,
                  on_error: "stop",
                  max_retries: 0,
                },
              ],
            }),
          });
          await api(
            `/api/automations/runbooks/${runbook.runbook_id}/publish`,
            {
              method: "POST",
              body: JSON.stringify({ confirm_name: null }),
            },
          );
          await api("/api/automations/schedules", {
            method: "POST",
            body: JSON.stringify({
              runbook_id: runbook.runbook_id,
              name: scheduleForm.name.trim(),
              cron_expression: scheduleForm.cron_expression.trim(),
              timezone: scheduleForm.timezone.trim(),
              enabled: scheduleForm.enabled,
            }),
          });
        } catch (error) {
          if (runbook?.runbook_id) {
            try {
              await api(`/api/automations/runbooks/${runbook.runbook_id}`, {
                method: "DELETE",
              });
            } catch {
              // Preserve the original failure; cleanup can be retried separately.
            }
          }
          throw error;
        }
      },
      `Расписание для задачи «${task?.name || scheduleForm.task_id}» создано.`,
    );
    if (created) setScheduleForm(DEFAULT_SCHEDULE);
  };

  const runbookById = new Map(
    runbooks.map((runbook) => [runbook.runbook_id, runbook]),
  );
  const taskById = new Map(
    scannerTasks.map((task) => [task.mp_task_id, task]),
  );
  const tabs = [
    ["schedules", "Расписания"],
    ["runs", "Запуски"],
    ["notifications", `Уведомления · ${notifications.unread || 0}`],
  ];

  return (
    <>
      <AutomationTabs tab={tab} tabs={tabs} onChange={setTab} />

      {tab === "schedules" && (
        <Panel
          id="automation-panel-schedules"
          role="tabpanel"
          aria-labelledby="automation-tab-schedules"
          title="Автоматизация сканирования"
          description="Запускайте выбранную задачу MP VM по cron. После завершения приложение автоматически выполнит штатную обработку результатов."
        >
          <Disclosure
            title="Новое расписание"
            description="Задача MP VM, cron и часовой пояс"
            defaultOpen
          >
            {scannerTasksQuery.isError ? (
              <AutomationQueryError
                label="задачи сканирования"
                query={scannerTasksQuery}
              />
            ) : null}
            <div className="form-grid form-grid--four">
              <Field label="Задача сканирования MP VM">
                <select
                  value={scheduleForm.task_id}
                  disabled={scannerTasksQuery.isPending}
                  onChange={(event) =>
                    setScheduleForm({
                      ...scheduleForm,
                      task_id: event.target.value,
                    })
                  }
                >
                  <option value="">
                    {scannerTasksQuery.isPending
                      ? "Загрузка задач…"
                      : "Выберите задачу"}
                  </option>
                  {scannerTasks.map((task) => (
                    <option key={task.mp_task_id} value={task.mp_task_id}>
                      {task.name || task.mp_task_id}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Название расписания">
                <input
                  value={scheduleForm.name}
                  placeholder="Например, ночное сканирование"
                  onChange={(event) =>
                    setScheduleForm({
                      ...scheduleForm,
                      name: event.target.value,
                    })
                  }
                />
              </Field>
              <Field label="Cron">
                <input
                  value={scheduleForm.cron_expression}
                  aria-describedby="automation-cron-help"
                  onChange={(event) =>
                    setScheduleForm({
                      ...scheduleForm,
                      cron_expression: event.target.value,
                    })
                  }
                />
                <small id="automation-cron-help">
                  Минута · час · день месяца · месяц · день недели
                </small>
              </Field>
              <Field label="Часовой пояс">
                <input
                  value={scheduleForm.timezone}
                  onChange={(event) =>
                    setScheduleForm({
                      ...scheduleForm,
                      timezone: event.target.value,
                    })
                  }
                />
              </Field>
            </div>
            <div className="action-row">
              <Toggle
                label="Активно"
                checked={scheduleForm.enabled}
                onChange={(enabled) =>
                  setScheduleForm({ ...scheduleForm, enabled })
                }
              />
              <Button busy={busy["schedule:create"]} onClick={createSchedule}>
                Создать расписание
              </Button>
            </div>
          </Disclosure>

          <SchedulesTable
            schedules={schedules}
            query={schedulesQuery}
            runbookById={runbookById}
            taskById={taskById}
            busy={busy}
            perform={perform}
          />
        </Panel>
      )}

      {tab === "runs" && (
        <RunsPanel
          runs={runs}
          query={runsQuery}
          selectedRun={selectedRun}
          setSelectedRun={setSelectedRun}
          busy={busy}
          perform={perform}
        />
      )}

      {tab === "notifications" && (
        <NotificationsPanel
          notifications={notifications}
          query={notificationsQuery}
          busy={busy}
          perform={perform}
        />
      )}
    </>
  );
}

function AutomationTabs({ tab, tabs, onChange }) {
  return (
    <div
      className="automation-tabs"
      role="tablist"
      aria-label="Разделы автоматизации"
    >
      {tabs.map(([id, label], index) => (
        <button
          type="button"
          role="tab"
          id={`automation-tab-${id}`}
          aria-controls={`automation-panel-${id}`}
          aria-selected={tab === id}
          tabIndex={tab === id ? 0 : -1}
          key={id}
          className={tab === id ? "is-active" : ""}
          onClick={() => onChange(id)}
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
                  ? tabs.length - 1
                  : (index +
                      (event.key === "ArrowRight" ? 1 : -1) +
                      tabs.length) %
                    tabs.length;
            onChange(tabs[nextIndex][0]);
            event.currentTarget.parentElement
              ?.querySelectorAll('[role="tab"]')
              ?.[nextIndex]?.focus();
          }}
        >
          {label}
        </button>
      ))}
    </div>
  );
}

function SchedulesTable({
  schedules,
  query,
  runbookById,
  taskById,
  busy,
  perform,
}) {
  return (
    <div className="table-shell">
      <table>
        <thead>
          <tr>
            <th>Название</th>
            <th>Задача MP VM</th>
            <th>Cron</th>
            <th>Следующий запуск</th>
            <th>Статус</th>
            <th>Действия</th>
          </tr>
        </thead>
        <tbody>
          {query.isPending ? (
            <LoadingRow columns="6" label="Загрузка расписаний…" />
          ) : query.isError ? (
            <ErrorRow columns="6" label="расписания" query={query} />
          ) : schedules.length ? (
            schedules.map((item) => {
              const runbook = runbookById.get(item.runbook_id);
              const step = (runbook?.draft?.steps || []).find(
                (value) => value.type === "scanner_task_start",
              );
              const taskId = step?.config?.task_id;
              const task = taskById.get(taskId);
              return (
                <tr key={item.schedule_id}>
                  <td>{item.name}</td>
                  <td>
                    <strong>
                      {task?.name || taskId || item.runbook_name || "—"}
                    </strong>
                    {taskId ? <small>{taskId}</small> : null}
                  </td>
                  <td>
                    <code>{item.cron_expression}</code>
                    <small>{item.timezone}</small>
                  </td>
                  <td>{formatDate(item.next_run_at)}</td>
                  <td>
                    {item.enabled ? item.last_status || "активно" : "пауза"}
                  </td>
                  <td>
                    <div className="row-actions">
                      <Button
                        variant="tiny"
                        busy={busy[`schedule:toggle:${item.schedule_id}`]}
                        onClick={() =>
                          perform(
                            `schedule:toggle:${item.schedule_id}`,
                            () =>
                              api(
                                `/api/automations/schedules/${item.schedule_id}`,
                                {
                                  method: "PUT",
                                  body: JSON.stringify({
                                    runbook_id: item.runbook_id,
                                    name: item.name,
                                    cron_expression: item.cron_expression,
                                    timezone: item.timezone,
                                    enabled: !item.enabled,
                                  }),
                                },
                              ),
                          )
                        }
                      >
                        {item.enabled ? "Пауза" : "Включить"}
                      </Button>
                      <Button
                        variant="tiny-danger"
                        busy={busy[`schedule:delete:${item.schedule_id}`]}
                        onClick={() =>
                          perform(
                            `schedule:delete:${item.schedule_id}`,
                            () =>
                              api(
                                `/api/automations/schedules/${item.schedule_id}`,
                                { method: "DELETE" },
                              ),
                            "Расписание удалено.",
                          )
                        }
                      >
                        Удалить
                      </Button>
                    </div>
                  </td>
                </tr>
              );
            })
          ) : (
            <EmptyRow columns="6" label="Расписания ещё не созданы." />
          )}
        </tbody>
      </table>
    </div>
  );
}

function RunsPanel({ runs, query, selectedRun, setSelectedRun, busy, perform }) {
  return (
    <div
      id="automation-panel-runs"
      role="tabpanel"
      aria-labelledby="automation-tab-runs"
    >
      <Panel
        title="История запусков"
        action={
          <Button
            variant="secondary"
            busy={busy["refresh:all"]}
            onClick={() => perform("refresh:all", () => Promise.resolve())}
          >
            Обновить
          </Button>
        }
      >
        <div className="table-shell">
          <table>
          <thead>
            <tr>
              <th>Расписание</th>
              <th>Триггер</th>
              <th>Статус</th>
              <th>Этап</th>
              <th>Создан</th>
              <th>Действия</th>
            </tr>
          </thead>
          <tbody>
            {query.isPending ? (
              <LoadingRow columns="6" label="Загрузка запусков…" />
            ) : query.isError ? (
              <ErrorRow columns="6" label="историю запусков" query={query} />
            ) : runs.length ? (
              runs.map((item) => (
                <tr key={item.run_id}>
                  <td>{item.runbook_name || item.runbook_id}</td>
                  <td>{item.trigger_type}</td>
                  <td>
                    <span
                      className={`operation-status operation-status--${item.status}`}
                    >
                      {item.status}
                    </span>
                  </td>
                  <td>{item.current_step + 1}</td>
                  <td>{formatDate(item.created_at)}</td>
                  <td>
                    <div className="row-actions">
                      <Button
                        variant="tiny"
                        busy={busy[`run:detail:${item.run_id}`]}
                        onClick={() =>
                          perform(`run:detail:${item.run_id}`, async () =>
                            setSelectedRun(
                              await api(
                                `/api/automations/runs/${item.run_id}`,
                              ),
                            ),
                          )
                        }
                      >
                        Этапы
                      </Button>
                      <Button
                        variant="tiny"
                        disabled={!["queued", "running", "cancelling"].includes(
                          item.status,
                        )}
                        busy={busy[`run:cancel:${item.run_id}`]}
                        onClick={() =>
                          perform(
                            `run:cancel:${item.run_id}`,
                            () =>
                              api(
                                `/api/automations/runs/${item.run_id}/cancel`,
                                { method: "POST" },
                              ),
                            "Отмена запрошена.",
                          )
                        }
                      >
                        Отменить
                      </Button>
                    </div>
                  </td>
                </tr>
              ))
            ) : (
              <EmptyRow columns="6" label="Запусков пока нет." />
            )}
          </tbody>
          </table>
        </div>
      </Panel>
      {selectedRun ? (
        <Panel
          title={`Этапы запуска ${selectedRun.run_id}`}
          action={
            <Button variant="ghost" onClick={() => setSelectedRun(null)}>
              Закрыть
            </Button>
          }
        >
          <div className="automation-run-steps">
            {(selectedRun.steps || []).map((step) => (
              <article key={step.step_index}>
                <strong>
                  {step.step_index + 1}. {step.step_id}
                </strong>
                <span>
                  {step.step_type} · {step.status} · попыток {step.attempts}
                </span>
                {step.error ? <p>{step.error}</p> : null}
                <details>
                  <summary>Вход и результат</summary>
                  <pre>
                    {JSON.stringify(
                      { input: step.input, output: step.output },
                      null,
                      2,
                    )}
                  </pre>
                </details>
              </article>
            ))}
          </div>
        </Panel>
      ) : null}
    </div>
  );
}

function NotificationsPanel({ notifications, query, busy, perform }) {
  return (
    <Panel
      id="automation-panel-notifications"
      role="tabpanel"
      aria-labelledby="automation-tab-notifications"
      title="Центр уведомлений"
      description={`Непрочитанных: ${notifications.unread || 0}`}
    >
      <div className="automation-notifications">
        {query.isPending ? (
          <div className="query-state" role="status">
            Загрузка уведомлений…
          </div>
        ) : null}
        {query.isError ? (
          <AutomationQueryError label="уведомления" query={query} />
        ) : null}
        {!query.isPending && !query.isError
          ? notifications.rows.map((item) => (
              <article
                key={item.notification_id}
                className={`automation-notification automation-notification--${item.level} ${item.is_read ? "is-read" : ""}`}
              >
                <div>
                  <strong>{item.title}</strong>
                  <p>{item.message}</p>
                  <small>
                    {formatDate(item.created_at)} · {item.event_type}
                  </small>
                </div>
                {!item.is_read ? (
                  <Button
                    variant="tiny"
                    busy={busy[`notification:read:${item.notification_id}`]}
                    onClick={() =>
                      perform(
                        `notification:read:${item.notification_id}`,
                        () =>
                          api(
                            `/api/notifications/${item.notification_id}/read`,
                            { method: "POST" },
                          ),
                      )
                    }
                  >
                    Прочитано
                  </Button>
                ) : null}
              </article>
            ))
          : null}
        {!query.isPending && !query.isError && !notifications.rows.length ? (
          <div className="query-state">Уведомлений пока нет.</div>
        ) : null}
      </div>
    </Panel>
  );
}

function LoadingRow({ columns, label }) {
  return (
    <tr>
      <td colSpan={columns} className="empty-cell" role="status">
        {label}
      </td>
    </tr>
  );
}

function EmptyRow({ columns, label }) {
  return (
    <tr>
      <td colSpan={columns} className="empty-cell">
        {label}
      </td>
    </tr>
  );
}

function ErrorRow({ columns, label, query }) {
  return (
    <tr>
      <td colSpan={columns} className="empty-cell">
        <AutomationQueryError label={label} query={query} />
      </td>
    </tr>
  );
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ru-RU");
}

function AutomationQueryError({ label, query }) {
  return (
    <div className="query-state query-state--error" role="alert">
      <span>
        Не удалось загрузить {label}:{" "}
        {query.error?.message || "сервис недоступен"}.
      </span>
      <Button variant="tiny" onClick={() => query.refetch()}>
        Повторить
      </Button>
    </div>
  );
}
