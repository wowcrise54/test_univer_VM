import { useQuery } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { api, createIdempotencyKey } from "../api/client.js";
import {
  AutomationStepEditor,
  automationStepFromApi,
  automationStepToApi,
  createAutomationStep,
  validateAutomationSteps,
} from "../features/automations/StepEditor.jsx";
import { Button, ConfirmDialog, Field, Panel, Toggle } from "../shared/ui.jsx";

export function AutomationsPage({ showAlert }) {
  const [tab, setTab] = useState("runbooks");
  const [busy, setBusy] = useState({});
  const busyRef = useRef(new Set());
  const [editingId, setEditingId] = useState(null);
  const [publishTarget, setPublishTarget] = useState(null);
  const [form, setForm] = useState({
    name: "",
    description: "",
    steps: [createAutomationStep()],
  });
  const [scheduleForm, setScheduleForm] = useState({
    runbook_id: "",
    name: "",
    cron_expression: "0 2 * * *",
    timezone: "Asia/Yekaterinburg",
    enabled: true,
  });
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
  const templatesQuery = useQuery({
    queryKey: ["automations", "templates"],
    queryFn: () => api("/api/automations/templates"),
  });
  const scannerTasksQuery = useQuery({
    queryKey: ["automations", "scanner-tasks"],
    queryFn: () => api("/api/scanner-tasks"),
  });
  const fieldCatalogQuery = useQuery({
    queryKey: ["automations", "field-catalog"],
    queryFn: () => api("/api/asset-card-query/fields?limit=500"),
  });

  const runbooks = runbooksQuery.data?.rows || [];
  const schedules = schedulesQuery.data?.rows || [];
  const runs = runsQuery.data?.rows || [];
  const notifications = notificationsQuery.data || { rows: [], unread: 0 };
  const templates = templatesQuery.data?.rows || [];
  const scannerTaskData = scannerTasksQuery.data;
  const scannerTasks = Array.isArray(scannerTaskData)
    ? scannerTaskData
    : scannerTaskData?.rows || [];
  const fieldCatalog = fieldCatalogQuery.data?.rows || [];
  const queries = [
    runbooksQuery,
    schedulesQuery,
    runsQuery,
    notificationsQuery,
    templatesQuery,
    scannerTasksQuery,
    fieldCatalogQuery,
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

  const payload = () => ({
    name: form.name.trim(),
    description: form.description.trim(),
    steps: form.steps.map(automationStepToApi),
  });

  const save = async () => {
    if (!form.name.trim()) {
      showAlert("Введите название сценария.", "error");
      return;
    }
    const validationError = validateAutomationSteps(form.steps);
    if (validationError) {
      showAlert(validationError, "error");
      return;
    }
    const saved = await perform(
      "runbook:save",
      () =>
        api(
          editingId
            ? `/api/automations/runbooks/${editingId}`
            : "/api/automations/runbooks",
          {
            method: editingId ? "PUT" : "POST",
            body: JSON.stringify(payload()),
          },
        ),
      editingId ? "Сценарий обновлён." : "Сценарий создан.",
    );
    if (saved) resetForm();
  };

  const edit = (runbook) => {
    setEditingId(runbook.runbook_id);
    setForm({
      name: runbook.name,
      description: runbook.description || "",
      steps: (runbook.draft?.steps || []).map(automationStepFromApi),
    });
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const resetForm = () => {
    setEditingId(null);
    setForm({ name: "", description: "", steps: [createAutomationStep()] });
  };

  const publish = (runbook) => {
    const destructive = (runbook.draft?.steps || []).some(
      (step) =>
        step.type === "pdql_export" && step.config?.delete_assets_after_export,
    );
    if (destructive) {
      setPublishTarget(runbook);
      return;
    }
    publishConfirmed(runbook, null);
  };

  const publishConfirmed = (runbook, confirmName) => {
    perform(
      `runbook:publish:${runbook.runbook_id}`,
      () =>
        api(`/api/automations/runbooks/${runbook.runbook_id}/publish`, {
          method: "POST",
          body: JSON.stringify({ confirm_name: confirmName }),
        }),
      "Версия опубликована.",
    ).then((published) => published && setPublishTarget(null));
  };

  const startRun = (runbook, dryRun) =>
    perform(
      `runbook:run:${runbook.runbook_id}:${dryRun ? "dry" : "live"}`,
      () =>
        api(`/api/automations/runbooks/${runbook.runbook_id}/run`, {
          method: "POST",
          headers: { "X-Idempotency-Key": createIdempotencyKey("runbook") },
          body: JSON.stringify({ dry_run: dryRun }),
        }),
      dryRun ? "Проверочный запуск начат." : "Сценарий запущен.",
    );

  const applyTemplate = (template) => {
    setEditingId(null);
    setForm({
      name: template.name,
      description: template.description,
      steps: template.steps.map(automationStepFromApi),
    });
  };

  const updateStep = (index, patch) =>
    setForm((current) => ({
      ...current,
      steps: current.steps.map((step, position) =>
        position === index ? { ...step, ...patch } : step,
      ),
    }));
  const moveStep = (index, delta) =>
    setForm((current) => {
      const steps = [...current.steps];
      const target = index + delta;
      if (target < 0 || target >= steps.length) return current;
      [steps[index], steps[target]] = [steps[target], steps[index]];
      return { ...current, steps };
    });

  const publishedRunbooks = runbooks.filter((item) => item.published_version);
  const automationTabs = [
    ["runbooks", "Сценарии"],
    ["schedules", "Расписания"],
    ["runs", "Запуски"],
    ["notifications", `Уведомления · ${notifications.unread || 0}`],
  ];

  return (
    <>
      <div
        className="automation-tabs"
        role="tablist"
        aria-label="Разделы автоматизации"
      >
        {automationTabs.map(([id, label], index) => (
          <button
            type="button"
            role="tab"
            id={`automation-tab-${id}`}
            aria-controls={`automation-panel-${id}`}
            aria-selected={tab === id}
            tabIndex={tab === id ? 0 : -1}
            key={id}
            className={tab === id ? "is-active" : ""}
            onClick={() => setTab(id)}
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
                    ? automationTabs.length - 1
                    : (index +
                        (event.key === "ArrowRight" ? 1 : -1) +
                        automationTabs.length) %
                      automationTabs.length;
              setTab(automationTabs[nextIndex][0]);
              const tabButtons =
                event.currentTarget.parentElement?.querySelectorAll(
                  '[role="tab"]',
                );
              tabButtons?.[nextIndex]?.focus();
            }}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "runbooks" && (
        <div
          id="automation-panel-runbooks"
          role="tabpanel"
          aria-labelledby="automation-tab-runbooks"
        >
          <Panel
            title={editingId ? "Редактирование сценария" : "Новый сценарий"}
            description="Добавьте действия в нужном порядке. Опубликованная версия остаётся неизменной."
          >
            <div className="form-grid form-grid--two">
              <Field label="Название">
                <input
                  value={form.name}
                  onChange={(event) =>
                    setForm({ ...form, name: event.target.value })
                  }
                />
              </Field>
              <Field label="Описание">
                <input
                  value={form.description}
                  onChange={(event) =>
                    setForm({ ...form, description: event.target.value })
                  }
                />
              </Field>
            </div>
            <div className="automation-steps">
              {scannerTasksQuery.isPending || fieldCatalogQuery.isPending ? (
                <div className="query-state" role="status">
                  Загрузка справочников редактора…
                </div>
              ) : null}
              {scannerTasksQuery.isError || fieldCatalogQuery.isError ? (
                <div className="query-state query-state--error" role="alert">
                  Не все справочники редактора доступны. Существующие значения
                  сохранены; повторите загрузку перед публикацией.
                </div>
              ) : null}
              {form.steps.map((step, index) => (
                <AutomationStepEditor
                  key={`${step.step_id}-${index}`}
                  step={step}
                  index={index}
                  steps={form.steps}
                  scannerTasks={scannerTasks}
                  fieldCatalog={fieldCatalog}
                  onChange={(next) => updateStep(index, next)}
                  onMove={(delta) => moveStep(index, delta)}
                  onRemove={() =>
                    setForm((current) => ({
                      ...current,
                      steps: current.steps.filter(
                        (_, position) => position !== index,
                      ),
                    }))
                  }
                />
              ))}
            </div>
            <div className="action-row">
              <Button
                variant="secondary"
                onClick={() =>
                  setForm((current) => ({
                    ...current,
                    steps: [...current.steps, createAutomationStep()],
                  }))
                }
              >
                Добавить шаг
              </Button>
              <Button busy={busy["runbook:save"]} onClick={save}>
                {editingId ? "Сохранить" : "Создать"}
              </Button>
              {editingId && (
                <Button variant="ghost" onClick={resetForm}>
                  Отмена
                </Button>
              )}
            </div>
            <div className="automation-templates">
              {templatesQuery.isPending ? (
                <span role="status">Загрузка шаблонов…</span>
              ) : null}
              {templatesQuery.isError ? (
                <span role="alert">Не удалось загрузить шаблоны.</span>
              ) : null}
              {templates.map((template) => (
                <button
                  key={template.template_id}
                  onClick={() => applyTemplate(template)}
                >
                  {template.name}
                </button>
              ))}
            </div>
          </Panel>
          <Panel
            title="Сценарии"
            description="Публикация фиксирует версию, а дальнейшие изменения сохраняются в новом черновике."
          >
            <div className="table-shell">
              <table>
                <thead>
                  <tr>
                    <th>Название</th>
                    <th>Версия</th>
                    <th>Шаги</th>
                    <th>Допуск</th>
                    <th>Действия</th>
                  </tr>
                </thead>
                <tbody>
                  {runbooksQuery.isPending ? (
                    <tr>
                      <td colSpan="5" className="empty-cell" role="status">
                        Загрузка сценариев…
                      </td>
                    </tr>
                  ) : runbooksQuery.isError ? (
                    <tr>
                      <td colSpan="5" className="empty-cell">
                        <AutomationQueryError
                          label="сценарии"
                          query={runbooksQuery}
                        />
                      </td>
                    </tr>
                  ) : (
                    runbooks.map((item) => (
                      <tr key={item.runbook_id}>
                        <td>
                          <strong>{item.name}</strong>
                          <small>{item.description}</small>
                        </td>
                        <td>{item.published_version || "Черновик"}</td>
                        <td>{item.draft?.steps?.length || 0}</td>
                        <td>
                          {item.allow_destructive
                            ? "опасные разрешены"
                            : "безопасный"}
                        </td>
                        <td>
                          <div className="row-actions">
                            <Button variant="tiny" onClick={() => edit(item)}>
                              Изменить
                            </Button>
                            <Button
                              variant="tiny"
                              busy={busy[`runbook:publish:${item.runbook_id}`]}
                              onClick={() => publish(item)}
                            >
                              Опубликовать
                            </Button>
                            <Button
                              variant="tiny"
                              disabled={!item.published_version}
                              busy={busy[`runbook:run:${item.runbook_id}:dry`]}
                              onClick={() => startRun(item, true)}
                            >
                              Проверить
                            </Button>
                            <Button
                              variant="tiny"
                              disabled={!item.published_version}
                              busy={busy[`runbook:run:${item.runbook_id}:live`]}
                              onClick={() => startRun(item, false)}
                            >
                              Запустить
                            </Button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                  {!runbooksQuery.isPending &&
                    !runbooksQuery.isError &&
                    !runbooks.length && (
                      <tr>
                        <td colSpan="5" className="empty-cell">
                          Сценарии ещё не созданы.
                        </td>
                      </tr>
                    )}
                </tbody>
              </table>
            </div>
          </Panel>
        </div>
      )}

      {tab === "schedules" && (
        <Panel
          id="automation-panel-schedules"
          role="tabpanel"
          aria-labelledby="automation-tab-schedules"
          title="Расписания"
          description="Cron вычисляется в выбранной timezone; пропуски не догоняются."
        >
          <div className="form-grid form-grid--four">
            <Field label="Сценарий">
              <select
                value={scheduleForm.runbook_id}
                onChange={(event) =>
                  setScheduleForm({
                    ...scheduleForm,
                    runbook_id: event.target.value,
                  })
                }
              >
                <option value="">Выберите</option>
                {publishedRunbooks.map((item) => (
                  <option key={item.runbook_id} value={item.runbook_id}>
                    {item.name}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Название">
              <input
                value={scheduleForm.name}
                onChange={(event) =>
                  setScheduleForm({ ...scheduleForm, name: event.target.value })
                }
              />
            </Field>
            <Field label="Cron">
              <input
                value={scheduleForm.cron_expression}
                onChange={(event) =>
                  setScheduleForm({
                    ...scheduleForm,
                    cron_expression: event.target.value,
                  })
                }
              />
            </Field>
            <Field label="Timezone">
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
            <Button
              busy={busy["schedule:create"]}
              onClick={() =>
                perform(
                  "schedule:create",
                  () =>
                    api("/api/automations/schedules", {
                      method: "POST",
                      body: JSON.stringify(scheduleForm),
                    }),
                  "Расписание создано.",
                )
              }
            >
              Создать расписание
            </Button>
          </div>
          <div className="table-shell">
            <table>
              <thead>
                <tr>
                  <th>Название</th>
                  <th>Сценарий</th>
                  <th>Cron</th>
                  <th>Следующий запуск</th>
                  <th>Статус</th>
                  <th>Действия</th>
                </tr>
              </thead>
              <tbody>
                {schedulesQuery.isPending ? (
                  <tr>
                    <td colSpan="6" className="empty-cell" role="status">
                      Загрузка расписаний…
                    </td>
                  </tr>
                ) : schedulesQuery.isError ? (
                  <tr>
                    <td colSpan="6" className="empty-cell">
                      <AutomationQueryError
                        label="расписания"
                        query={schedulesQuery}
                      />
                    </td>
                  </tr>
                ) : schedules.length ? (
                  schedules.map((item) => (
                    <tr key={item.schedule_id}>
                      <td>{item.name}</td>
                      <td>{item.runbook_name}</td>
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
                            busy={busy[`schedule:toggle:${item.schedule_id}`]}
                          >
                            {item.enabled ? "Пауза" : "Включить"}
                          </Button>
                          <Button
                            variant="tiny-danger"
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
                            busy={busy[`schedule:delete:${item.schedule_id}`]}
                          >
                            Удалить
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="6" className="empty-cell">
                      Расписания ещё не созданы.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {tab === "runs" && (
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
                    <th>Сценарий</th>
                    <th>Триггер</th>
                    <th>Статус</th>
                    <th>Шаг</th>
                    <th>Создан</th>
                    <th>Действия</th>
                  </tr>
                </thead>
                <tbody>
                  {runsQuery.isPending ? (
                    <tr>
                      <td colSpan="6" className="empty-cell" role="status">
                        Загрузка запусков…
                      </td>
                    </tr>
                  ) : runsQuery.isError ? (
                    <tr>
                      <td colSpan="6" className="empty-cell">
                        <AutomationQueryError
                          label="историю запусков"
                          query={runsQuery}
                        />
                      </td>
                    </tr>
                  ) : runs.length ? (
                    runs.map((item) => (
                      <tr key={item.run_id}>
                        <td>{item.runbook_name || item.runbook_id}</td>
                        <td>
                          {item.trigger_type}
                          {item.dry_run ? " · dry-run" : ""}
                        </td>
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
                              Шаги
                            </Button>
                            <Button
                              variant="tiny"
                              disabled={
                                !["queued", "running", "cancelling"].includes(
                                  item.status,
                                )
                              }
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
                              busy={busy[`run:cancel:${item.run_id}`]}
                            >
                              Отменить
                            </Button>
                          </div>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="6" className="empty-cell">
                        Запусков пока нет.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Panel>
          {selectedRun && (
            <Panel
              title={`Шаги запуска ${selectedRun.run_id}`}
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
                    {step.error && <p>{step.error}</p>}
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
          )}
        </div>
      )}

      {tab === "notifications" && (
        <Panel
          id="automation-panel-notifications"
          role="tabpanel"
          aria-labelledby="automation-tab-notifications"
          title="Центр уведомлений"
          description={`Непрочитанных: ${notifications.unread || 0}`}
        >
          <div className="automation-notifications">
            {notificationsQuery.isPending ? (
              <div className="query-state" role="status">
                Загрузка уведомлений…
              </div>
            ) : null}
            {notificationsQuery.isError ? (
              <AutomationQueryError
                label="уведомления"
                query={notificationsQuery}
              />
            ) : null}
            {!notificationsQuery.isPending &&
              !notificationsQuery.isError &&
              notifications.rows.map((item) => (
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
                  {!item.is_read && (
                    <Button
                      variant="tiny"
                      onClick={() =>
                        perform(
                          `notification:read:${item.notification_id}`,
                          () =>
                            api(
                              `/api/notifications/${item.notification_id}/read`,
                              {
                                method: "POST",
                              },
                            ),
                        )
                      }
                      busy={busy[`notification:read:${item.notification_id}`]}
                    >
                      Прочитано
                    </Button>
                  )}
                </article>
              ))}
            {!notificationsQuery.isPending &&
            !notificationsQuery.isError &&
            !notifications.rows.length ? (
              <div className="query-state">Уведомлений пока нет.</div>
            ) : null}
          </div>
        </Panel>
      )}

      <ConfirmDialog
        open={Boolean(publishTarget)}
        title="Разрешить удаление активов?"
        description="В сценарии включён шаг, который после успешного экспорта удаляет активы из MP VM. Опубликуйте его только если это ожидаемое поведение."
        impact={[
          "Сначала результат будет сохранён в локальной базе.",
          "После этого выбранные активы будут удалены из MP VM.",
          "Опубликованная версия останется неизменной до следующей публикации.",
        ]}
        requireText={publishTarget?.name || ""}
        confirmLabel="Опубликовать с удалением"
        busy={Boolean(
          publishTarget && busy[`runbook:publish:${publishTarget.runbook_id}`],
        )}
        onClose={() => setPublishTarget(null)}
        onConfirm={() => publishConfirmed(publishTarget, publishTarget.name)}
      />
    </>
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
