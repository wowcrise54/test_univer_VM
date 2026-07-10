import { useCallback, useEffect, useMemo, useState } from "react";
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
  const [runbooks, setRunbooks] = useState([]);
  const [schedules, setSchedules] = useState([]);
  const [runs, setRuns] = useState([]);
  const [notifications, setNotifications] = useState({ rows: [], unread: 0 });
  const [templates, setTemplates] = useState([]);
  const [scannerTasks, setScannerTasks] = useState([]);
  const [fieldCatalog, setFieldCatalog] = useState([]);
  const [busy, setBusy] = useState(false);
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

  const load = useCallback(async () => {
    const [
      runbookData,
      scheduleData,
      runData,
      notificationData,
      templateData,
      scannerTaskData,
      fieldData,
    ] = await Promise.all([
      api("/api/automations/runbooks"),
      api("/api/automations/schedules"),
      api("/api/automations/runs"),
      api("/api/notifications"),
      api("/api/automations/templates"),
      api("/api/scanner-tasks").catch(() => []),
      api("/api/asset-card-query/fields?limit=500").catch(() => ({ rows: [] })),
    ]);
    setRunbooks(runbookData.rows || []);
    setSchedules(scheduleData.rows || []);
    setRuns(runData.rows || []);
    setNotifications(notificationData);
    setTemplates(templateData.rows || []);
    setScannerTasks(
      Array.isArray(scannerTaskData)
        ? scannerTaskData
        : scannerTaskData.rows || [],
    );
    setFieldCatalog(fieldData.rows || []);
  }, []);

  useEffect(() => {
    load().catch((error) => showAlert(error.message, "error"));
  }, [load, showAlert]);

  const perform = async (action, success) => {
    setBusy(true);
    try {
      await action();
      await load();
      if (success) showAlert(success, "success");
      return true;
    } catch (error) {
      showAlert(error.message, "error");
      return false;
    } finally {
      setBusy(false);
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

  const publishedRunbooks = useMemo(
    () => runbooks.filter((item) => item.published_version),
    [runbooks],
  );

  return (
    <>
      <div className="automation-tabs">
        {[
          ["runbooks", "Сценарии"],
          ["schedules", "Расписания"],
          ["runs", "Запуски"],
          ["notifications", `Уведомления · ${notifications.unread || 0}`],
        ].map(([id, label]) => (
          <button
            key={id}
            className={tab === id ? "is-active" : ""}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "runbooks" && (
        <>
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
              <Button busy={busy} onClick={save}>
                {editingId ? "Сохранить" : "Создать"}
              </Button>
              {editingId && (
                <Button variant="ghost" onClick={resetForm}>
                  Отмена
                </Button>
              )}
            </div>
            <div className="automation-templates">
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
                  {runbooks.map((item) => (
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
                          <Button variant="tiny" onClick={() => publish(item)}>
                            Опубликовать
                          </Button>
                          <Button
                            variant="tiny"
                            disabled={!item.published_version}
                            onClick={() => startRun(item, true)}
                          >
                            Проверить
                          </Button>
                          <Button
                            variant="tiny"
                            disabled={!item.published_version}
                            onClick={() => startRun(item, false)}
                          >
                            Запустить
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {!runbooks.length && (
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
        </>
      )}

      {tab === "schedules" && (
        <Panel
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
              busy={busy}
              onClick={() =>
                perform(
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
                {schedules.map((item) => (
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
                            perform(() =>
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
                          onClick={() =>
                            perform(
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
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {tab === "runs" && (
        <>
          <Panel
            title="История запусков"
            action={
              <Button variant="secondary" onClick={load}>
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
                  {runs.map((item) => (
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
                            onClick={() =>
                              api(`/api/automations/runs/${item.run_id}`)
                                .then(setSelectedRun)
                                .catch((error) =>
                                  showAlert(error.message, "error"),
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
                  ))}
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
        </>
      )}

      {tab === "notifications" && (
        <Panel
          title="Центр уведомлений"
          description={`Непрочитанных: ${notifications.unread || 0}`}
        >
          <div className="automation-notifications">
            {notifications.rows.map((item) => (
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
                      perform(() =>
                        api(`/api/notifications/${item.notification_id}/read`, {
                          method: "POST",
                        }),
                      )
                    }
                  >
                    Прочитано
                  </Button>
                )}
              </article>
            ))}
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
        busy={busy}
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
