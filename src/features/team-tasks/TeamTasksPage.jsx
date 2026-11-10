import { useId, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, createIdempotencyKey } from "../../api/client.js";
import {
  ActionMenu,
  Button,
  ConfirmDialog,
  Field,
  Panel,
  useDialogAccessibility,
} from "../../shared/ui.jsx";
import { taskStatusLabel } from "../../shared/labels.js";
import { OS_LABELS } from "../task-presets/presetForm.js";
import { displayText } from "../tasks/taskFormat.jsx";
import { TeamTaskDetails } from "./TeamTaskDetails.jsx";
import { remoteStatus, useTeamTaskProgress } from "./teamTaskProgress.js";

const ACTIVE_POSTPROCESS = new Set([
  "monitoring",
  "resolving",
  "processing",
  "waiting",
  "cancelling",
]);

// A task that was just started is "Запущена" here; the shared label says "Выполняется".
const STATUS_LABELS = { started: "Запущена" };

function runStatusLabel(value) {
  value = displayText(value);
  if (!value) return "—";
  return (
    {
      finished: "Завершён",
      completed: "Завершён",
      running: "Выполняется",
      inprogress: "Выполняется",
      started: "Выполняется",
      queued: "В очереди",
      pending: "В очереди",
      assigned: "Назначен",
      scheduled: "Запланирован",
      stopped: "Остановлен",
      suspended: "Приостановлен",
      cancelled: "Остановлен",
      canceled: "Остановлен",
      failed: "Ошибка",
      error: "Ошибка",
      completedwitherrors: "Завершён с ошибками",
    }[remoteStatus({ status: value })] || value
  );
}

const POSTPROCESS_LABELS = {
  monitoring: "Сканирование идёт",
  resolving: "Сопоставление результатов",
  processing: "Обработка результатов",
  waiting: "Ожидание",
  cancelling: "Остановка",
  completed: "Завершено",
  completed_with_errors: "Завершено с ошибками",
  failed: "Ошибка",
  cancelled: "Остановлено",
};

export function isTeamTaskRunning(task) {
  return ACTIVE_POSTPROCESS.has(String(task?.postprocess?.status || ""));
}

export function teamTaskStatus(task) {
  const postprocess = String(task?.postprocess?.status || "");
  if (postprocess && POSTPROCESS_LABELS[postprocess]) {
    return POSTPROCESS_LABELS[postprocess];
  }
  const status = String(task?.status || "");
  return status ? taskStatusLabel(status, STATUS_LABELS) : "—";
}

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

function errorText(error) {
  return error?.operatorMessage || error?.message || String(error || "");
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? String(value)
    : new Intl.DateTimeFormat("ru-RU", {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date);
}

export function TeamTasksPage({ currentUser, showAlert }) {
  const queryClient = useQueryClient();
  const canManagePresets = new Set(currentUser?.permissions || []).has(
    "task_presets.manage",
  );
  const [createPreset, setCreatePreset] = useState(null);
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [historyTaskId, setHistoryTaskId] = useState(null);
  const [details, setDetails] = useState(null);
  const [osFilter, setOsFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  const presetsQuery = useQuery({
    queryKey: ["task-presets", { archived: false }],
    queryFn: () => api("/api/task-presets"),
  });
  const tasksQuery = useQuery({
    queryKey: ["team-tasks"],
    queryFn: () => api("/api/team-tasks"),
    refetchInterval: (query) =>
      (query.state.data?.rows || []).some(isTeamTaskRunning) ? 5000 : 30000,
  });
  const presets = useMemo(
    () =>
      (presetsQuery.data?.rows || []).filter(
        (preset) => !osFilter || preset.os_family === osFilter,
      ),
    [presetsQuery.data, osFilter],
  );
  const tasks = (tasksQuery.data?.rows || []).filter(
    (task) => !osFilter || task.os_family === osFilter,
  );
  const progressRows = useTeamTaskProgress(
    tasks,
    isTeamTaskRunning,
    tasksQuery.dataUpdatedAt,
  );
  const visibleRows = progressRows.filter((progress) => {
    if (statusFilter === "active") return progress.active;
    if (statusFilter === "attention") return progress.reasons.length > 0;
    if (statusFilter === "completed") return progress.completed;
    return true;
  });

  const detailsRow = progressRows.find(
    ({ task }) => task.mp_task_id === details?.taskId,
  );

  const refreshTasks = () =>
    queryClient.invalidateQueries({
      predicate: ({ queryKey }) =>
        ["team-tasks", "team-task-latest", "team-task-progress-jobs"].includes(
          queryKey[0],
        ),
    });

  const actionMutation = useMutation({
    mutationFn: ({ task, action }) =>
      api(`/api/team-tasks/${encodeURIComponent(task.mp_task_id)}/${action}`, {
        method: "POST",
        headers:
          action === "stop"
            ? undefined
            : {
                "X-Idempotency-Key": createIdempotencyKey(
                  `team-task-${action}`,
                ),
              },
      }),
    onSuccess: async (result, { task, action }) => {
      if (action === "start") {
        const started = result?.status === "started";
        showAlert(
          started
            ? `Задача «${task.name}» запущена.`
            : `Задача «${task.name}» не запущена: ${result?.error || result?.status || "см. статус"}.`,
          started ? "success" : "warning",
        );
      } else if (action === "stop") {
        showAlert(`Запрошена остановка задачи «${task.name}».`, "info");
      } else {
        showAlert(`Задача «${task.name}» удалена.`, "success");
        setDeleteTarget(null);
      }
      await refreshTasks();
    },
    onError: (error) => showAlert(errorText(error), "error"),
  });
  const pendingTaskId = actionMutation.isPending
    ? actionMutation.variables?.task?.mp_task_id
    : null;

  return (
    <div className="team-tasks-page">
      <Panel
        title="Пресеты"
        action={
          <Field label="ОС">
            <select
              value={osFilter}
              onChange={(event) => setOsFilter(event.target.value)}
            >
              <option value="">Все</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
            </select>
          </Field>
        }
      >
        {presetsQuery.error ? (
          <p className="preset-error" role="alert">
            {errorText(presetsQuery.error)}
          </p>
        ) : null}
        <div className="team-preset-grid">
          {presets.map((preset) => (
            <article className="team-preset-card" key={preset.preset_id}>
              <span
                className={`team-os-badge team-os-badge--${preset.os_family}`}
              >
                {OS_LABELS[preset.os_family] || preset.os_family}
              </span>
              <h3>{preset.name}</h3>
              {preset.description ? <p>{preset.description}</p> : null}
              <dl>
                <div>
                  <dt>Запуск</dt>
                  <dd>
                    {preset.trigger_parameters ? "По расписанию" : "Разовый"}
                  </dd>
                </div>
              </dl>
              <Button onClick={() => setCreatePreset(preset)}>
                Создать задачу
              </Button>
            </article>
          ))}
          {!presetsQuery.isLoading && !presets.length ? (
            <p className="empty-cell">
              {canManagePresets
                ? "Пресетов нет. Создайте их в разделе «Пресеты задач»."
                : "Для вашей роли пресетов нет — обратитесь к администратору."}
            </p>
          ) : null}
        </div>
      </Panel>

      <Panel
        title="Задачи команды"
        action={
          <Button
            variant="secondary"
            busy={tasksQuery.isFetching}
            onClick={refreshTasks}
          >
            Обновить
          </Button>
        }
      >
        <Field label="Статус задач">
          <select
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
          >
            <option value="">Все</option>
            <option value="active">В работе</option>
            <option value="attention">Требуют внимания</option>
            <option value="completed">Завершены</option>
          </select>
        </Field>
        {tasksQuery.error ? (
          <p className="preset-error" role="alert">
            {errorText(tasksQuery.error)}
          </p>
        ) : null}
        <div className="table-shell team-table-scroll">
          <table>
            <thead>
              <tr>
                <th scope="col">Задача</th>
                <th scope="col">Пресет</th>
                <th scope="col">Цели</th>
                <th scope="col">Автор</th>
                <th scope="col">Сканирование</th>
                <th scope="col">Обработка результатов</th>
                <th scope="col">
                  <span className="team-sr-only">Действия</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {visibleRows.map((progress) => {
                const { task, active, run } = progress;
                const busy = pendingTaskId === task.mp_task_id;
                return (
                  <TeamTaskRow
                    key={task.mp_task_id}
                    task={task}
                    progress={progress}
                    running={active}
                    busy={busy}
                    historyOpen={historyTaskId === task.mp_task_id}
                    onStart={() =>
                      actionMutation.mutate({ task, action: "start" })
                    }
                    onStop={() =>
                      actionMutation.mutate({ task, action: "stop" })
                    }
                    onDelete={() => setDeleteTarget(task)}
                    onOpenDetails={() =>
                      setDetails({ taskId: task.mp_task_id, runId: run?.id })
                    }
                    onToggleHistory={() =>
                      setHistoryTaskId((current) =>
                        current === task.mp_task_id ? null : task.mp_task_id,
                      )
                    }
                  />
                );
              })}
              {!tasksQuery.isLoading && !visibleRows.length ? (
                <tr>
                  <td colSpan={7} className="empty-cell">
                    {statusFilter
                      ? "Нет задач по выбранному статусу."
                      : "Задач пока нет."}
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </Panel>

      {detailsRow ? (
        <TeamTaskDetails
          task={detailsRow.task}
          initialRunId={details.runId}
          running={detailsRow.active}
          onClose={() => setDetails(null)}
        />
      ) : null}

      {createPreset ? (
        <CreateTeamTaskDialog
          preset={createPreset}
          showAlert={showAlert}
          onClose={() => setCreatePreset(null)}
          onCreated={async (task, startNow) => {
            // Close at once; the scan itself starts in the background.
            setCreatePreset(null);
            if (startNow) actionMutation.mutate({ task, action: "start" });
            await refreshTasks();
          }}
        />
      ) : null}

      <ConfirmDialog
        open={Boolean(deleteTarget)}
        title="Удалить задачу?"
        description={`Задача «${deleteTarget?.name || ""}» будет удалена из MP VM и из списка команды.`}
        confirmLabel="Удалить"
        busy={actionMutation.isPending}
        onConfirm={() =>
          actionMutation.mutate({ task: deleteTarget, action: "delete" })
        }
        onClose={() => setDeleteTarget(null)}
      />
    </div>
  );
}

function TeamTaskRow({
  task,
  progress,
  running,
  busy,
  historyOpen,
  onStart,
  onStop,
  onDelete,
  onOpenDetails,
  onToggleHistory,
}) {
  const groups = task.preset_asset_groups || [];
  const targets = task.preset_targets || [];
  const scope = [...groups.map((group) => group.name || group.id), ...targets];
  const { run, postprocess, counts, reasons, loading, updatedAt, scanActive } =
    progress;
  return (
    <>
      <tr
        className="team-task-row"
        title="Двойной клик — ход выполнения"
        onDoubleClick={(event) => {
          if (!event.target.closest("button, a, input, select, textarea"))
            onOpenDetails();
        }}
      >
        <td>
          <strong>{task.name}</strong>
          <small className="preset-muted">
            Обновлена {formatDate(task.updated_at)}
          </small>
        </td>
        <td>
          {task.preset_name}
          {task.preset_is_active === false ? (
            <small className="preset-muted">пресет в архиве</small>
          ) : null}
        </td>
        <td
          title={[
            ...groups.map((group) => group.path || group.name),
            ...targets,
          ].join("\n")}
        >
          {scope.join(", ") || "—"}
        </td>
        <td>{task.created_by || "—"}</td>
        <td>
          <span className={`task-status ${scanActive || (!run && running) ? "is-running" : ""}`}>
            <i aria-hidden="true" />
            {run
              ? runStatusLabel(run.status || run.state)
              : teamTaskStatus(task)}
          </span>
          {counts ? (
            <small className="preset-muted">
              {`${counts.finished} из ${counts.total} заданий · ${counts.failed} с ошибкой`}
            </small>
          ) : null}
          <small className="preset-muted">
            {loading
              ? "Проверяем запуски MP VM…"
              : updatedAt
                ? `Проверено ${formatDate(updatedAt)}`
                : "Нет данных MP VM"}
          </small>
        </td>
        <td>
          {postprocess ? (
            <>
              <span>
                {postprocess.status === "monitoring"
                  ? "Ожидание результатов"
                  : POSTPROCESS_LABELS[postprocess.status] || postprocess.status}
              </span>
              {postprocess.asset_count > 0 ? (
                <small className="preset-muted">
                  Карточки обработаны {postprocess.completed_count} из{" "}
                  {postprocess.asset_count} · ошибок {postprocess.failed_count}
                </small>
              ) : null}
              {postprocess.updated_at ? (
                <small className="preset-muted">
                  Прогресс {formatDate(postprocess.updated_at)}
                </small>
              ) : null}
            </>
          ) : (
            <span>Карточки — данных по запуску нет</span>
          )}
        </td>
        <td>
          <div className="row-actions">
            {running ? (
              <Button variant="tiny" busy={busy} onClick={onStop}>
                Остановить
              </Button>
            ) : (
              <Button
                variant="tiny"
                busy={busy}
                disabled={task.preset_is_active === false}
                onClick={onStart}
              >
                Запустить
              </Button>
            )}
            <Button variant="tiny" onClick={onOpenDetails}>
              Ход выполнения
            </Button>
            <Button
              variant="tiny"
              aria-expanded={historyOpen}
              onClick={onToggleHistory}
            >
              История
            </Button>
            <ActionMenu className="row-actions__more">
              <Button
                variant="tiny"
                disabled={busy || running}
                onClick={onDelete}
              >
                Удалить
              </Button>
            </ActionMenu>
          </div>
          {reasons.length ? (
            <small className="preset-muted">{reasons.join(" · ")}</small>
          ) : null}
        </td>
      </tr>
      {historyOpen ? (
        <tr className="team-history-row">
          <td colSpan={7}>
            <TeamTaskHistory taskId={task.mp_task_id} />
          </td>
        </tr>
      ) : null}
    </>
  );
}

function TeamTaskHistory({ taskId }) {
  const runsQuery = useQuery({
    queryKey: ["team-task-runs", taskId],
    queryFn: () =>
      api(`/api/team-tasks/${encodeURIComponent(taskId)}/runs?limit=10`),
  });
  if (runsQuery.isLoading) return <p className="preset-muted">Загрузка…</p>;
  if (runsQuery.error)
    return (
      <p className="preset-error" role="alert">
        {errorText(runsQuery.error)}
      </p>
    );
  const runs = runsQuery.data?.items || [];
  if (!runs.length)
    return <p className="preset-muted">Запусков ещё не было.</p>;
  return (
    <ol className="team-runs" aria-label="Последние запуски">
      {runs.map((run, index) => (
        <li key={run.id || index}>
          <strong>{runStatusLabel(run.status || run.state)}</strong>
          <span>
            {formatDate(run.startedAt || run.started_at)} —{" "}
            {formatDate(run.finishedAt || run.finished_at)}
          </span>
        </li>
      ))}
    </ol>
  );
}

function CreateTeamTaskDialog({ preset, showAlert, onClose, onCreated }) {
  const titleId = useId();
  const [targetsText, setTargetsText] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [idempotencyKey, setIdempotencyKey] = useState(() =>
    createIdempotencyKey("team-task"),
  );

  const createMutation = useMutation({
    mutationFn: (startNow) =>
      api("/api/team-tasks", {
        method: "POST",
        headers: {
          "X-Idempotency-Key": `${idempotencyKey}:${startNow ? "run" : "save"}`,
        },
        body: JSON.stringify({
          preset_id: preset.preset_id,
          targets,
          name: name.trim() || null,
          description: description.trim() || null,
          start_now: false,
        }),
      }),
    onSuccess: async (result, startNow) => {
      showAlert(
        startNow
          ? `Задача «${result.task.name}» создана, запускаем сканирование…`
          : `Задача «${result.task.name}» создана.`,
        startNow ? "info" : "success",
      );
      await onCreated(result.task, startNow);
    },
    onError: (error) => {
      // Keep the key only when the outcome is unknown (network failure); a
      // definite rejection gets a fresh key so the engineer can retry.
      if (error?.code !== "NETWORK_UNAVAILABLE") {
        setIdempotencyKey(createIdempotencyKey("team-task"));
      }
      showAlert(errorText(error), "error");
    },
  });
  const dialogRef = useDialogAccessibility(
    true,
    createMutation.isPending ? undefined : onClose,
  );

  const targets = parseTargets(targetsText);
  const blocked = !targets.length;

  const dialog = (
    <div
      className="confirm-overlay"
      role="presentation"
      onMouseDown={(event) => {
        if (!createMutation.isPending && event.target === event.currentTarget)
          onClose();
      }}
    >
      <section
        ref={dialogRef}
        className="confirm-dialog team-create-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <h2 id={titleId}>{preset.name}</h2>
        {preset.description ? <p>{preset.description}</p> : null}
        <fieldset className="preset-fieldset">
          <legend>IP-адреса, подсети и FQDN · указано {targets.length}</legend>
          <textarea
            rows={3}
            value={targetsText}
            aria-label="IP-адреса, подсети и FQDN для сканирования"
            placeholder={"10.0.0.15\n10.0.1.0/24\nsrv01.corp.local"}
            onChange={(event) => setTargetsText(event.target.value)}
          />
          <small className="preset-muted">
            По одному в строке.
          </small>
        </fieldset>
        <Field label="Название">
          <input
            value={name}
            maxLength={160}
            placeholder="По умолчанию — группы, адреса и дата"
            onChange={(event) => setName(event.target.value)}
          />
        </Field>
        <Field label="Комментарий">
          <input
            value={description}
            maxLength={2000}
            onChange={(event) => setDescription(event.target.value)}
          />
        </Field>
        <div className="confirm-dialog__actions">
          <Button
            variant="secondary"
            disabled={createMutation.isPending}
            onClick={onClose}
          >
            Отмена
          </Button>
          <Button
            variant="secondary"
            disabled={blocked}
            busy={
              createMutation.isPending && createMutation.variables === false
            }
            onClick={() => createMutation.mutate(false)}
          >
            Создать
          </Button>
          <Button
            disabled={blocked}
            busy={createMutation.isPending && createMutation.variables === true}
            onClick={() => createMutation.mutate(true)}
          >
            Создать и запустить
          </Button>
        </div>
      </section>
    </div>
  );
  return typeof document === "undefined"
    ? dialog
    : createPortal(dialog, document.body);
}
