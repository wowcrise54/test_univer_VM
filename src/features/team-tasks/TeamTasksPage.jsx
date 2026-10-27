import { useId, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, createIdempotencyKey } from "../../api/client.js";
import {
  Button,
  ConfirmDialog,
  Field,
  Panel,
  useDialogAccessibility,
} from "../../shared/ui.jsx";
import { OS_LABELS } from "../task-presets/presetForm.js";

const ACTIVE_POSTPROCESS = new Set([
  "monitoring",
  "resolving",
  "processing",
  "waiting",
  "cancelling",
]);

const STATUS_LABELS = {
  created: "Создана",
  updated: "Изменена",
  preset_synced: "Готовится к запуску",
  updated_before_start: "Готовится к запуску",
  valid: "Проверена",
  started: "Запущена",
  stop_requested: "Остановка",
  validation_failed: "Ошибка проверки",
  precheck_failed: "Хосты недоступны",
  precheck_updated_targets: "Precheck пройден",
};

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
  return STATUS_LABELS[status] || status || "—";
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
  const [osFilter, setOsFilter] = useState("");

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

  const refreshTasks = () =>
    queryClient.invalidateQueries({ queryKey: ["team-tasks"] });

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
        title="Сканирование по пресетам"
        description="Выберите пресет и группы активов. Профиль, учётная запись и остальные параметры уже настроены администратором."
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
                  <dt>Группы</dt>
                  <dd>{(preset.allowed_asset_groups || []).length}</dd>
                </div>
                <div>
                  <dt>В задаче</dt>
                  <dd>до {preset.max_groups_per_task}</dd>
                </div>
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
                ? "Пресетов пока нет. Создайте их в разделе «Пресеты задач»."
                : "Для вашей роли пока нет пресетов. Обратитесь к администратору."}
            </p>
          ) : null}
        </div>
      </Panel>

      <Panel
        title="Задачи команды"
        description="Задачи, созданные по пресетам вашей команды."
        action={
          <Button
            variant="secondary"
            busy={tasksQuery.isFetching}
            onClick={() => tasksQuery.refetch()}
          >
            Обновить
          </Button>
        }
      >
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
                <th scope="col">Группы</th>
                <th scope="col">Автор</th>
                <th scope="col">Состояние</th>
                <th scope="col">
                  <span className="team-sr-only">Действия</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {tasks.map((task) => {
                const running = isTeamTaskRunning(task);
                const busy = pendingTaskId === task.mp_task_id;
                return (
                  <TeamTaskRow
                    key={task.mp_task_id}
                    task={task}
                    running={running}
                    busy={busy}
                    historyOpen={historyTaskId === task.mp_task_id}
                    onStart={() =>
                      actionMutation.mutate({ task, action: "start" })
                    }
                    onStop={() =>
                      actionMutation.mutate({ task, action: "stop" })
                    }
                    onDelete={() => setDeleteTarget(task)}
                    onToggleHistory={() =>
                      setHistoryTaskId((current) =>
                        current === task.mp_task_id ? null : task.mp_task_id,
                      )
                    }
                  />
                );
              })}
              {!tasksQuery.isLoading && !tasks.length ? (
                <tr>
                  <td colSpan={6} className="empty-cell">
                    Задач команды пока нет.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </Panel>

      {createPreset ? (
        <CreateTeamTaskDialog
          preset={createPreset}
          showAlert={showAlert}
          onClose={() => setCreatePreset(null)}
          onCreated={async () => {
            setCreatePreset(null);
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
  running,
  busy,
  historyOpen,
  onStart,
  onStop,
  onDelete,
  onToggleHistory,
}) {
  const groups = task.preset_asset_groups || [];
  const targets = task.preset_targets || [];
  const scope = [...groups.map((group) => group.name || group.id), ...targets];
  return (
    <>
      <tr>
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
          <span className={`task-status ${running ? "is-running" : ""}`}>
            <i aria-hidden="true" />
            {teamTaskStatus(task)}
          </span>
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
            <Button
              variant="tiny"
              aria-expanded={historyOpen}
              onClick={onToggleHistory}
            >
              История
            </Button>
            <Button
              variant="tiny"
              disabled={busy || running}
              onClick={onDelete}
            >
              Удалить
            </Button>
          </div>
        </td>
      </tr>
      {historyOpen ? (
        <tr className="team-history-row">
          <td colSpan={6}>
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
          <strong>{run.status || run.state || "—"}</strong>
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
  const [selected, setSelected] = useState([]);
  const [targetsText, setTargetsText] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [search, setSearch] = useState("");
  const [idempotencyKey, setIdempotencyKey] = useState(() =>
    createIdempotencyKey("team-task"),
  );
  const limit = Number(preset.max_groups_per_task || 1);

  const createMutation = useMutation({
    mutationFn: (startNow) =>
      api("/api/team-tasks", {
        method: "POST",
        headers: {
          "X-Idempotency-Key": `${idempotencyKey}:${startNow ? "run" : "save"}`,
        },
        body: JSON.stringify({
          preset_id: preset.preset_id,
          asset_group_ids: selected,
          targets,
          name: name.trim() || null,
          description: description.trim() || null,
          start_now: startNow,
        }),
      }),
    onSuccess: async (result, startNow) => {
      const started = result?.start?.status === "started";
      if (!startNow) {
        showAlert(`Задача «${result.task.name}» создана.`, "success");
      } else if (started) {
        showAlert(
          `Задача «${result.task.name}» создана и запущена.`,
          "success",
        );
      } else {
        showAlert(
          `Задача «${result.task.name}» создана, но не запущена: ${result?.start?.error || result?.start?.status || "см. статус"}.`,
          "warning",
        );
      }
      await onCreated();
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

  const query = search.trim().toLocaleLowerCase("ru-RU");
  const groups = (preset.allowed_asset_groups || []).filter(
    (group) =>
      !query ||
      String(group.path || group.name || group.id)
        .toLocaleLowerCase("ru-RU")
        .includes(query),
  );
  const toggle = (id) =>
    setSelected((current) =>
      current.includes(id)
        ? current.filter((value) => value !== id)
        : [...current, id],
    );
  const targets = parseTargets(targetsText);
  const overLimit = selected.length > limit;
  const blocked = (!selected.length && !targets.length) || overLimit;

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
        <span className="confirm-dialog__eyebrow">
          {OS_LABELS[preset.os_family] || preset.os_family} · пресет
        </span>
        <h2 id={titleId}>{preset.name}</h2>
        {preset.description ? <p>{preset.description}</p> : null}
        <fieldset className="preset-fieldset">
          <legend>
            Группы активов · выбрано {selected.length} из {limit} возможных
          </legend>
          <input
            type="search"
            value={search}
            placeholder="Поиск группы"
            aria-label="Поиск группы активов"
            onChange={(event) => setSearch(event.target.value)}
          />
          <div className="preset-group-list">
            {groups.map((group) => (
              <label className="toggle" key={group.id}>
                <input
                  type="checkbox"
                  checked={selected.includes(group.id)}
                  onChange={() => toggle(group.id)}
                />
                <span>{group.path || group.name || group.id}</span>
              </label>
            ))}
            {!groups.length ? (
              <p className="preset-muted">Группы не найдены.</p>
            ) : null}
          </div>
          {overLimit ? (
            <p className="preset-error" role="alert">
              Пресет разрешает не больше {limit} групп в одной задаче.
            </p>
          ) : null}
        </fieldset>
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
            IP-адрес, подсеть (CIDR), диапазон (10.0.2.1-10.0.2.50) или FQDN —
            по одному в строке или через запятую. Можно вместе с группами или
            без них.
          </small>
        </fieldset>
        <Field label="Название (необязательно)">
          <input
            value={name}
            maxLength={160}
            placeholder="По умолчанию — группы, адреса и дата"
            onChange={(event) => setName(event.target.value)}
          />
        </Field>
        <Field label="Комментарий (необязательно)">
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
