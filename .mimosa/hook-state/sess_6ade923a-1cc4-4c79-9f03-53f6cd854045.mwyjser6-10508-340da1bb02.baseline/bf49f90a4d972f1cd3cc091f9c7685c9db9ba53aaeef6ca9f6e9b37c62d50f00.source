import { useId, useState } from "react";
import { createPortal } from "react-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client.js";
import { Button, useDialogAccessibility } from "../../shared/ui.jsx";
import {
  StatusBadge,
  connectionChecks,
  displayTargets,
  displayText,
  formatCheckErrors,
  formatDate,
  formatDuration,
  objectRecords,
  taskStatusLabel,
} from "../tasks/taskFormat.jsx";

const RUNS_PAGE = 20;
const MAX_RUNS = 100;
const LIVE_REFRESH_MS = 5000;

function errorText(error) {
  return error?.message || "Не удалось загрузить данные.";
}

/**
 * Run history and per-target progress of a team task: the same view the main
 * task workspace opens for a task, backed by the RBAC-scoped team endpoints.
 */
export function TeamTaskDetails({ task, running, onClose }) {
  const titleId = useId();
  const dialogRef = useDialogAccessibility(true, onClose);
  const taskId = task.mp_task_id;
  const [limit, setLimit] = useState(RUNS_PAGE);
  const [pickedRunId, setPickedRunId] = useState(null);

  const runsQuery = useQuery({
    queryKey: ["team-task-details-runs", taskId, limit],
    queryFn: () =>
      api(`/api/team-tasks/${encodeURIComponent(taskId)}/runs?limit=${limit}`),
    refetchInterval: running ? LIVE_REFRESH_MS : false,
  });
  const runs = objectRecords(runsQuery.data?.items);
  const runId = pickedRunId || runs[0]?.id || null;

  const jobsQuery = useQuery({
    queryKey: ["team-task-details-jobs", taskId, runId],
    queryFn: () =>
      api(
        `/api/team-tasks/${encodeURIComponent(taskId)}/runs/${encodeURIComponent(runId)}/jobs`,
      ),
    enabled: Boolean(runId),
    refetchInterval: running ? LIVE_REFRESH_MS : false,
  });
  const jobs = objectRecords(jobsQuery.data?.items);
  const checks = jobs.flatMap((job) => connectionChecks(job));
  const groups = (task.preset_asset_groups || []).map(
    (group) => group.name || group.id,
  );
  const scope = [...groups, ...(task.preset_targets || [])].join(", ");

  const dialog = (
    <div
      className="confirm-overlay"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        ref={dialogRef}
        className="confirm-dialog team-details-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <h2 id={titleId}>{task.name}</h2>
        <p className="preset-muted">
          {task.preset_name} · {scope || "цели не указаны"}
        </p>

        <div className="team-details-grid">
          <section aria-labelledby={`${titleId}-runs`}>
            <h3 id={`${titleId}-runs`}>Запуски</h3>
            {runsQuery.isLoading ? <p role="status">Загружаем историю…</p> : null}
            {runsQuery.error ? (
              <p className="preset-error" role="alert">
                {errorText(runsQuery.error)}
              </p>
            ) : null}
            {!runsQuery.isLoading && !runsQuery.error && !runs.length ? (
              <p className="preset-muted">У задачи пока нет запусков.</p>
            ) : null}
            <div className="task-runs-list">
              {runs.map((run, index) => (
                <button
                  type="button"
                  key={run.id || index}
                  aria-pressed={runId === run.id}
                  className={`task-run-item ${runId === run.id ? "is-active" : ""}`}
                  title={displayText(run.id)}
                  onClick={() => setPickedRunId(run.id)}
                >
                  <span className="task-run-item__status">
                    {run.status
                      ? taskStatusLabel(displayText(run.status))
                      : "Запуск"}
                  </span>
                  <strong>{formatDate(run.startedAt || run.createdAt)}</strong>
                  <small>
                    {displayText(run.initiator) ||
                      displayText(run.startedBy) ||
                      "Запуск MP VM"}
                  </small>
                </button>
              ))}
              {runs.length >= limit && limit < MAX_RUNS ? (
                <Button
                  variant="secondary"
                  busy={runsQuery.isFetching}
                  onClick={() => setLimit((value) => value + RUNS_PAGE)}
                >
                  Показать ещё
                </Button>
              ) : null}
            </div>
          </section>

          <section aria-labelledby={`${titleId}-jobs`}>
            <h3 id={`${titleId}-jobs`}>Ход выполнения</h3>
            <p className="preset-muted">{jobs.length} целей</p>
            {jobsQuery.isLoading ? (
              <p role="status">Загружаем задания…</p>
            ) : null}
            {jobsQuery.error ? (
              <p className="preset-error" role="alert">
                {errorText(jobsQuery.error)}
              </p>
            ) : null}
            {!runId ? (
              <p className="preset-muted">Выберите запуск.</p>
            ) : !jobsQuery.isLoading && !jobsQuery.error && !jobs.length ? (
              <p className="preset-muted">Нет заданий.</p>
            ) : null}
            {jobs.length ? (
              <div className="task-jobs-table-wrap">
                <table className="task-jobs-table">
                  <thead>
                    <tr>
                      <th>Статус</th>
                      <th>Начало</th>
                      <th>Окончание</th>
                      <th>Длительность</th>
                      <th>Коллектор</th>
                      <th>Цель</th>
                      <th>Профиль</th>
                    </tr>
                  </thead>
                  <tbody>
                    {jobs.map((job, index) => (
                      <tr key={job.id || index}>
                        <td>
                          <StatusBadge
                            status={job.status}
                            result={job.errorStatus}
                          />
                        </td>
                        <td>{formatDate(job.startedAt)}</td>
                        <td>{formatDate(job.finishedAt)}</td>
                        <td>{formatDuration(job.startedAt, job.finishedAt)}</td>
                        <td>
                          {displayText(job.agent) ||
                            displayText(job.collector) ||
                            "—"}
                        </td>
                        <td>
                          {displayTargets(job.targets) ||
                            displayText(job.target) ||
                            "—"}
                        </td>
                        <td>{displayText(job.profile) || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}
            {checks.length ? (
              <div className="task-connection-checks">
                <h4>Проверки соединения</h4>
                {checks.map((check, index) => (
                  <p key={index}>
                    <strong>
                      {typeof check.transport === "string"
                        ? check.transport
                        : "Проверка"}
                      :
                    </strong>{" "}
                    {typeof check.status === "string"
                      ? check.status
                      : "неизвестно"}
                    {formatCheckErrors(check.errors)}
                  </p>
                ))}
              </div>
            ) : null}
          </section>
        </div>

        <div className="confirm-dialog__actions">
          <Button variant="secondary" onClick={onClose}>
            Закрыть
          </Button>
        </div>
      </section>
    </div>
  );
  return typeof document === "undefined"
    ? dialog
    : createPortal(dialog, document.body);
}
