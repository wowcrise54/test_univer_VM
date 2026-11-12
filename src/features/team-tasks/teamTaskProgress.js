import { useQueries } from "@tanstack/react-query";
import { api } from "../../api/client.js";
import { connectionChecks, displayText } from "../tasks/taskFormat.jsx";

const ACTIVE_RUN = new Set([
  "inprogress",
  "running",
  "started",
  "assigned",
  "scheduled",
  "pending",
  "queued",
]);
const FAILED_RUN = new Set(["failed", "error", "completedwitherrors"]);
const FINISHED_RUN = new Set([
  "finished",
  "completed",
  "failed",
  "error",
  "completedwitherrors",
  "stopped",
  "suspended",
  "cancelled",
  "canceled",
]);
const NORMAL_RESULT = new Set([
  "",
  "none",
  "noerror",
  "noerrors",
  "withouterrors",
  "ok",
  "success",
  "green",
  "succeeded",
  "successful",
]);
const ACTIVE_REFRESH_MS = 5000;
const IDLE_REFRESH_MS = 30000;
const NO_PROGRESS_MS = 15 * 60 * 1000;

function normalize(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
}

export function remoteStatus(run) {
  return normalize(displayText(run?.status || run?.state));
}

function remoteFinished(run) {
  const status = remoteStatus(run);
  return (
    !ACTIVE_RUN.has(status) &&
    Boolean(FINISHED_RUN.has(status) || run?.finishedAt || run?.finished_at)
  );
}

function hasErrors(result) {
  if (Array.isArray(result)) return result.some(hasErrors);
  if (result && typeof result === "object")
    return Object.values(result).some(hasErrors);
  return !NORMAL_RESULT.has(normalize(result));
}

function summarizeJobs(jobs) {
  let total = 0;
  let finished = 0;
  let failed = 0;
  let connectionFailures = 0;
  for (const job of jobs) {
    const failedChecks = connectionChecks(job).filter(
      (check) =>
        FAILED_RUN.has(remoteStatus(check)) || Boolean(check.errors?.length),
    );
    connectionFailures += failedChecks.length;
    if (normalize(job.runMode).includes("connectioncheck")) {
      if (
        !failedChecks.length &&
        remoteFinished(job) &&
        hasErrors(job.errorStatus)
      ) {
        connectionFailures += 1;
      }
      continue;
    }
    total += 1;
    if (!remoteFinished(job)) continue;
    finished += 1;
    if (FAILED_RUN.has(remoteStatus(job)) || hasErrors(job.errorStatus))
      failed += 1;
  }
  return { total, finished, failed, connectionFailures };
}

export function useTeamTaskProgress(tasks, isLocalRunning, localCheckedAt) {
  const runs = useQueries({
    queries: tasks.map((task) => ({
      queryKey: ["team-task-latest", task.mp_task_id],
      queryFn: ({ signal }) =>
        api(
          `/api/team-tasks/${encodeURIComponent(task.mp_task_id)}/runs?limit=1`,
          { signal },
        ),
      refetchInterval: (query) =>
        isLocalRunning(task) ||
        ACTIVE_RUN.has(remoteStatus(query.state.data?.items?.[0]))
          ? ACTIVE_REFRESH_MS
          : IDLE_REFRESH_MS,
      retry: false,
    })),
  });
  const jobs = useQueries({
    queries: tasks.map((task, index) => {
      const run = runs[index].data?.items?.[0];
      const finished = remoteFinished(run);
      return {
        queryKey: [
          "team-task-progress-jobs",
          task.mp_task_id,
          run?.id,
          finished,
        ],
        queryFn: async ({ signal }) => {
          const result = await api(
            `/api/team-tasks/${encodeURIComponent(task.mp_task_id)}/runs/${encodeURIComponent(run.id)}/jobs`,
            { signal },
          );
          return summarizeJobs(result.items || []);
        },
        enabled: Boolean(run?.id) && !runs[index].isError,
        refetchInterval: (query) =>
          finished
            ? query.state.status === "error"
              ? IDLE_REFRESH_MS
              : false
            : ACTIVE_REFRESH_MS,
        staleTime: finished ? Infinity : 0,
        retry: false,
      };
    }),
  });

  return tasks.map((task, index) => {
    const runQuery = runs[index];
    const jobQuery = jobs[index];
    const run = runQuery.data?.items?.[0];
    const local = task.postprocess;
    const localRunning = isLocalRunning(task);
    const postprocess =
      !run || (local?.mp_run_id && String(local.mp_run_id) === String(run.id))
        ? local
        : null;
    const scanActive = ACTIVE_RUN.has(remoteStatus(run));
    const active = localRunning || scanActive;
    const counts = jobQuery.data;
    const reasons = [];
    if (runQuery.isError) reasons.push("Не удалось обновить запуск MP VM");
    if (jobQuery.isError) reasons.push("Не удалось загрузить задания MP VM");
    if (
      remoteFinished(run) &&
      (FAILED_RUN.has(remoteStatus(run)) || hasErrors(run?.errorStatus))
    )
      reasons.push("Сканирование завершилось с ошибкой");
    if (counts?.failed) reasons.push(`Ошибки сканирования · ${counts.failed}`);
    if (counts?.connectionFailures)
      reasons.push(`Ошибки подключения · ${counts.connectionFailures}`);
    if (["completed_with_errors", "failed"].includes(postprocess?.status))
      reasons.push("Ошибка обработки результатов");
    if (
      task.status === "precheck_failed" &&
      !active &&
      (!run ||
        Date.parse(task.updated_at) >=
          Date.parse(run.finishedAt || run.startedAt))
    )
      reasons.push("Проверка подключения не пройдена");
    if (
      localRunning &&
      Math.max(
        localCheckedAt,
        runQuery.dataUpdatedAt,
        runQuery.errorUpdatedAt,
      ) -
        Date.parse(local?.updated_at) >=
        NO_PROGRESS_MS
    )
      reasons.push("Нет обновлений постобработки 15 минут");
    return {
      task,
      run,
      postprocess,
      counts,
      scanActive,
      active,
      reasons,
      loading: runQuery.isPending,
      updatedAt: runQuery.dataUpdatedAt,
      completed:
        !active &&
        (run ? remoteFinished(run) : postprocess?.status === "completed"),
    };
  });
}
