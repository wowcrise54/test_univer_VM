import { formatCount } from "../../shared/format.js";
import {
  SortableHeader,
  useSortedRows,
  useTableSort,
} from "../../shared/table.jsx";

export function TaskPostprocessPanel({ run }) {
  const items = Array.isArray(run.items) ? run.items : [];
  const [tableSort, toggleTableSort] = useTableSort();
  const sortedItems = useSortedRows(items, tableSort);
  return (
    <section className="task-postprocess" aria-live="polite">
      <div className="task-postprocess__header">
        <div>
          <span className="eyebrow">Фоновая обработка</span>
          <h3>{postprocessStageLabel(run.stage)}</h3>
          {run.message || run.error ? <p>{run.message || run.error}</p> : null}
          {run.error ? (
            <p className="error-text">Исходная причина: {run.error}</p>
          ) : null}
        </div>
        <div className="task-postprocess__metrics">
          <span>
            Задания{" "}
            <strong>
              {formatCount(run.successful_job_count)} /{" "}
              {formatCount(run.total_job_count)}
            </strong>
          </span>
          <span>
            Активы{" "}
            <strong>
              {formatCount(run.completed_count)} /{" "}
              {formatCount(run.asset_count)}
            </strong>
          </span>
          <span>
            Ошибки <strong>{formatCount(run.failed_count)}</strong>
          </span>
        </div>
      </div>
      {items.length ? (
        <div className="mpvm-table-shell">
          <table className="postprocess-item-table">
            <thead>
              <tr>
                <SortableHeader
                  column="target"
                  sort={tableSort}
                  onSort={toggleTableSort}
                >
                  Цель
                </SortableHeader>
                <SortableHeader
                  column="asset_id"
                  sort={tableSort}
                  onSort={toggleTableSort}
                >
                  ID актива
                </SortableHeader>
                <SortableHeader
                  column="mp_job_id"
                  sort={tableSort}
                  onSort={toggleTableSort}
                >
                  Задание
                </SortableHeader>
                <SortableHeader
                  column="build_job_id"
                  sort={tableSort}
                  onSort={toggleTableSort}
                >
                  Карточка
                </SortableHeader>
                <SortableHeader
                  column="removal_operation_id"
                  sort={tableSort}
                  onSort={toggleTableSort}
                >
                  Удаление MP VM
                </SortableHeader>
                <SortableHeader
                  column="status"
                  sort={tableSort}
                  onSort={toggleTableSort}
                >
                  Статус / ошибка
                </SortableHeader>
              </tr>
            </thead>
            <tbody>
              {sortedItems.map((item) => (
                <tr key={item.id || item.item_key}>
                  <td>{item.target || "—"}</td>
                  <td className="mono-cell">{item.asset_id || "—"}</td>
                  <td className="mono-cell">{item.mp_job_id || "—"}</td>
                  <td className="mono-cell">
                    {item.build_job_id || postprocessCardLabel(item.status)}
                  </td>
                  <td className="mono-cell">
                    {item.removal_operation_id ||
                      postprocessRemovalLabel(item.status)}
                  </td>
                  <td>
                    <TaskStatus status={item.status} />
                    {item.error ? (
                      <small className="error-text">{item.error}</small>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-cell">
          Ожидаем завершения сканирования и появления успешных устройств.
        </div>
      )}
    </section>
  );
}

function taskStatusLabel(status) {
  return (
    {
      pending: "Ожидает",
      building: "Сборка карточки",
      card_saved: "Карточка сохранена",
      asset_refresh_created: "Обновление карточки запущено",
      deleted: "Удалён из MP VM",
      removal_failed: "Ошибка удаления",
      queued: "В очереди",
      running: "Выполняется",
      started: "Запущена",
      finished: "Завершена",
      failed: "Ошибка",
      timeout: "Истекло время",
    }[String(status).toLowerCase()] || postprocessStageLabel(status)
  );
}

function postprocessStageLabel(stage) {
  const labels = {
    waiting_for_run: "Ожидание запуска MP VM",
    scanning: "Сканирование выполняется",
    watching_jobs: "Ожидание заданий сканирования",
    scan_finished: "Сканирование завершено",
    scanner_start_failed: "Не удалось подтвердить запуск сканирования",
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

function TaskStatus({ status }) {
  const normalized = String(status || "").toLowerCase();
  let kind = "neutral";
  let icon = "•";
  if (
    [
      "started",
      "precheck_started",
      "monitoring",
      "resolving",
      "processing",
      "building",
      "deleting",
      "queued",
      "waiting",
    ].some((item) => normalized.includes(item))
  ) {
    kind = "running";
    icon = "◔";
  } else if (normalized.includes("with_errors")) {
    kind = "danger";
    icon = "⚠";
  } else if (
    ["finished", "valid", "created", "updated", "completed", "card_saved"].some(
      (item) => normalized.includes(item),
    )
  ) {
    kind = "success";
    icon = "✓";
  } else if (
    ["failed", "timeout", "stop", "deleted"].some((item) =>
      normalized.includes(item),
    )
  ) {
    kind = "danger";
    icon = "⚠";
  }
  return (
    <span className={`task-status task-status--${kind}`}>
      <span>{icon}</span>
      {status ? taskStatusLabel(status) : "Неизвестно"}
    </span>
  );
}
