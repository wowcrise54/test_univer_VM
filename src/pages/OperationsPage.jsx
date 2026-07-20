import { useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { api, createIdempotencyKey } from "../api/client.js";
import { Button, Panel, useDialogAccessibility } from "../shared/ui.jsx";
import { SortableHeader, useTableSort } from "../shared/table.jsx";

const PAGE_SIZE = 50;
const ACTIVE_STATUSES = new Set([
  "queued",
  "running",
  "cancelling",
  "recovering",
]);
const ATTENTION_STATUSES = new Set([
  "failed",
  "interrupted",
  "completed_with_errors",
]);

export function OperationsPage({
  operations = [],
  total = 0,
  updatedAt,
  stale,
  loading = false,
  error = null,
  summary = null,
  refreshOperations,
  refreshOperationSummary,
  runBusy,
  busy,
  showAlert,
}) {
  const [filters, setFilters] = useState({ q: "", status: "", kind: "" });
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState(null);
  const [returnFocus, setReturnFocus] = useState(null);
  const [savedViews, setSavedViews] = useState([]);
  const [viewName, setViewName] = useState("");
  const [sort, toggleSort, setSort] = useTableSort("created_at", "desc");

  useEffect(() => {
    const timer = window.setTimeout(
      () => setDebouncedQuery(filters.q.trim()),
      300,
    );
    return () => window.clearTimeout(timer);
  }, [filters.q]);

  const request = useMemo(
    () => ({
      limit: PAGE_SIZE,
      offset,
      q: debouncedQuery,
      status: filters.status,
      kind: filters.kind,
      sort_by: sort.key,
      sort_dir: sort.direction,
    }),
    [debouncedQuery, filters.kind, filters.status, offset, sort],
  );

  useEffect(() => {
    if (!refreshOperations) return;
    Promise.resolve(refreshOperations(request)).catch((loadError) => {
      showAlert?.(
        `Не удалось обновить операции: ${loadError.message || String(loadError)}`,
        "error",
      );
    });
  }, [refreshOperations, request, showAlert]);

  useEffect(() => {
    api("/api/saved-views?route=operations")
      .then((result) => setSavedViews(result.rows || []))
      .catch((loadError) =>
        showAlert?.(
          `Не удалось загрузить сохранённые представления: ${loadError.message || String(loadError)}`,
          "error",
        ),
      );
  }, [showAlert]);

  useEffect(() => {
    const operationId = typeof window === "undefined" ? null : new URLSearchParams(window.location.search).get("operation");
    if (!operationId) return;
    api(`/api/operations/${encodeURIComponent(operationId)}`).then(setSelected).catch((loadError) =>
      showAlert?.(`Не удалось открыть операцию: ${loadError.message || String(loadError)}`, "error"));
  }, [showAlert]);

  useEffect(() => {
    if (offset && offset >= total) {
      setOffset(
        Math.max(0, Math.floor(Math.max(0, total - 1) / PAGE_SIZE) * PAGE_SIZE),
      );
    }
  }, [offset, total]);

  const selectedOperationId = selected?.operation_id;
  const selectedStatus = selected?.status;
  useEffect(() => {
    if (!selectedOperationId || !ACTIVE_STATUSES.has(selectedStatus))
      return undefined;
    let cancelled = false;
    const refreshDetail = async () => {
      try {
        const detail = await api(
          `/api/operations/${encodeURIComponent(selectedOperationId)}`,
        );
        if (!cancelled) setSelected(detail);
      } catch {
        // Keep the last valid detail visible; the global status banner reports outages.
      }
    };
    const timer = window.setInterval(refreshDetail, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [selectedOperationId, selectedStatus]);

  const refreshCurrent = () =>
    Promise.all([refreshOperations?.(request), refreshOperationSummary?.()]);

  const changeFilter = (key, value) => {
    setOffset(0);
    setFilters((current) => ({ ...current, [key]: value }));
  };

  const changeSort = (key, initialDirection) => {
    setOffset(0);
    toggleSort(key, initialDirection);
  };

  const openOperation = (operation, trigger) => {
    setReturnFocus(trigger || null);
    return runBusy(`operation:${operation.operation_id}`, async () => {
      const detail = await api(
        `/api/operations/${encodeURIComponent(operation.operation_id)}`,
      );
      setSelected(detail);
      return detail;
    });
  };

  const cancelOperation = (operation) =>
    runBusy(`operationCancel:${operation.operation_id}`, async () => {
      const result = await api(
        `/api/operations/${encodeURIComponent(operation.operation_id)}/cancel`,
        { method: "POST" },
      );
      setSelected(result);
      await refreshCurrent();
      showAlert("Запрос на остановку операции принят.", "info");
      return result;
    });

  const retryOperation = (operation) =>
    runBusy(`operationRetry:${operation.operation_id}`, async () => {
      const result = await api(
        `/api/operations/${encodeURIComponent(operation.operation_id)}/retry`,
        {
          method: "POST",
          headers: { "X-Idempotency-Key": createIdempotencyKey("retry") },
        },
      );
      setSelected(result.operation || null);
      await refreshCurrent();
      showAlert("Повтор операции поставлен в очередь.", "success");
      return result;
    });

  const saveCurrentView = () =>
    runBusy("saveOperationView", async () => {
      const name = viewName.trim();
      if (!name) throw new Error("Введите название представления.");
      const result = await api("/api/saved-views", {
        method: "POST",
        body: JSON.stringify({
          route: "operations",
          name,
          filters: { ...filters, sort },
        }),
      });
      setSavedViews((items) =>
        [...items.filter((item) => item.id !== result.id), result].sort(
          (a, b) => a.name.localeCompare(b.name),
        ),
      );
      setViewName("");
      showAlert(`Представление «${name}» сохранено.`, "success");
    });

  const applySavedView = (id) => {
    const view = savedViews.find((item) => String(item.id) === id);
    if (!view) return;
    const stored = view.filters || {};
    setOffset(0);
    setFilters({
      q: stored.q || "",
      status: stored.status || "",
      kind: stored.kind || "",
    });
    setSort({
      key: stored.sort?.key || "created_at",
      direction: stored.sort?.direction === "asc" ? "asc" : "desc",
    });
  };

  const globalTotal = summary?.total ?? total;
  const globalActive =
    summary?.active ??
    operations.filter((item) => ACTIVE_STATUSES.has(item.status)).length;
  const globalAttention =
    summary?.attention ??
    operations.filter((item) => ATTENTION_STATUSES.has(item.status)).length;
  const lastUpdated = summary?.updated_at || updatedAt;
  const firstRow = total ? offset + 1 : 0;
  const lastRow = Math.min(offset + PAGE_SIZE, total);

  return (
    <>
      <Panel
        id="operations"
        eyebrow="02"
        title="Центр операций"
        description="Фоновые задания сохраняются в PostgreSQL и остаются видимыми после обновления страницы или перезапуска приложения."
        action={
          <Button
            variant="secondary"
            busy={busy.operationsRefresh}
            onClick={() => runBusy("operationsRefresh", refreshCurrent)}
          >
            Обновить
          </Button>
        }
      >
        <div
          className="operation-summary"
          aria-label="Глобальная сводка операций"
        >
          <div>
            <strong>{globalTotal}</strong>
            <span>всего</span>
          </div>
          <div>
            <strong>{globalActive}</strong>
            <span>активных</span>
          </div>
          <div>
            <strong>{globalAttention}</strong>
            <span>требуют внимания</span>
          </div>
          <div className={stale ? "is-stale" : ""}>
            <strong>{stale ? "Устарели" : "Актуальны"}</strong>
            <span>{formatDate(lastUpdated)}</span>
          </div>
        </div>

        <div className="operation-filters">
          <input
            aria-label="Поиск операций"
            value={filters.q}
            onChange={(event) => changeFilter("q", event.target.value)}
            placeholder="Поиск по объекту, operation ID или сообщению"
          />
          <select
            aria-label="Статус операции"
            value={filters.status}
            onChange={(event) => changeFilter("status", event.target.value)}
          >
            <option value="">Все статусы</option>
            {[
              "queued",
              "running",
              "cancelling",
              "recovering",
              "completed",
              "completed_with_errors",
              "failed",
              "cancelled",
              "interrupted",
            ].map((status) => (
              <option value={status} key={status}>
                {statusLabel(status)}
              </option>
            ))}
          </select>
          <select
            aria-label="Тип операции"
            value={filters.kind}
            onChange={(event) => changeFilter("kind", event.target.value)}
          >
            <option value="">Все типы</option>
            {[
              "scan_postprocess",
              "asset_card_build",
              "asset_card_bulk_refresh",
              "asset_search_reindex",
              "passport_detail_sync",
              "pdql_export",
              "asset_removal",
              "task_delete",
              "automation_run",
            ].map((kind) => (
              <option value={kind} key={kind}>
                {kindLabel(kind)}
              </option>
            ))}
          </select>
        </div>

        <div className="saved-view-row">
          <select
            aria-label="Сохранённое представление"
            value=""
            onChange={(event) => applySavedView(event.target.value)}
          >
            <option value="">Сохранённые представления</option>
            {savedViews.map((view) => (
              <option value={view.id} key={view.id}>
                {view.name}
              </option>
            ))}
          </select>
          <input
            aria-label="Название представления"
            value={viewName}
            onChange={(event) => setViewName(event.target.value)}
            placeholder="Название текущего представления"
          />
          <Button
            variant="secondary"
            busy={busy.saveOperationView}
            onClick={saveCurrentView}
          >
            Сохранить
          </Button>
        </div>

        <div
          className="table-shell operation-table-shell"
          aria-busy={loading ? "true" : undefined}
        >
          <table className="operation-table">
            <thead>
              <tr>
                <SortableHeader column="status" sort={sort} onSort={changeSort}>
                  Состояние
                </SortableHeader>
                <SortableHeader column="kind" sort={sort} onSort={changeSort}>
                  Операция
                </SortableHeader>
                <SortableHeader
                  column="subject"
                  sort={sort}
                  onSort={changeSort}
                >
                  Объект
                </SortableHeader>
                <SortableHeader
                  column="progress"
                  sort={sort}
                  onSort={changeSort}
                >
                  Прогресс
                </SortableHeader>
                <SortableHeader
                  column="updated_at"
                  sort={sort}
                  onSort={changeSort}
                  initialDirection="desc"
                >
                  Обновлено
                </SortableHeader>
                <th>Действия</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={6} className="empty-cell" role="status">
                    Загрузка операций…
                  </td>
                </tr>
              ) : error ? (
                <tr>
                  <td colSpan={6} className="empty-cell">
                    <div
                      className="query-state query-state--error"
                      role="alert"
                    >
                      <span>
                        Не удалось загрузить операции:{" "}
                        {error.message || String(error)}
                      </span>
                      <Button variant="tiny" onClick={refreshCurrent}>
                        Повторить
                      </Button>
                    </div>
                  </td>
                </tr>
              ) : operations.length ? (
                operations.map((operation) => (
                  <tr key={operation.operation_id}>
                    <td>
                      <span
                        className={`operation-status operation-status--${operation.status}`}
                      >
                        {statusLabel(operation.status)}
                      </span>
                    </td>
                    <td>
                      <strong>{kindLabel(operation.kind)}</strong>
                      <span>{operation.message || operation.stage}</span>
                    </td>
                    <td>
                      <span>
                        {operation.subject?.label ||
                          operation.subject?.id ||
                          "—"}
                      </span>
                      <code title={operation.operation_id}>
                        {shortId(operation.operation_id)}
                      </code>
                    </td>
                    <td>
                      <div
                        className="operation-progress"
                        role="progressbar"
                        aria-label={`Прогресс ${kindLabel(operation.kind)}`}
                        aria-valuemin="0"
                        aria-valuemax="100"
                        aria-valuenow={operation.progress_percent || 0}
                      >
                        <span
                          style={{
                            width: `${operation.progress_percent || 0}%`,
                          }}
                        />
                      </div>
                      <small>{operation.progress_percent || 0}%</small>
                    </td>
                    <td>{formatDate(operation.updated_at)}</td>
                    <td>
                      <div className="row-actions">
                        <Button
                          variant="tiny"
                          busy={busy[`operation:${operation.operation_id}`]}
                          onClick={(event) =>
                            openOperation(operation, event.currentTarget)
                          }
                        >
                          Открыть
                        </Button>
                        {operation.can_cancel ? (
                          <Button
                            variant="tiny-danger"
                            busy={
                              busy[`operationCancel:${operation.operation_id}`]
                            }
                            onClick={() => cancelOperation(operation)}
                          >
                            Остановить
                          </Button>
                        ) : null}
                        {operation.can_retry ? (
                          <Button
                            variant="tiny"
                            busy={
                              busy[`operationRetry:${operation.operation_id}`]
                            }
                            onClick={() => retryOperation(operation)}
                          >
                            Повторить
                          </Button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="empty-cell">
                    Операции с такими фильтрами не найдены.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <nav className="operation-pagination" aria-label="Страницы операций">
          <Button
            variant="secondary"
            disabled={offset === 0 || loading}
            onClick={() => setOffset((value) => Math.max(0, value - PAGE_SIZE))}
          >
            Назад
          </Button>
          <span aria-live="polite">
            {total ? `${firstRow}–${lastRow} из ${total}` : "Нет операций"}
          </span>
          <Button
            variant="secondary"
            disabled={offset + PAGE_SIZE >= total || loading}
            onClick={() => setOffset((value) => value + PAGE_SIZE)}
          >
            Далее
          </Button>
        </nav>
      </Panel>
      {selected ? (
        <OperationDetail
          operation={selected}
          onClose={() => setSelected(null)}
          onCancel={cancelOperation}
          onRetry={retryOperation}
          busy={busy}
          returnFocus={returnFocus}
        />
      ) : null}
    </>
  );
}

function OperationDetail({
  operation,
  onClose,
  onCancel,
  onRetry,
  busy,
  returnFocus,
}) {
  const dialogRef = useDialogAccessibility(true, onClose, returnFocus);
  const drawer = (
    <div
      className="operation-drawer-overlay"
      role="presentation"
      onMouseDown={(event) => event.target === event.currentTarget && onClose()}
    >
      <aside
        ref={dialogRef}
        className="operation-drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby="operation-detail-title"
        tabIndex={-1}
      >
        <header>
          <div>
            <span>{kindLabel(operation.kind)}</span>
            <h2 id="operation-detail-title">
              {operation.subject?.label || operation.operation_id}
            </h2>
          </div>
          <button type="button" onClick={onClose} aria-label="Закрыть">
            ×
          </button>
        </header>
        <div className="operation-detail-grid" aria-live="polite">
          <div>
            <span>Статус</span>
            <strong>{statusLabel(operation.status)}</strong>
          </div>
          <div>
            <span>Этап</span>
            <strong>{operation.stage || "—"}</strong>
          </div>
          <div>
            <span>Прогресс</span>
            <strong>{operation.progress_percent || 0}%</strong>
          </div>
          <div>
            <span>Обновлено</span>
            <strong>{formatDate(operation.updated_at)}</strong>
          </div>
        </div>
        {operation.message ? (
          <p className="operation-message">{operation.message}</p>
        ) : null}
        {operation.trace_id ? (
          <div className="trace-box">
            <span>Trace ID</span>
            <code>{operation.trace_id}</code>
          </div>
        ) : null}
        <div className="operation-detail-actions">
          {operation.can_cancel ? (
            <Button
              variant="tiny-danger"
              busy={busy[`operationCancel:${operation.operation_id}`]}
              onClick={() => onCancel(operation)}
            >
              Остановить
            </Button>
          ) : null}
          {operation.can_retry ? (
            <Button
              variant="tiny"
              busy={busy[`operationRetry:${operation.operation_id}`]}
              onClick={() => onRetry(operation)}
            >
              Повторить
            </Button>
          ) : null}
          <a
            className="button secondary"
            href={`/api/operations/${encodeURIComponent(operation.operation_id)}/diagnostics`}
          >
            Диагностика
          </a>
        </div>
        <section className="operation-timeline">
          <h3>Хронология</h3>
          {(operation.events || []).map((event) => (
            <div key={event.id}>
              <span />
              <p>
                <strong>
                  {statusLabel(event.status)} · {event.stage}
                </strong>
                <small>
                  {event.message || "Изменение состояния"} ·{" "}
                  {formatDate(event.created_at)}
                </small>
              </p>
            </div>
          ))}
        </section>
        <details className="raw-details">
          <summary>Параметры и результат</summary>
          <pre>
            {JSON.stringify(
              {
                request: operation.request,
                result: operation.result,
                error: operation.error,
              },
              null,
              2,
            )}
          </pre>
        </details>
      </aside>
    </div>
  );
  return typeof document === "undefined"
    ? drawer
    : createPortal(drawer, document.body);
}

function kindLabel(kind) {
  return (
    {
      automation_run: "Runbook автоматизации",
      scan_postprocess: "Постобработка сканирования",
      asset_card_build: "Карточка актива",
      asset_card_bulk_refresh: "Массовое обновление карточек",
      asset_search_reindex: "Индексация карточек",
      passport_detail_sync: "Детали паспортов",
      pdql_export: "PDQL экспорт",
      asset_removal: "Удаление активов",
      task_delete: "Удаление задачи MP VM",
    }[kind] || kind
  );
}

function statusLabel(status) {
  return (
    {
      queued: "В очереди",
      running: "Выполняется",
      cancelling: "Останавливается",
      recovering: "Восстанавливается",
      completed: "Завершено",
      completed_with_errors: "С ошибками",
      failed: "Ошибка",
      cancelled: "Отменено",
      interrupted: "Прервано",
    }[status] || status
  );
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ru-RU");
}

function shortId(value) {
  const text = String(value || "");
  return text.length > 18 ? `${text.slice(0, 8)}…${text.slice(-6)}` : text;
}
