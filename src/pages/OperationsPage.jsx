import { useEffect, useMemo, useState } from "react";
import { api, createIdempotencyKey } from "../api/client.js";
import { Button, Panel } from "../shared/ui.jsx";
import { SortableHeader, sortRows, useTableSort } from "../shared/table.jsx";

const ACTIVE_STATUSES = new Set(["queued", "running", "cancelling", "recovering"]);

export function OperationsPage({ operations, total, updatedAt, stale, refreshOperations, runBusy, busy, showAlert }) {
  const [filters, setFilters] = useState({ q: "", status: "", kind: "" });
  const [selected, setSelected] = useState(null);
  const [savedViews, setSavedViews] = useState([]);
  const [viewName, setViewName] = useState("");
  const [sort, toggleSort] = useTableSort("created_at", "desc");

  const changeSort = (key, initialDirection) => {
    const direction = sort.key === key ? (sort.direction === "asc" ? "desc" : "asc") : initialDirection;
    toggleSort(key, initialDirection);
    runBusy("operationsSort", () => refreshOperations({ sort_by: key, sort_dir: direction }));
  };

  const filtered = useMemo(() => {
    const needle = filters.q.trim().toLowerCase();
    return operations.filter((operation) => {
      if (filters.status && operation.status !== filters.status) return false;
      if (filters.kind && operation.kind !== filters.kind) return false;
      if (!needle) return true;
      return [operation.subject?.label, operation.subject?.id, operation.message, operation.operation_id]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(needle));
    });
  }, [filters, operations]);
  const displayed = useMemo(() => sortRows(filtered, sort, {
    subject: (operation) => operation.subject?.label || operation.subject?.id,
    progress: (operation) => operation.progress_percent,
  }), [filtered, sort]);

  useEffect(() => {
    api("/api/saved-views?route=operations")
      .then((result) => setSavedViews(result.rows || []))
      .catch(() => null);
  }, []);

  const openOperation = (operation) => runBusy(`operation:${operation.operation_id}`, async () => {
    const detail = await api(`/api/operations/${encodeURIComponent(operation.operation_id)}`);
    setSelected(detail);
  });

  const cancelOperation = (operation) => runBusy(`operationCancel:${operation.operation_id}`, async () => {
    const result = await api(`/api/operations/${encodeURIComponent(operation.operation_id)}/cancel`, { method: "POST" });
    setSelected(result);
    await refreshOperations();
    showAlert("Запрос на остановку операции принят.", "info");
  });

  const retryOperation = (operation) => runBusy(`operationRetry:${operation.operation_id}`, async () => {
    const result = await api(`/api/operations/${encodeURIComponent(operation.operation_id)}/retry`, {
      method: "POST",
      headers: { "X-Idempotency-Key": createIdempotencyKey("retry") },
    });
    setSelected(result.operation || null);
    await refreshOperations();
    showAlert("Повтор операции поставлен в очередь.", "success");
  });

  const saveCurrentView = () => runBusy("saveOperationView", async () => {
    const name = viewName.trim();
    if (!name) throw new Error("Введите название представления.");
    const result = await api("/api/saved-views", {
      method: "POST",
      body: JSON.stringify({ route: "operations", name, filters }),
    });
    setSavedViews((items) => [...items.filter((item) => item.id !== result.id), result].sort((a, b) => a.name.localeCompare(b.name)));
    setViewName("");
    showAlert(`Представление «${name}» сохранено.`, "success");
  });

  return (
    <>
      <Panel
        id="operations"
        eyebrow="02"
        title="Центр операций"
        description="Фоновые задания сохраняются в PostgreSQL и остаются видимыми после обновления страницы или перезапуска приложения."
        action={<Button variant="secondary" busy={busy.operationsRefresh} onClick={() => runBusy("operationsRefresh", refreshOperations)}>Обновить</Button>}
      >
        <div className="operation-summary">
          <div><strong>{total}</strong><span>всего</span></div>
          <div><strong>{operations.filter((item) => ACTIVE_STATUSES.has(item.status)).length}</strong><span>активных</span></div>
          <div><strong>{operations.filter((item) => ["failed", "interrupted", "completed_with_errors"].includes(item.status)).length}</strong><span>требуют внимания</span></div>
          <div className={stale ? "is-stale" : ""}><strong>{stale ? "Устарели" : "Актуальны"}</strong><span>{formatDate(updatedAt)}</span></div>
        </div>

        <div className="operation-filters">
          <input value={filters.q} onChange={(event) => setFilters((value) => ({ ...value, q: event.target.value }))} placeholder="Поиск по объекту, ID или сообщению" />
          <select value={filters.status} onChange={(event) => setFilters((value) => ({ ...value, status: event.target.value }))}>
            <option value="">Все статусы</option>
            {["queued", "running", "completed", "completed_with_errors", "failed", "cancelled", "interrupted"].map((status) => <option value={status} key={status}>{statusLabel(status)}</option>)}
          </select>
          <select value={filters.kind} onChange={(event) => setFilters((value) => ({ ...value, kind: event.target.value }))}>
            <option value="">Все типы</option>
            {["scan_postprocess", "asset_card_build", "asset_search_reindex", "passport_detail_sync", "pdql_export", "asset_removal", "task_delete"].map((kind) => <option value={kind} key={kind}>{kindLabel(kind)}</option>)}
          </select>
        </div>

        <div className="saved-view-row">
          <select value="" onChange={(event) => {
            const view = savedViews.find((item) => String(item.id) === event.target.value);
            if (view) setFilters({ q: "", status: "", kind: "", ...view.filters });
          }}>
            <option value="">Сохранённые представления</option>
            {savedViews.map((view) => <option value={view.id} key={view.id}>{view.name}</option>)}
          </select>
          <input value={viewName} onChange={(event) => setViewName(event.target.value)} placeholder="Название текущего представления" />
          <Button variant="secondary" busy={busy.saveOperationView} onClick={saveCurrentView}>Сохранить</Button>
        </div>

        <div className="table-shell operation-table-shell">
          <table className="operation-table">
            <thead><tr>
              <SortableHeader column="status" sort={sort} onSort={changeSort}>Состояние</SortableHeader>
              <SortableHeader column="kind" sort={sort} onSort={changeSort}>Операция</SortableHeader>
              <SortableHeader column="subject" sort={sort} onSort={changeSort}>Объект</SortableHeader>
              <SortableHeader column="progress" sort={sort} onSort={changeSort}>Прогресс</SortableHeader>
              <SortableHeader column="updated_at" sort={sort} onSort={changeSort} initialDirection="desc">Обновлено</SortableHeader>
              <th>Действия</th>
            </tr></thead>
            <tbody>
              {displayed.length ? displayed.map((operation) => (
                <tr key={operation.operation_id}>
                  <td><span className={`operation-status operation-status--${operation.status}`}>{statusLabel(operation.status)}</span></td>
                  <td><strong>{kindLabel(operation.kind)}</strong><span>{operation.message || operation.stage}</span></td>
                  <td><span>{operation.subject?.label || operation.subject?.id || "—"}</span><code>{shortId(operation.operation_id)}</code></td>
                  <td><div className="operation-progress"><span style={{ width: `${operation.progress_percent || 0}%` }} /></div><small>{operation.progress_percent || 0}%</small></td>
                  <td>{formatDate(operation.updated_at)}</td>
                  <td><div className="row-actions">
                    <Button variant="tiny" busy={busy[`operation:${operation.operation_id}`]} onClick={() => openOperation(operation)}>Открыть</Button>
                    {operation.can_cancel ? <Button variant="tiny-danger" busy={busy[`operationCancel:${operation.operation_id}`]} onClick={() => cancelOperation(operation)}>Остановить</Button> : null}
                    {operation.can_retry ? <Button variant="tiny" busy={busy[`operationRetry:${operation.operation_id}`]} onClick={() => retryOperation(operation)}>Повторить</Button> : null}
                  </div></td>
                </tr>
              )) : <tr><td colSpan={6} className="empty-cell">Операции с такими фильтрами не найдены.</td></tr>}
            </tbody>
          </table>
        </div>
      </Panel>
      {selected ? <OperationDetail operation={selected} onClose={() => setSelected(null)} onCancel={cancelOperation} onRetry={retryOperation} busy={busy} /> : null}
    </>
  );
}

function OperationDetail({ operation, onClose, onCancel, onRetry, busy }) {
  return (
    <div className="operation-drawer-overlay" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <aside className="operation-drawer" aria-label="Детали операции">
        <header><div><span>{kindLabel(operation.kind)}</span><h2>{operation.subject?.label || operation.operation_id}</h2></div><button onClick={onClose} aria-label="Закрыть">×</button></header>
        <div className="operation-detail-grid">
          <div><span>Статус</span><strong>{statusLabel(operation.status)}</strong></div>
          <div><span>Этап</span><strong>{operation.stage || "—"}</strong></div>
          <div><span>Прогресс</span><strong>{operation.progress_percent || 0}%</strong></div>
          <div><span>Обновлено</span><strong>{formatDate(operation.updated_at)}</strong></div>
        </div>
        {operation.message ? <p className="operation-message">{operation.message}</p> : null}
        {operation.trace_id ? <div className="trace-box"><span>Trace ID</span><code>{operation.trace_id}</code></div> : null}
        <div className="operation-detail-actions">
          {operation.can_cancel ? <Button variant="tiny-danger" busy={busy[`operationCancel:${operation.operation_id}`]} onClick={() => onCancel(operation)}>Остановить</Button> : null}
          {operation.can_retry ? <Button variant="tiny" busy={busy[`operationRetry:${operation.operation_id}`]} onClick={() => onRetry(operation)}>Повторить</Button> : null}
          <a className="button secondary" href={`/api/operations/${encodeURIComponent(operation.operation_id)}/diagnostics`}>Диагностика</a>
        </div>
        <section className="operation-timeline"><h3>Хронология</h3>{(operation.events || []).map((event) => <div key={event.id}><span /><p><strong>{statusLabel(event.status)} · {event.stage}</strong><small>{event.message || "Изменение состояния"} · {formatDate(event.created_at)}</small></p></div>)}</section>
        <details className="raw-details"><summary>Параметры и результат</summary><pre>{JSON.stringify({ request: operation.request, result: operation.result, error: operation.error }, null, 2)}</pre></details>
      </aside>
    </div>
  );
}

function kindLabel(kind) {
  if (kind === "automation_run") return "Runbook автоматизации";
  return ({ scan_postprocess: "Постобработка сканирования", asset_card_build: "Карточка актива", asset_search_reindex: "Индексация карточек", passport_detail_sync: "Детали паспортов", pdql_export: "PDQL экспорт", asset_removal: "Удаление активов", task_delete: "Удаление задачи MP VM" })[kind] || kind;
}

function statusLabel(status) {
  return ({ queued: "В очереди", running: "Выполняется", cancelling: "Останавливается", recovering: "Восстанавливается", completed: "Завершено", completed_with_errors: "С ошибками", failed: "Ошибка", cancelled: "Отменено", interrupted: "Прервано" })[status] || status;
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
