import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, createIdempotencyKey } from "../api/client.js";
import { Button, Panel } from "../shared/ui.jsx";

const ACTIVE = new Set(["queued", "running", "cancelling"]);
const workflowStatus = {
  queued: "В очереди", running: "Выполняется", cancelling: "Отменяется",
  completed: "Завершён", completed_with_errors: "Завершён с ошибками",
  failed: "Ошибка", cancelled: "Отменён",
};
const stepLabels = {
  validation: "Проверка задачи", targets: "Подготовка целей", scan: "Сканирование MP VM",
  postprocess: "Загрузка и карточки", reconcile: "Сверка находок",
};

export function VmManagementPage({ session, currentUser, showAlert, onNavigate }) {
  const queryClient = useQueryClient();
  const [selectedWorkflowId, setSelectedWorkflowId] = useState(() => queryValue("workflow"));
  const [selectedCampaignId, setSelectedCampaignId] = useState(() => queryValue("campaign"));
  const [taskId, setTaskId] = useState("");
  const [options, setOptions] = useState({ precheck_enabled: false, require_clean_jobs: false, task_timeout_minutes: 120 });
  const [starting, setStarting] = useState(false);
  const permissions = useMemo(() => new Set(currentUser?.permissions || []), [currentUser]);

  const overview = useQuery({
    queryKey: ["vm-overview"], queryFn: () => api("/api/vm/overview"),
    refetchInterval: (query) => Number(query.state.data?.active_workflows || 0) ? 2000 : 15000,
  });
  const tasks = useQuery({
    queryKey: ["scanner-tasks"], queryFn: () => api("/api/scanner-tasks"),
    enabled: session.connected && permissions.has("tasks.read"),
  });
  const campaigns = useQuery({
    queryKey: ["remediation-campaigns"], queryFn: () => api("/api/remediation/campaigns"),
    enabled: permissions.has("remediation.read"), refetchInterval: 15000,
  });
  const workflow = useQuery({
    queryKey: ["vm-workflow", selectedWorkflowId],
    queryFn: () => api(`/api/vm/workflows/${encodeURIComponent(selectedWorkflowId)}`),
    enabled: Boolean(selectedWorkflowId),
    refetchInterval: (query) => ACTIVE.has(query.state.data?.status) ? 1500 : false,
  });
  const campaign = useQuery({
    queryKey: ["remediation-campaign", selectedCampaignId],
    queryFn: () => api(`/api/remediation/campaigns/${encodeURIComponent(selectedCampaignId)}`),
    enabled: Boolean(selectedCampaignId),
  });

  useEffect(() => {
    if (!taskId && tasks.data?.length) setTaskId(tasks.data[0].mp_task_id);
  }, [taskId, tasks.data]);
  useEffect(() => {
    if (workflow.data && !ACTIVE.has(workflow.data.status)) {
      void queryClient.invalidateQueries({ queryKey: ["vm-overview"] });
      void queryClient.invalidateQueries({ queryKey: ["remediation-campaigns"] });
      if (selectedCampaignId) void queryClient.invalidateQueries({ queryKey: ["remediation-campaign", selectedCampaignId] });
    }
  }, [workflow.data, queryClient, selectedCampaignId]);

  const openWorkflow = (id) => {
    setSelectedWorkflowId(id); setSelectedCampaignId(null); setQuery({ workflow: id });
  };
  const openCampaign = (id) => {
    setSelectedCampaignId(id); setSelectedWorkflowId(null); setQuery({ campaign: id });
  };
  const refresh = async () => {
    await Promise.all([
      overview.refetch(), campaigns.refetch(),
      selectedWorkflowId ? workflow.refetch() : Promise.resolve(),
      selectedCampaignId ? campaign.refetch() : Promise.resolve(),
    ]);
  };
  const startScan = async () => {
    if (!taskId) return;
    setStarting(true);
    try {
      const result = await api("/api/vm/workflows/scan", {
        method: "POST", headers: { "X-Idempotency-Key": createIdempotencyKey("vm-scan") },
        body: JSON.stringify({ task_id: taskId, options }),
      });
      showAlert("VM-конвейер запущен.", "success");
      openWorkflow(result.workflow_id); await refresh();
    } catch (error) { showAlert(error.operatorMessage || error.message, "error"); }
    finally { setStarting(false); }
  };
  const workflowAction = async (action) => {
    try {
      const result = await api(`/api/vm/workflows/${selectedWorkflowId}/${action}`, {
        method: "POST", headers: action === "retry" ? { "X-Idempotency-Key": createIdempotencyKey("vm-retry") } : undefined,
      });
      const next = result.workflow || result;
      if (action === "retry") openWorkflow(next.workflow_id);
      showAlert(action === "cancel" ? "Отмена запрошена." : "Повтор запущен.", "success");
      await refresh();
    } catch (error) { showAlert(error.operatorMessage || error.message, "error"); }
  };

  const data = overview.data || {};
  const attention = data.attention || [];
  const recentWorkflows = data.recent_workflows || [];
  const campaignRows = campaigns.data?.rows || [];
  return <div className="vm-page">
    <div className="vm-workspace-grid">
      <div className="vm-control-column">
      <Panel className="vm-launcher" title="Запустить полный цикл"
        description="После запуска импорт, карточки и сверка выполнятся автоматически.">
        <label><span>Задача MP VM</span><select value={taskId} onChange={(event) => setTaskId(event.target.value)} disabled={!session.connected}>
          <option value="">Выберите задачу</option>{(tasks.data || []).map((task) => <option value={task.mp_task_id} key={task.mp_task_id}>{task.payload?.name || task.name || task.mp_task_id}</option>)}
        </select></label>
        <div className="vm-launch-options">
          <label><input type="checkbox" checked={options.precheck_enabled} onChange={(event) => setOptions({ ...options, precheck_enabled: event.target.checked })} /> Проверить доступность целей</label>
          <label><input type="checkbox" checked={options.require_clean_jobs} onChange={(event) => setOptions({ ...options, require_clean_jobs: event.target.checked })} /> Требовать чистый результат</label>
          <label><span>Таймаут, минут</span><input type="number" min="1" max="1440" value={options.task_timeout_minutes} onChange={(event) => setOptions({ ...options, task_timeout_minutes: Number(event.target.value) })} /></label>
        </div>
        <Button className="vm-launch-button" busy={starting} disabled={!taskId || !session.connected || !permissions.has("tasks.execute")} onClick={startScan}>Запустить конвейер <span aria-hidden="true">→</span></Button>
        {!permissions.has("tasks.execute") ? <small className="vm-permission-note">Для запуска требуется право tasks.execute.</small> : null}
      </Panel>

        <nav className="vm-stage-links" aria-label="Этапы VM-процесса">
          <Stage number="01" title="Сканирование" text="Задачи и выполнение" onClick={() => onNavigate("/tasks")} />
          <Stage number="02" title="Находки" text="Уязвимости и покрытие" onClick={() => onNavigate("/vulnerabilities")} />
          <Stage number="03" title="Устранение" text="SLA, риск и кампании" onClick={() => onNavigate("/remediation")} />
          <Stage number="04" title="Проверка" text="Повторное сканирование" onClick={() => document.getElementById("vm-campaigns")?.scrollIntoView({ behavior: "smooth" })} />
          <Stage number="05" title="Отчётность" text="CSV и автоматизации" onClick={() => onNavigate("/export")} />
        </nav>
      </div>

      <div className="vm-operations-column">
        <Panel id="vm-overview" className="vm-overview" title="Оперативная сводка"
          description="Основные показатели VM-контура"
          action={<Button variant="secondary" busy={overview.isFetching} onClick={refresh}>Обновить</Button>}>
          {!session.connected ? <div className="vm-callout vm-callout--warning"><div><strong>MP VM не подключён</strong><span>Для запуска сканирования установите рабочую сессию.</span></div><Button onClick={() => onNavigate("/connection")}>Настроить</Button></div> : null}
          {overview.error ? <div className="inline-error vm-overview-error" role="alert">{overview.error.operatorMessage || overview.error.message}</div> : null}
          <div className="vm-kpis" aria-label="Сводка VM Management">
            <Kpi label="Активные процессы" value={data.active_workflows} tone="blue" />
            <Kpi label="Открытые кейсы" value={data.open_cases} />
            <Kpi label="Просрочено" value={data.overdue_cases} tone="danger" />
            <Kpi label="Срочный риск" value={data.risk?.urgent} tone="danger" />
            <Kpi label="Ожидают проверки" value={data.awaiting_verification} tone="warning" />
            <Kpi label="Покрытие" value={`${data.coverage?.coverage_percent ?? 100}%`} />
          </div>
          <section className="vm-attention" aria-labelledby="vm-attention-title">
            <div className="vm-section-heading"><div><h3 id="vm-attention-title">Требуют внимания</h3><p>Сначала просроченные, затем наиболее критичные находки.</p></div><span className="vm-attention-count">{attention.length}</span></div>
            <div className="vm-attention-list">{attention.length ? attention.map((item) =>
              <a href={`/remediation?case=${encodeURIComponent(item.case_id)}`} key={item.case_id}>
                <span className={`severity severity--${item.severity}`}>{item.severity}</span>
                <div><strong>{item.cve || item.title}</strong><small>{item.asset_id}</small></div>
                <time dateTime={item.due_at || undefined}>{date(item.due_at)}</time>
                <b aria-hidden="true">→</b>
              </a>) : <p className="empty-cell">Срочных кейсов нет.</p>}</div>
          </section>
        </Panel>

        <Panel id="vm-workflows" className="vm-workflows" title="Последние процессы"
          description="Состояние сохраняется после обновления страницы и перезапуска приложения."
          action={<Button variant="secondary" onClick={() => onNavigate("/operations")}>Все операции</Button>}>
          <div className="vm-workflow-list">{recentWorkflows.length ? recentWorkflows.map((item) => <button type="button" onClick={() => openWorkflow(item.workflow_id)} key={item.workflow_id}>
            <Status value={item.status} /><div><strong>{item.kind === "verification" ? "Проверка кампании" : "Полное сканирование"}</strong><small>{item.task_id || item.campaign_id || item.workflow_id} · {date(item.created_at)}</small></div><Progress value={item.progress_percent} /><b>{item.progress_percent}%</b>
          </button>) : <p className="empty-cell">Процессов пока нет.</p>}</div>
        </Panel>
      </div>
    </div>

    <Panel id="vm-campaigns" className="vm-campaigns" title="Кампании устранения"
      description="Ответственные, сроки и проверка результата повторным сканированием."
      action={<Button variant="secondary" onClick={() => onNavigate("/remediation")}>Очередь риска</Button>}>
      <div className="vm-campaign-grid">{campaignRows.length ? campaignRows.map((item) => <button type="button" onClick={() => openCampaign(item.campaign_id)} key={item.campaign_id}>
        <span className={`campaign-state campaign-state--${item.status}`}>{campaignLabel(item.status)}</span><strong>{item.name}</strong><small>{item.assignee || "Ответственный не назначен"} · {date(item.due_at)}</small><Progress value={item.total ? Math.round(item.resolved * 100 / item.total) : 0} /><span><b>{item.resolved}/{item.total}</b> подтверждено · <em>{item.overdue} просрочено</em></span>
      </button>) : <p className="empty-cell">Кампаний пока нет.</p>}</div>
    </Panel>

    {selectedWorkflowId ? <WorkflowDrawer item={workflow.data} loading={workflow.isLoading} onClose={() => { setSelectedWorkflowId(null); setQuery({}); }} onCancel={() => workflowAction("cancel")} onRetry={() => workflowAction("retry")} /> : null}
    {selectedCampaignId ? <CampaignDrawer item={campaign.data} loading={campaign.isLoading} permissions={permissions} showAlert={showAlert} onWorkflow={openWorkflow} onRefresh={refresh} onClose={() => { setSelectedCampaignId(null); setQuery({}); }} /> : null}
  </div>;
}

function Kpi({ label, value, tone = "neutral" }) { return <article className={`vm-kpi vm-kpi--${tone}`}><strong>{value ?? 0}</strong><span>{label}</span></article>; }
function Stage({ number, title, text, onClick }) { return <button type="button" onClick={onClick}><span>{number}</span><span><strong>{title}</strong><small>{text}</small></span></button>; }
function Status({ value }) { return <span className={`vm-status vm-status--${value}`}>{workflowStatus[value] || value}</span>; }
function Progress({ value = 0 }) { return <span className="vm-progress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow={value}><i style={{ width: `${value}%` }} /></span>; }

function WorkflowDrawer({ item, loading, onClose, onCancel, onRetry }) {
  return <div className="vm-drawer-overlay" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}><aside className="vm-drawer" role="dialog" aria-modal="true" aria-labelledby="vm-workflow-title">
    <header><div><span>VM workflow</span><h2 id="vm-workflow-title">{item?.kind === "verification" ? "Проверка кампании" : "Полное сканирование"}</h2></div><button onClick={onClose} aria-label="Закрыть">×</button></header>
    {loading || !item ? <p>Загрузка процесса…</p> : <><div className="vm-drawer-summary"><Status value={item.status} /><strong>{item.progress_percent}%</strong><span>{item.workflow_id}</span></div><Progress value={item.progress_percent} />
      <ol className="vm-step-list">{item.steps.map((step) => <li className={`is-${step.status}`} key={step.step_key}><span>{step.status === "completed" ? "✓" : step.position}</span><div><strong>{stepLabels[step.step_key] || step.step_key}</strong><small>{step.message || workflowStatus[step.status] || step.status}</small>{step.error?.message ? <em>{step.error.message}</em> : null}</div><b>{step.progress_percent}%</b></li>)}</ol>
      {item.error?.message ? <div className="inline-error" role="alert">{item.error.message}</div> : null}
      <div className="action-row">{item.can_cancel ? <Button variant="danger" onClick={onCancel}>Остановить</Button> : null}{item.can_retry ? <Button onClick={onRetry}>Повторить с места сбоя</Button> : null}{item.operation_id ? <a className="button secondary" href={`/operations?operation=${encodeURIComponent(item.operation_id)}`}>Открыть операцию</a> : null}</div>
    </>}</aside></div>;
}

function CampaignDrawer({ item, loading, permissions, showAlert, onWorkflow, onRefresh, onClose }) {
  const [draft, setDraft] = useState(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (item) setDraft({ name: item.name, assignee: item.assignee || "", due_at: inputDate(item.due_at), status: item.status, comment: item.comment || "" }); }, [item]);
  const save = async () => { setBusy(true); try { await api(`/api/remediation/campaigns/${item.campaign_id}`, { method: "PATCH", body: JSON.stringify({ ...draft, due_at: draft.due_at || null }) }); showAlert("Кампания обновлена.", "success"); await onRefresh(); } catch (error) { showAlert(error.operatorMessage || error.message, "error"); } finally { setBusy(false); } };
  const verify = async () => { setBusy(true); try { const result = await api(`/api/remediation/campaigns/${item.campaign_id}/verify`, { method: "POST", headers: { "X-Idempotency-Key": createIdempotencyKey("campaign-verify") } }); showAlert("Проверочное сканирование запущено.", "success"); onWorkflow(result.workflow_id); } catch (error) { showAlert(error.operatorMessage || error.message, "error"); } finally { setBusy(false); } };
  return <div className="vm-drawer-overlay" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}><aside className="vm-drawer vm-campaign-drawer" role="dialog" aria-modal="true" aria-labelledby="vm-campaign-title"><header><div><span>Кампания устранения</span><h2 id="vm-campaign-title">{item?.name || "Загрузка…"}</h2></div><button onClick={onClose} aria-label="Закрыть">×</button></header>
    {loading || !item || !draft ? <p>Загрузка кампании…</p> : <><div className="form-grid"><label>Название<input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} /></label><label>Ответственный<input value={draft.assignee} onChange={(event) => setDraft({ ...draft, assignee: event.target.value })} /></label><label>Срок<input type="datetime-local" value={draft.due_at} onChange={(event) => setDraft({ ...draft, due_at: event.target.value })} /></label><label>Статус<select value={draft.status} onChange={(event) => setDraft({ ...draft, status: event.target.value })}>{["draft", "active", "completed", "cancelled"].map((value) => <option key={value} value={value}>{campaignLabel(value)}</option>)}</select></label><label className="span-2">Комментарий<textarea value={draft.comment} onChange={(event) => setDraft({ ...draft, comment: event.target.value })} /></label></div>
      <div className="action-row"><Button busy={busy} disabled={!permissions.has("risk.manage")} onClick={save}>Сохранить</Button><Button busy={busy} disabled={!permissions.has("tasks.execute") || !permissions.has("risk.manage") || !permissions.has("remediation.manage")} onClick={verify}>Запустить проверку</Button></div>
      <h3>Кейсы · {item.cases?.length || 0}</h3><div className="vm-case-list">{(item.cases || []).map((entry) => <a href={`/remediation?case=${encodeURIComponent(entry.case_id)}`} key={entry.case_id}><span className={`severity severity--${entry.severity}`}>{entry.severity}</span><div><strong>{entry.cve || entry.title}</strong><small>{entry.asset_id} · {entry.verification_status || "none"}</small></div><b>{entry.status}</b></a>)}</div>
      <details><summary>История кампании ({item.events?.length || 0})</summary><ul className="audit-list">{(item.events || []).map((event) => <li key={event.event_id}><strong>{event.event_type}</strong> · {date(event.created_at)}</li>)}</ul></details>
    </>}</aside></div>;
}

function queryValue(key) { return typeof window === "undefined" ? null : new URLSearchParams(window.location.search).get(key); }
function setQuery(values) { if (typeof window === "undefined") return; const params = new URLSearchParams(Object.entries(values).filter(([, value]) => value)); window.history.replaceState({}, "", `/vm${params.size ? `?${params}` : ""}`); }
function date(value) { if (!value) return "без срока"; const parsed = new Date(value); return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString("ru-RU"); }
function inputDate(value) { if (!value) return ""; const parsed = new Date(value); return new Date(parsed.getTime() - parsed.getTimezoneOffset() * 60000).toISOString().slice(0, 16); }
function campaignLabel(value) { return { draft: "Черновик", active: "Активна", completed: "Завершена", cancelled: "Отменена" }[value] || value; }
