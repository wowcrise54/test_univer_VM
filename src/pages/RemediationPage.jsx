import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client.js";

const statusLabels = {
  open: "Открыта", in_progress: "В работе", risk_accepted: "Риск принят",
  false_positive: "Ложное срабатывание", resolved: "Устранена",
};

export function RemediationPage({ showAlert, onNavigate }) {
  const [rows, setRows] = useState([]);
  const [summary, setSummary] = useState({});
  const [policy, setPolicy] = useState(null);
  const [selected, setSelected] = useState(null);
  const [checked, setChecked] = useState([]);
  const [filters, setFilters] = useState({ q: "", status: "", severity: "", overdue: false });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true); setError("");
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => { if (value) params.set(key, String(value)); });
    try {
      const [cases, totals, nextPolicy] = await Promise.all([
        api(`/api/remediation/cases?${params}`), api("/api/remediation/summary"), api("/api/remediation/policy"),
      ]);
      setRows(cases.rows || []); setSummary(totals || {}); setPolicy(nextPolicy);
      setChecked((value) => value.filter((id) => (cases.rows || []).some((item) => item.case_id === id)));
    } catch (nextError) { setError(nextError.operatorMessage || nextError.message); }
    finally { setLoading(false); }
  }, [filters]);

  useEffect(() => { load(); }, [load]);

  const openCase = async (caseId) => {
    try { setSelected(await api(`/api/remediation/cases/${caseId}`)); }
    catch (nextError) { showAlert(nextError.operatorMessage || nextError.message, "error"); }
  };

  const updateCase = async (values) => {
    try {
      const next = await api(`/api/remediation/cases/${selected.case_id}`, {
        method: "PATCH", body: JSON.stringify({ ...values, expected_version: selected.version }),
      });
      setSelected(next); showAlert("Кейс обновлён.", "success"); await load();
    } catch (nextError) { showAlert(nextError.operatorMessage || nextError.message, "error"); }
  };

  const bulkUpdate = async (status) => {
    if (!checked.length) return;
    try {
      const result = await api("/api/remediation/cases/bulk-update", {
        method: "POST", body: JSON.stringify({ case_ids: checked, status, comment: "Массовое обновление" }),
      });
      showAlert(`Обновлено кейсов: ${result.updated_count}.`, "success"); setChecked([]); await load();
    } catch (nextError) { showAlert(nextError.operatorMessage || nextError.message, "error"); }
  };

  return <section className="panel remediation-page">
    <div className="panel__header"><div><h2>Устранение уязвимостей</h2><p>Ответственные, сроки и подтверждение устранения повторным сканированием.</p></div>
      <button className="button button--secondary" onClick={load}>Обновить</button></div>
    <div className="metric-grid remediation-metrics">
      <Metric label="Открыто" value={summary.open} />
      <Metric label="Просрочено" value={summary.overdue} danger />
      <Metric label="Скоро срок" value={summary.near_due} />
      <Metric label="Риск принят" value={summary.risk_accepted} />
      <Metric label="Устранено за 30 дней" value={summary.resolved_30d} />
      <Metric label="Средний срок, дней" value={summary.mean_time_to_resolve_days ?? "—"} />
    </div>
    <div className="remediation-toolbar">
      <input aria-label="Поиск кейсов" placeholder="CVE, уязвимость или актив" value={filters.q} onChange={(e) => setFilters({ ...filters, q: e.target.value })} />
      <select aria-label="Статус" value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}><option value="">Все статусы</option>{Object.entries(statusLabels).map(([value,label]) => <option key={value} value={value}>{label}</option>)}</select>
      <select aria-label="Критичность" value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}><option value="">Любая критичность</option>{["critical","high","medium","low","unknown"].map((value) => <option key={value}>{value}</option>)}</select>
      <label><input type="checkbox" checked={filters.overdue} onChange={(e) => setFilters({ ...filters, overdue: e.target.checked })} /> Только просроченные</label>
      <button disabled={!checked.length} onClick={() => bulkUpdate("in_progress")}>Взять в работу ({checked.length})</button>
    </div>
    {error ? <div className="inline-error">{error}</div> : null}
    <div className="table-shell"><table><thead><tr><th></th><th>Уязвимость</th><th>Актив</th><th>Критичность</th><th>Статус</th><th>Ответственный</th><th>Срок</th></tr></thead>
      <tbody>{loading ? <tr><td colSpan="7" className="empty-cell">Загрузка…</td></tr> : rows.length ? rows.map((item) => <tr key={item.case_id} className={item.overdue ? "row--danger" : ""}>
        <td><input aria-label={`Выбрать ${item.title || item.cve}`} type="checkbox" checked={checked.includes(item.case_id)} onChange={(e) => setChecked(e.target.checked ? [...checked,item.case_id] : checked.filter((id) => id !== item.case_id))} /></td>
        <td><button className="link-button" onClick={() => openCase(item.case_id)}>{item.cve || item.title || item.vulnerability_key}</button><small>{item.title}</small></td>
        <td>{item.display_name || item.asset_id}<small>{item.ip_address || item.fqdn}</small></td><td><span className={`severity severity--${item.severity}`}>{item.severity}</span></td>
        <td>{statusLabels[item.status]}</td><td>{item.assignee || "—"}</td><td>{formatDate(item.due_at)}{item.overdue ? <small className="danger-text">Просрочено</small> : null}</td>
      </tr>) : <tr><td colSpan="7" className="empty-cell">Кейсы не найдены.</td></tr>}</tbody></table></div>
    {selected ? <CaseEditor item={selected} onClose={() => setSelected(null)} onSave={updateCase} onNavigate={onNavigate} /> : null}
    {policy ? <PolicyEditor policy={policy} setPolicy={setPolicy} onSaved={load} showAlert={showAlert} /> : null}
  </section>;
}

function Metric({ label, value, danger }) { return <article className={`metric-card${danger ? " metric-card--danger" : ""}`}><span>{label}</span><strong>{value ?? 0}</strong></article>; }

function CaseEditor({ item, onClose, onSave, onNavigate }) {
  const [draft, setDraft] = useState({ status: item.status, assignee: item.assignee || "", due_at: toInputDate(item.due_at), risk_reason: item.risk_reason || "", risk_expires_at: toInputDate(item.risk_expires_at), comment: "" });
  return <div className="detail-card remediation-detail"><header><div><h3>{item.cve || item.title}</h3><p>{item.display_name || item.asset_id}</p></div><button onClick={onClose}>Закрыть</button></header>
    <div className="form-grid"><label>Статус<select value={draft.status} onChange={(e) => setDraft({...draft,status:e.target.value})}>{Object.entries(statusLabels).filter(([value]) => value !== "resolved").map(([value,label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      <label>Ответственный<input value={draft.assignee} onChange={(e) => setDraft({...draft,assignee:e.target.value})} /></label>
      <label>Срок<input type="datetime-local" value={draft.due_at} onChange={(e) => setDraft({...draft,due_at:e.target.value})} /></label>
      {draft.status === "risk_accepted" ? <><label>Риск принят до<input required type="datetime-local" value={draft.risk_expires_at} onChange={(e) => setDraft({...draft,risk_expires_at:e.target.value})} /></label><label className="span-2">Обоснование<textarea required value={draft.risk_reason} onChange={(e) => setDraft({...draft,risk_reason:e.target.value})} /></label></> : null}
      <label className="span-2">Комментарий<textarea value={draft.comment} onChange={(e) => setDraft({...draft,comment:e.target.value})} /></label></div>
    <div className="action-row"><button className="button button--primary" onClick={() => onSave(Object.fromEntries(Object.entries(draft).map(([key,value]) => [key,value || null])))}>Сохранить</button>
      <button onClick={() => onNavigate("/asset-cards")}>Карточка актива</button>{item.passport_internal_id ? <button onClick={() => onNavigate("/passports")}>Паспорт</button> : null}</div>
    <h4>История</h4><ul className="audit-list">{(item.events || []).map((event) => <li key={event.event_id}><strong>{event.event_type}</strong> · {formatDate(event.created_at)}{event.comment ? <p>{event.comment}</p> : null}</li>)}</ul>
  </div>;
}

function PolicyEditor({ policy, setPolicy, onSaved, showAlert }) {
  const save = async (apply) => { try { await api("/api/remediation/policy", { method:"PUT", body:JSON.stringify({...policy,apply_to_open:apply}) }); showAlert("SLA-политика сохранена.","success"); onSaved(); } catch (error) { showAlert(error.operatorMessage || error.message,"error"); } };
  return <details className="settings-card"><summary>Настройка SLA</summary><div className="policy-grid">{["critical","high","medium","low"].map((severity) => <label key={severity}>{severity}<input type="number" min="1" value={policy[`${severity}_days`]} onChange={(e) => setPolicy({...policy,[`${severity}_days`]:Number(e.target.value)})} /> дней</label>)}<label>Скоро срок<input type="number" min="0" value={policy.near_due_days} onChange={(e) => setPolicy({...policy,near_due_days:Number(e.target.value)})} /> дней</label></div><div className="action-row"><button onClick={() => save(false)}>Сохранить для новых</button><button onClick={() => save(true)}>Сохранить и пересчитать открытые</button></div></details>;
}

function formatDate(value) { return value ? new Intl.DateTimeFormat("ru-RU", { dateStyle:"short", timeStyle:"short" }).format(new Date(value)) : "—"; }
function toInputDate(value) { if (!value) return ""; const date=new Date(value); return new Date(date.getTime()-date.getTimezoneOffset()*60000).toISOString().slice(0,16); }
