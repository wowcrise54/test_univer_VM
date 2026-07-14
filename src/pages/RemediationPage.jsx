import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client.js";

const statusLabels = {
  open: "Открыта", in_progress: "В работе", risk_accepted: "Риск принят",
  false_positive: "Ложное срабатывание", resolved: "Устранена",
};

export function RemediationPage({ showAlert }) {
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

  useEffect(() => {
    const caseId = typeof window === "undefined" ? null : new URLSearchParams(window.location.search).get("case");
    if (!caseId) return;
    api(`/api/remediation/cases/${encodeURIComponent(caseId)}`).then(setSelected).catch((nextError) =>
      showAlert(nextError.operatorMessage || nextError.message, "error"));
  }, [showAlert]);

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
    <RiskWorkspace showAlert={showAlert} onRefresh={load} />
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
    {selected ? <CaseEditor item={selected} onClose={() => setSelected(null)} onSave={updateCase} /> : null}
    {policy ? <PolicyEditor policy={policy} setPolicy={setPolicy} onSaved={load} showAlert={showAlert} /> : null}
  </section>;
}

function RiskWorkspace({ showAlert, onRefresh }) {
  const [data, setData] = useState({ rows: [], total: 0 });
  const [summary, setSummary] = useState({});
  const [campaigns, setCampaigns] = useState([]);
  const [level, setLevel] = useState("");
  const [checked, setChecked] = useState([]);
  const [context, setContext] = useState({ criticality: "medium", environment: "production", exposure: "internal" });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const suffix = level ? `?level=${level}` : "";
      const [queue, totals, campaignData] = await Promise.all([
        api(`/api/risk/queue${suffix}`), api("/api/risk/summary"), api("/api/remediation/campaigns"),
      ]);
      setData(queue); setSummary(totals); setCampaigns(campaignData.rows || []);
      setChecked((value) => value.filter((id) => (queue.rows || []).some((row) => row.case_id === id)));
    } catch (error) {
      setError(error.code === "DATABASE_UNAVAILABLE"
        ? "Модуль приоритизации ещё не подготовлен в PostgreSQL. Примените миграции и повторите загрузку."
        : error.operatorMessage || error.message);
    }
    finally { setLoading(false); }
  }, [level]);
  useEffect(() => { load(); }, [load]);
  const createCampaign = async () => {
    const name = window.prompt("Название кампании");
    if (!name) return;
    try {
      await api("/api/remediation/campaigns", { method: "POST", body: JSON.stringify({ name, case_ids: checked }) });
      setChecked([]); showAlert("Кампания создана.", "success"); await load(); await onRefresh();
    } catch (error) { showAlert(error.operatorMessage || error.message, "error"); }
  };
  const updateContext = async () => {
    const assetIds = [...new Set((data.rows || []).filter((row) => checked.includes(row.case_id)).map((row) => row.asset_id))];
    if (!assetIds.length) return;
    try {
      await api("/api/assets/context", { method: "PATCH", body: JSON.stringify({ asset_ids: assetIds, values: context }) });
      showAlert(`Контекст обновлён для активов: ${assetIds.length}.`, "success"); await load();
    } catch (error) { showAlert(error.operatorMessage || error.message, "error"); }
  };
  const importContext = async (event) => {
    const file = event.target.files?.[0]; if (!file) return;
    try {
      const result = await api("/api/assets/context/import", { method: "POST", body: JSON.stringify({ csv_text: await file.text() }) });
      showAlert(`CSV обработан: сопоставлено ${result.matched}, не найдено ${result.unmatched?.length || 0}.`, result.errors?.length ? "warning" : "success"); await load();
    } catch (error) { showAlert(error.operatorMessage || error.message, "error"); }
    finally { event.target.value = ""; }
  };
  return <section className="risk-workspace" aria-label="Приоритет риска">
    <div className="risk-workspace__header"><div><h3>Приоритетная очередь</h3><p>Локальная модель {summary.risk_model_version || "local-risk-v1"}: критичность актива, доступность, CVSS, возраст и SLA.</p></div>
      <select aria-label="Уровень риска" value={level} onChange={(event) => setLevel(event.target.value)}><option value="">Все уровни</option><option value="urgent">Срочный</option><option value="high">Высокий</option><option value="medium">Средний</option><option value="low">Низкий</option></select></div>
    {error ? <div className="inline-error" role="alert">{error} <button onClick={load}>Повторить</button></div> : null}
    <div className="metric-grid risk-metrics"><Metric label="Срочно" value={summary.urgent} danger /><Metric label="Высокий" value={summary.high} /><Metric label="Средний" value={summary.medium} /><Metric label="Низкий" value={summary.low} /></div>
    <div className="risk-context-controls"><select aria-label="Критичность актива" value={context.criticality} onChange={(event) => setContext({...context,criticality:event.target.value})}><option value="critical">Критичный</option><option value="high">Высокий</option><option value="medium">Средний</option><option value="low">Низкий</option></select><select aria-label="Среда" value={context.environment} onChange={(event) => setContext({...context,environment:event.target.value})}><option value="production">Production</option><option value="test">Test</option><option value="development">Development</option></select><select aria-label="Доступность" value={context.exposure} onChange={(event) => setContext({...context,exposure:event.target.value})}><option value="external">Внешний</option><option value="internal">Внутренний</option><option value="isolated">Изолированный</option></select><button disabled={!checked.length} onClick={updateContext}>Применить к активам</button><label className="button button--secondary">Импорт контекста CSV<input hidden type="file" accept=".csv,text/csv" onChange={importContext} /></label></div>
    <div className="action-row"><button disabled={!checked.length} onClick={createCampaign}>Создать кампанию ({checked.length})</button><span>Найдено: {data.total || 0}</span></div>
    <div className="table-shell"><table><thead><tr><th></th><th>Риск</th><th>Уязвимость</th><th>Актив</th><th>Контекст</th><th>Почему</th></tr></thead><tbody>
      {loading ? <tr><td colSpan="6" className="empty-cell">Расчёт приоритета…</td></tr> : (data.rows || []).map((row) => <tr key={row.case_id}>
        <td><input type="checkbox" aria-label={`Выбрать ${row.cve || row.title}`} checked={checked.includes(row.case_id)} onChange={(event) => setChecked(event.target.checked ? [...checked,row.case_id] : checked.filter((id) => id !== row.case_id))} /></td>
        <td><strong className={`risk-score risk-score--${row.risk_level}`}>{row.risk_score}</strong><small>{row.risk_level}</small></td><td>{row.cve || row.title}<small>{row.severity} · CVSS {row.cvss_score ?? "—"}</small></td>
        <td>{row.display_name || row.asset_id}<small>{row.ip_address || row.fqdn}</small></td><td>{row.criticality} · {row.environment}<small>{row.exposure} · {row.owner || "владелец не указан"}</small></td><td><small>{row.risk_explanation}</small></td>
      </tr>)}</tbody></table></div>
    {campaigns.length ? <details className="settings-card"><summary>Кампании устранения ({campaigns.length})</summary><div className="campaign-grid">{campaigns.map((item) => <article key={item.campaign_id}><strong>{item.name}</strong><span>{item.resolved}/{item.total} подтверждено</span><small>В работе: {item.in_progress} · просрочено: {item.overdue} · риск принят: {item.risk_accepted}</small></article>)}</div></details> : null}
  </section>;
}

function Metric({ label, value, danger }) { return <article className={`metric-card${danger ? " metric-card--danger" : ""}`}><span>{label}</span><strong>{value ?? 0}</strong></article>; }

function CaseEditor({ item, onClose, onSave }) {
  const [draft, setDraft] = useState({ status: item.status, assignee: item.assignee || "", due_at: toInputDate(item.due_at), exception_reason: item.exception_reason || item.risk_reason || "", exception_expires_at: toInputDate(item.exception_expires_at || item.risk_expires_at), comment: "" });
  return <div className="detail-card remediation-detail"><header><div><h3>{item.cve || item.title}</h3><p>{item.display_name || item.asset_id}</p></div><button onClick={onClose}>Закрыть</button></header>
    <div className="form-grid"><label>Статус<select value={draft.status} onChange={(e) => setDraft({...draft,status:e.target.value})}>{Object.entries(statusLabels).filter(([value]) => value !== "resolved").map(([value,label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      <label>Ответственный<input value={draft.assignee} onChange={(e) => setDraft({...draft,assignee:e.target.value})} /></label>
      <label>Срок<input type="datetime-local" value={draft.due_at} onChange={(e) => setDraft({...draft,due_at:e.target.value})} /></label>
      {["risk_accepted", "false_positive"].includes(draft.status) ? <><label>Исключение действует до<input required type="datetime-local" value={draft.exception_expires_at} onChange={(e) => setDraft({...draft,exception_expires_at:e.target.value})} /></label><label className="span-2">Обоснование исключения<textarea required value={draft.exception_reason} onChange={(e) => setDraft({...draft,exception_reason:e.target.value})} /></label></> : null}
      <label className="span-2">Комментарий<textarea value={draft.comment} onChange={(e) => setDraft({...draft,comment:e.target.value})} /></label></div>
    <div className="action-row"><button className="button button--primary" onClick={() => onSave(Object.fromEntries(Object.entries(draft).map(([key,value]) => [key,value || null])))}>Сохранить</button>
      <a className="button secondary" href={`/asset-cards?asset=${encodeURIComponent(item.asset_id)}`}>Карточка актива</a>{item.passport_internal_id ? <a className="button secondary" href={`/passports?passport=${encodeURIComponent(item.passport_internal_id)}`}>Паспорт</a> : null}{item.verification_workflow_id ? <a className="button secondary" href={`/vm?workflow=${encodeURIComponent(item.verification_workflow_id)}`}>Проверка</a> : null}</div>
    <h4>История</h4><ul className="audit-list">{(item.events || []).map((event) => <li key={event.event_id}><strong>{event.event_type}</strong> · {formatDate(event.created_at)}{event.comment ? <p>{event.comment}</p> : null}</li>)}</ul>
  </div>;
}

function PolicyEditor({ policy, setPolicy, onSaved, showAlert }) {
  const save = async (apply) => { try { await api("/api/remediation/policy", { method:"PUT", body:JSON.stringify({...policy,apply_to_open:apply}) }); showAlert("SLA-политика сохранена.","success"); onSaved(); } catch (error) { showAlert(error.operatorMessage || error.message,"error"); } };
  return <details className="settings-card"><summary>Настройка SLA</summary><div className="policy-grid">{["critical","high","medium","low"].map((severity) => <label key={severity}>{severity}<input type="number" min="1" value={policy[`${severity}_days`]} onChange={(e) => setPolicy({...policy,[`${severity}_days`]:Number(e.target.value)})} /> дней</label>)}<label>Скоро срок<input type="number" min="0" value={policy.near_due_days} onChange={(e) => setPolicy({...policy,near_due_days:Number(e.target.value)})} /> дней</label></div><div className="action-row"><button onClick={() => save(false)}>Сохранить для новых</button><button onClick={() => save(true)}>Сохранить и пересчитать открытые</button></div></details>;
}

function formatDate(value) { return value ? new Intl.DateTimeFormat("ru-RU", { dateStyle:"short", timeStyle:"short" }).format(new Date(value)) : "—"; }
function toInputDate(value) { if (!value) return ""; const date=new Date(value); return new Date(date.getTime()-date.getTimezoneOffset()*60000).toISOString().slice(0,16); }
