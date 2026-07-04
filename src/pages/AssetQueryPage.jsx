import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client.js";
import { SortableHeader, useTableSort } from "../shared/table.jsx";
import { Button, Panel } from "../shared/ui.jsx";

const EMPTY_RULE = () => ({ field_path: "", operator: "equals", value: "" });
const EMPTY_GROUP = (depth = 0) => ({ combinator: "and", match_scope: depth ? "same_entity" : "host", rules: [EMPTY_RULE()] });
const PAGE_SIZE = 50;
const RESULT_COLUMNS = [
  ["display_name", "Хост"], ["ip_address", "IP-адрес"], ["fqdn", "FQDN"], ["os_name", "ОС"], ["last_seen", "Свежесть"],
];

export function AssetQueryPage({ runBusy, busy, showAlert }) {
  const [catalog, setCatalog] = useState([]);
  const [coverage, setCoverage] = useState({ indexed_cards: 0, total_cards: 0 });
  const [query, setQuery] = useState(EMPTY_GROUP());
  const [result, setResult] = useState({ rows: [], total: 0, offset: 0 });
  const [sort, toggleSort, setSort] = useTableSort("display_name", "asc");
  const [savedViews, setSavedViews] = useState([]);
  const [viewName, setViewName] = useState("");
  const [columns, setColumns] = useState(RESULT_COLUMNS.map(([key]) => key));
  const fieldMap = useMemo(() => new Map(catalog.map((item) => [item.field_path, item])), [catalog]);

  useEffect(() => {
    Promise.all([api("/api/asset-card-query/fields?limit=500"), api("/api/saved-views?route=asset-query")])
      .then(([fields, views]) => {
        setCatalog(fields.rows || []);
        setCoverage(fields);
        setSavedViews(views.rows || []);
      })
      .catch(() => null);
  }, []);

  const execute = async (offset = 0, nextSort = sort) => {
    const payload = { query, sort_by: nextSort.key, sort_dir: nextSort.direction, limit: PAGE_SIZE, offset };
    const response = await api("/api/asset-card-query", { method: "POST", body: JSON.stringify(payload) });
    setResult(response);
    setCoverage(response);
    return response;
  };

  const changeSort = (key, initialDirection = "asc") => {
    const next = { key, direction: sort.key === key ? (sort.direction === "asc" ? "desc" : "asc") : initialDirection };
    toggleSort(key, initialDirection);
    runBusy("assetQuery", () => execute(0, next));
  };

  const saveView = () => runBusy("assetQuerySave", async () => {
    if (!viewName.trim()) throw new Error("Введите название представления.");
    const saved = await api("/api/saved-views", {
      method: "POST",
      body: JSON.stringify({ route: "asset-query", name: viewName.trim(), filters: { query, sort, columns } }),
    });
    setSavedViews((items) => [...items.filter((item) => item.id !== saved.id), saved].sort((a, b) => a.name.localeCompare(b.name)));
    setViewName("");
    showAlert("Представление сохранено.", "success");
  });

  const exportCsv = () => runBusy("assetQueryExport", async () => {
    const response = await fetch("/api/asset-card-query/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query, sort_by: sort.key, sort_dir: sort.direction, limit: 50000, offset: 0 }),
    });
    if (!response.ok) throw new Error("Не удалось сформировать CSV.");
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = contentDispositionFilename(response.headers.get("content-disposition")) || "asset-query.csv";
    link.click();
    URL.revokeObjectURL(url);
  });

  const applyView = (id) => {
    const view = savedViews.find((item) => String(item.id) === id);
    if (!view) return;
    setQuery(view.filters?.query || EMPTY_GROUP());
    if (view.filters?.sort) setSort(view.filters.sort);
    if (Array.isArray(view.filters?.columns) && view.filters.columns.length) setColumns(view.filters.columns);
    setResult({ rows: [], total: 0, offset: 0 });
  };

  const incomplete = coverage.indexed_cards < coverage.total_cards;
  return (
    <Panel
      id="asset-query"
      eyebrow="07"
      title="Выборки по карточкам активов"
      description="Локальные выборки по firewall, сети, ОС и любым индексированным листовым полям карточки. Запросы к MP VM не выполняются."
      action={<Button busy={busy.assetQuery} onClick={() => runBusy("assetQuery", () => execute(0))}>Выполнить</Button>}
    >
      <div className={`index-coverage ${incomplete ? "index-coverage--warning" : ""}`}>
        <strong>{coverage.indexed_cards || 0} из {coverage.total_cards || 0}</strong>
        <span>{incomplete ? "Карточки ещё индексируются: результат может быть неполным." : "Все локальные карточки проиндексированы."}</span>
      </div>

      <QueryGroup group={query} depth={0} path={[]} onChange={setQuery} fieldMap={fieldMap} catalog={catalog} />

      <div className="asset-query-toolbar">
        <select value="" onChange={(event) => applyView(event.target.value)} aria-label="Сохранённые представления">
          <option value="">Сохранённые представления</option>
          {savedViews.map((view) => <option key={view.id} value={view.id}>{view.name}</option>)}
        </select>
        <input value={viewName} onChange={(event) => setViewName(event.target.value)} placeholder="Название представления" />
        <Button variant="secondary" busy={busy.assetQuerySave} onClick={saveView}>Сохранить</Button>
        <Button variant="secondary" busy={busy.assetQueryExport} onClick={exportCsv}>Скачать весь CSV</Button>
      </div>
      <div className="asset-query-columns" aria-label="Колонки результата">
        <span>Колонки:</span>{RESULT_COLUMNS.map(([key, label]) => (
          <label key={key}><input type="checkbox" checked={columns.includes(key)} onChange={() => setColumns((current) => current.includes(key) ? (current.length > 1 ? current.filter((item) => item !== key) : current) : [...current, key])} />{label}</label>
        ))}
      </div>

      <div className="asset-query-result-header"><strong>{result.total || 0} хостов</strong><span>В таблице показаны поля, доказавшие совпадение.</span></div>
      <div className="table-shell">
        <table className="asset-query-table">
          <thead><tr>
            {columns.includes("display_name") ? <SortableHeader column="display_name" sort={sort} onSort={changeSort}>Хост</SortableHeader> : null}
            {columns.includes("ip_address") ? <SortableHeader column="ip_address" sort={sort} onSort={changeSort}>IP-адрес</SortableHeader> : null}
            {columns.includes("fqdn") ? <SortableHeader column="fqdn" sort={sort} onSort={changeSort}>FQDN</SortableHeader> : null}
            {columns.includes("os_name") ? <SortableHeader column="os_name" sort={sort} onSort={changeSort}>ОС</SortableHeader> : null}
            {columns.includes("last_seen") ? <SortableHeader column="last_seen" sort={sort} onSort={changeSort} initialDirection="desc">Свежесть</SortableHeader> : null}
            <th>Совпадения</th>
          </tr></thead>
          <tbody>{result.rows?.length ? result.rows.map((row) => (
            <tr key={row.asset_id}>
              {columns.includes("display_name") ? <td><strong>{row.display_name || row.hostname || row.asset_id}</strong><code>{row.asset_id}</code></td> : null}
              {columns.includes("ip_address") ? <td>{row.ip_address || "—"}</td> : null}
              {columns.includes("fqdn") ? <td>{row.fqdn || "—"}</td> : null}
              {columns.includes("os_name") ? <td>{row.os_name || "—"}</td> : null}
              {columns.includes("last_seen") ? <td>{formatDate(row.last_seen)}</td> : null}
              <td><div className="query-evidence">{(row.matches || []).map((match, index) => (
                <span key={`${match.entity_path}-${match.field_path}-${index}`}><code>{match.entity_path}</code><b>{match.field_path}</b> = {String(match.value ?? "—")}</span>
              ))}</div></td>
            </tr>
          )) : <tr><td colSpan={columns.length + 1} className="empty-cell">Задайте правила и выполните выборку.</td></tr>}</tbody>
        </table>
      </div>
      <div className="passport-pagination">
        <Button variant="secondary" disabled={!result.offset} onClick={() => runBusy("assetQuery", () => execute(Math.max(0, result.offset - PAGE_SIZE)))}>Назад</Button>
        <span>{result.total ? `${result.offset + 1}–${Math.min(result.offset + PAGE_SIZE, result.total)} из ${result.total}` : "Нет результатов"}</span>
        <Button variant="secondary" disabled={result.offset + PAGE_SIZE >= result.total} onClick={() => runBusy("assetQuery", () => execute(result.offset + PAGE_SIZE))}>Далее</Button>
      </div>
    </Panel>
  );
}

function QueryGroup({ group, depth, path, onChange, fieldMap, catalog }) {
  const update = (patch) => onChange(updateAtPathRoot(group, path, (current) => ({ ...current, ...patch })));
  const updateRule = (index, rule) => onChange(updateAtPathRoot(group, path, (current) => ({ ...current, rules: current.rules.map((item, i) => i === index ? rule : item) })));
  const remove = (index) => onChange(updateAtPathRoot(group, path, (current) => ({ ...current, rules: current.rules.filter((_, i) => i !== index) })));
  const add = (item) => onChange(updateAtPathRoot(group, path, (current) => ({ ...current, rules: [...current.rules, item] })));
  return (
    <fieldset className="query-group">
      <legend>{depth ? `Группа уровня ${depth + 1}` : "Правила выборки"}</legend>
      <div className="query-group__controls">
        <label>Связь<select value={group.combinator} onChange={(event) => update({ combinator: event.target.value })}><option value="and">Все условия (AND)</option><option value="or">Любое условие (OR)</option></select></label>
        <label>Область<select value={group.match_scope} onChange={(event) => update({ match_scope: event.target.value })}><option value="host">В пределах хоста</option><option value="same_entity">В одном элементе коллекции</option></select></label>
        <span>{group.match_scope === "same_entity" ? "Например, порт и действие должны относиться к одному firewall-правилу." : "Условия могут совпасть в разных сущностях карточки."}</span>
      </div>
      <div className="query-group__rules">{group.rules.map((item, index) => item.field_path !== undefined ? (
        <QueryRule key={index} rule={item} onChange={(rule) => updateRule(index, rule)} onRemove={() => remove(index)} fieldMap={fieldMap} catalog={catalog} />
      ) : (
        <QueryGroup key={index} group={item} depth={depth + 1} path={[]} onChange={(next) => updateRule(index, next)} fieldMap={fieldMap} catalog={catalog} />
      ))}</div>
      <div className="query-group__actions">
        <Button variant="tiny" disabled={countRules(group) >= 20} onClick={() => add(EMPTY_RULE())}>Добавить правило</Button>
        <Button variant="tiny" disabled={depth >= 2 || countRules(group) >= 20} onClick={() => add(EMPTY_GROUP(depth + 1))}>Добавить группу</Button>
      </div>
    </fieldset>
  );
}

function QueryRule({ rule, onChange, onRemove, fieldMap, catalog }) {
  const field = fieldMap.get(rule.field_path);
  const operators = operatorsFor(field?.value_type);
  const needsValue = !["exists", "not_exists", "is_true", "is_false"].includes(rule.operator);
  return (
    <div className="query-rule">
      <label>Поле<input list="asset-query-fields" value={rule.field_path} onChange={(event) => onChange({ ...rule, field_path: event.target.value })} placeholder="Например, asset.firewall.rules.port" /></label>
      <datalist id="asset-query-fields">{catalog.map((item) => <option key={`${item.field_path}-${item.value_type}`} value={item.field_path}>{item.field_name} · {item.asset_count} хостов · {item.sample_value ?? item.value_type}</option>)}</datalist>
      <label>Оператор<select value={rule.operator} onChange={(event) => onChange({ ...rule, operator: event.target.value })}>{operators.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      <label>Значение<input disabled={!needsValue} type={field?.value_type === "number" ? "number" : "text"} value={needsValue ? rule.value : ""} onChange={(event) => onChange({ ...rule, value: event.target.value })} placeholder={field?.sample_value || "Значение"} /></label>
      <span className="query-rule__meta">{field ? `${field.value_type} · ${field.asset_count} хостов` : "Выберите индексированное поле"}</span>
      <Button variant="tiny-danger" onClick={onRemove}>Удалить</Button>
    </div>
  );
}

function updateAtPathRoot(root, path, updater) {
  if (!path.length) return updater(root);
  const [index, ...rest] = path;
  return { ...root, rules: root.rules.map((item, i) => i === index ? updateAtPathRoot(item, rest, updater) : item) };
}

function countRules(node) { return node.field_path !== undefined ? 1 : (node.rules || []).reduce((sum, item) => sum + countRules(item), 0); }
function operatorsFor(type) {
  if (type === "number") return [["equals", "равно"], ["not_equals", "не равно"], ["gt", ">"], ["gte", "≥"], ["lt", "<"], ["lte", "≤"], ["exists", "существует"], ["not_exists", "не существует"]];
  if (type === "boolean") return [["is_true", "истина"], ["is_false", "ложь"], ["exists", "существует"], ["not_exists", "не существует"]];
  return [["equals", "равно"], ["not_equals", "не равно"], ["contains", "содержит"], ["starts_with", "начинается с"], ["in", "в списке"], ["exists", "существует"], ["not_exists", "не существует"]];
}
function formatDate(value) { return value ? new Date(value).toLocaleString("ru-RU") : "—"; }
function contentDispositionFilename(value) { return value?.match(/filename="?([^";]+)"?/i)?.[1] || ""; }
