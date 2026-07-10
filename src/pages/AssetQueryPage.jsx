import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client.js";
import { SortableHeader, useTableSort } from "../shared/table.jsx";
import { Button, Panel } from "../shared/ui.jsx";

const EMPTY_RULE = () => ({ field_path: "", operator: "equals", value: "" });
const EMPTY_GROUP = (depth = 0) => ({
  combinator: "and",
  match_scope: depth ? "same_entity" : "host",
  rules: [EMPTY_RULE()],
});
const DEFAULT_SORT = { key: "display_name", direction: "asc" };
const PAGE_SIZE = 50;
const RESULT_COLUMNS = [
  ["display_name", "Хост"],
  ["ip_address", "IP-адрес"],
  ["fqdn", "FQDN"],
  ["os_name", "ОС"],
  ["last_seen", "Свежесть"],
];
const RESULT_COLUMN_KEYS = new Set(RESULT_COLUMNS.map(([key]) => key));

export function AssetQueryPage({ runBusy, busy, showAlert }) {
  const [catalog, setCatalog] = useState([]);
  const [coverage, setCoverage] = useState({
    indexed_cards: 0,
    total_cards: 0,
  });
  const [query, setQuery] = useState(EMPTY_GROUP());
  const [result, setResult] = useState({ rows: [], total: 0, offset: 0 });
  const [sort, toggleSort, setSort] = useTableSort(
    DEFAULT_SORT.key,
    DEFAULT_SORT.direction,
  );
  const [savedViews, setSavedViews] = useState([]);
  const [activeViewId, setActiveViewId] = useState("");
  const [viewName, setViewName] = useState("");
  const [columns, setColumns] = useState(RESULT_COLUMNS.map(([key]) => key));
  const fieldMap = useMemo(
    () => new Map(catalog.map((item) => [item.field_path, item])),
    [catalog],
  );
  const activeView = useMemo(
    () => savedViews.find((item) => String(item.id) === activeViewId) || null,
    [activeViewId, savedViews],
  );
  const activeViewChanged = useMemo(
    () =>
      Boolean(activeView) &&
      !sameViewSettings(activeView.filters, { query, sort, columns }),
    [activeView, columns, query, sort],
  );

  useEffect(() => {
    Promise.all([
      api("/api/asset-card-query/fields?limit=500"),
      api("/api/saved-views?route=asset-query"),
    ])
      .then(([fields, views]) => {
        setCatalog(fields.rows || []);
        setCoverage(fields);
        setSavedViews(views.rows || []);
      })
      .catch(() => null);
  }, []);

  const execute = async (offset = 0, nextSort = sort, nextQuery = query) => {
    const payload = {
      query: nextQuery,
      sort_by: nextSort.key,
      sort_dir: nextSort.direction,
      limit: PAGE_SIZE,
      offset,
    };
    const response = await api("/api/asset-card-query", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    setResult(response);
    setCoverage(response);
    return response;
  };

  const changeQuery = (nextQuery) => {
    setQuery(nextQuery);
    setResult({ rows: [], total: 0, offset: 0 });
  };

  const changeSort = (key, initialDirection = "asc") => {
    const next = {
      key,
      direction:
        sort.key === key
          ? sort.direction === "asc"
            ? "desc"
            : "asc"
          : initialDirection,
    };
    toggleSort(key, initialDirection);
    runBusy("assetQuery", () => execute(0, next));
  };

  const startNewView = () => {
    setActiveViewId("");
    setViewName("");
    setQuery(EMPTY_GROUP());
    setSort(DEFAULT_SORT);
    setColumns(RESULT_COLUMNS.map(([key]) => key));
    setResult({ rows: [], total: 0, offset: 0 });
  };

  const applyView = (id) => {
    const view = savedViews.find((item) => String(item.id) === id);
    if (!view) return;
    const nextQuery = normalizeQueryTree(view.filters?.query, fieldMap);
    const nextSort = normalizeSort(view.filters?.sort);
    const nextColumns = normalizeColumns(view.filters?.columns);
    setActiveViewId(String(view.id));
    setViewName(view.name);
    setQuery(nextQuery);
    setSort(nextSort);
    setColumns(nextColumns);
    setResult({ rows: [], total: 0, offset: 0 });
    runBusy("assetQuery", () => execute(0, nextSort, nextQuery));
  };

  const saveView = () =>
    runBusy("assetQuerySave", async () => {
      const name = viewName.trim();
      if (!name) throw new Error("Введите название выборки.");
      const saved = await api("/api/saved-views", {
        method: "POST",
        body: JSON.stringify({
          route: "asset-query",
          name,
          filters: { query, sort, columns },
        }),
      });
      setSavedViews((items) =>
        [...items.filter((item) => item.id !== saved.id), saved].sort((a, b) =>
          a.name.localeCompare(b.name, "ru"),
        ),
      );
      setActiveViewId(String(saved.id));
      setViewName(saved.name || name);
      showAlert(`Выборка «${saved.name || name}» сохранена.`, "success");
    });

  const deleteView = () => {
    if (!activeView) return;
    runBusy("assetQueryDelete", async () => {
      await api(`/api/saved-views/${encodeURIComponent(activeView.id)}`, {
        method: "DELETE",
      });
      setSavedViews((items) =>
        items.filter((item) => item.id !== activeView.id),
      );
      setActiveViewId("");
      setViewName("");
      showAlert(`Выборка «${activeView.name}» удалена.`, "success");
    });
  };

  const exportCsv = () =>
    runBusy("assetQueryExport", async () => {
      const response = await fetch("/api/asset-card-query/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query,
          sort_by: sort.key,
          sort_dir: sort.direction,
          limit: 50000,
          offset: 0,
        }),
      });
      if (!response.ok) throw new Error("Не удалось сформировать CSV.");
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download =
        contentDispositionFilename(
          response.headers.get("content-disposition"),
        ) || "asset-query.csv";
      link.click();
      URL.revokeObjectURL(url);
    });

  const incomplete = coverage.indexed_cards < coverage.total_cards;
  return (
    <Panel
      id="asset-query"
      eyebrow="07"
      title="Выборки по карточкам активов"
      description="Задайте понятные условия по данным локальных карточек. Запросы к MP VM при поиске не выполняются."
      action={
        <Button
          busy={busy.assetQuery}
          onClick={() => runBusy("assetQuery", () => execute(0))}
        >
          Показать активы
        </Button>
      }
    >
      <div
        className={`index-coverage ${incomplete ? "index-coverage--warning" : ""}`}
      >
        <strong>
          {coverage.indexed_cards || 0} из {coverage.total_cards || 0}
        </strong>
        <span>
          {incomplete
            ? "Карточки ещё индексируются: результат может быть неполным."
            : "Все локальные карточки готовы к поиску."}
        </span>
      </div>

      <section className="asset-query-view" aria-label="Управление выборкой">
        <div className="asset-query-view__picker">
          <label>
            <span>Сохранённая выборка</span>
            <select
              value={activeViewId}
              onChange={(event) => applyView(event.target.value)}
            >
              <option value="" disabled>
                Выберите выборку
              </option>
              {savedViews.map((view) => (
                <option key={view.id} value={view.id}>
                  {view.name}
                </option>
              ))}
            </select>
          </label>
          <div className="asset-query-view__actions">
            <Button variant="secondary" onClick={startNewView}>
              Новая выборка
            </Button>
            <Button
              variant="tiny-danger"
              disabled={!activeView}
              busy={busy.assetQueryDelete}
              onClick={deleteView}
            >
              Удалить выборку
            </Button>
          </div>
        </div>
        <div className="asset-query-view__save">
          <label>
            <span>Название выборки</span>
            <input
              value={viewName}
              onChange={(event) => setViewName(event.target.value)}
              placeholder="Например, Linux-серверы с открытым портом 443"
            />
          </label>
          <Button
            variant="secondary"
            busy={busy.assetQuerySave}
            onClick={saveView}
          >
            {activeView ? "Сохранить изменения" : "Сохранить выборку"}
          </Button>
          <span
            className={`asset-query-view__state ${activeViewChanged ? "is-dirty" : ""}`}
            aria-live="polite"
          >
            {activeView
              ? activeViewChanged
                ? "Есть несохранённые изменения"
                : `Активна выборка «${activeView.name}»`
              : "Новая выборка ещё не сохранена"}
          </span>
        </div>
      </section>

      <QueryGroup
        group={query}
        depth={0}
        onChange={changeQuery}
        fieldMap={fieldMap}
      />
      <datalist id="asset-query-fields">
        {catalog.map((item) => (
          <option
            key={`${item.field_path}-${item.value_type}`}
            value={item.field_path}
          >
            {item.field_name || friendlyFieldName(item.field_path)} ·{" "}
            {valueTypeLabel(item.value_type)} · {item.asset_count} активов
          </option>
        ))}
      </datalist>

      <div className="asset-query-result-options">
        <div className="asset-query-columns" aria-label="Колонки результата">
          <span>Показывать в таблице:</span>
          {RESULT_COLUMNS.map(([key, label]) => (
            <label key={key}>
              <input
                type="checkbox"
                checked={columns.includes(key)}
                onChange={() =>
                  setColumns((current) =>
                    current.includes(key)
                      ? current.length > 1
                        ? current.filter((item) => item !== key)
                        : current
                      : [...current, key],
                  )
                }
              />
              {label}
            </label>
          ))}
        </div>
        <Button
          variant="secondary"
          busy={busy.assetQueryExport}
          onClick={exportCsv}
        >
          Скачать CSV
        </Button>
      </div>

      <div className="asset-query-result-header">
        <strong>Найдено активов: {result.total || 0}</strong>
        <span>Подробности совпадения скрыты внутри каждой строки.</span>
      </div>
      <div className="table-shell">
        <table className="asset-query-table">
          <thead>
            <tr>
              {columns.includes("display_name") ? (
                <SortableHeader
                  column="display_name"
                  sort={sort}
                  onSort={changeSort}
                >
                  Хост
                </SortableHeader>
              ) : null}
              {columns.includes("ip_address") ? (
                <SortableHeader
                  column="ip_address"
                  sort={sort}
                  onSort={changeSort}
                >
                  IP-адрес
                </SortableHeader>
              ) : null}
              {columns.includes("fqdn") ? (
                <SortableHeader column="fqdn" sort={sort} onSort={changeSort}>
                  FQDN
                </SortableHeader>
              ) : null}
              {columns.includes("os_name") ? (
                <SortableHeader
                  column="os_name"
                  sort={sort}
                  onSort={changeSort}
                >
                  ОС
                </SortableHeader>
              ) : null}
              {columns.includes("last_seen") ? (
                <SortableHeader
                  column="last_seen"
                  sort={sort}
                  onSort={changeSort}
                  initialDirection="desc"
                >
                  Свежесть
                </SortableHeader>
              ) : null}
              <th>Совпадение</th>
            </tr>
          </thead>
          <tbody>
            {result.rows?.length ? (
              result.rows.map((row) => (
                <tr key={row.asset_id}>
                  {columns.includes("display_name") ? (
                    <td>
                      <strong>
                        {row.display_name || row.hostname || row.asset_id}
                      </strong>
                      <code>{row.asset_id}</code>
                    </td>
                  ) : null}
                  {columns.includes("ip_address") ? (
                    <td>{row.ip_address || "—"}</td>
                  ) : null}
                  {columns.includes("fqdn") ? <td>{row.fqdn || "—"}</td> : null}
                  {columns.includes("os_name") ? (
                    <td>{row.os_name || "—"}</td>
                  ) : null}
                  {columns.includes("last_seen") ? (
                    <td>{formatDate(row.last_seen)}</td>
                  ) : null}
                  <td>
                    <QueryEvidence matches={row.matches || []} />
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={columns.length + 1} className="empty-cell">
                  Задайте условия и нажмите «Показать активы».
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="passport-pagination">
        <Button
          variant="secondary"
          disabled={!result.offset}
          onClick={() =>
            runBusy("assetQuery", () =>
              execute(Math.max(0, result.offset - PAGE_SIZE)),
            )
          }
        >
          Назад
        </Button>
        <span>
          {result.total
            ? `${result.offset + 1}–${Math.min(result.offset + PAGE_SIZE, result.total)} из ${result.total}`
            : "Нет результатов"}
        </span>
        <Button
          variant="secondary"
          disabled={result.offset + PAGE_SIZE >= result.total}
          onClick={() =>
            runBusy("assetQuery", () => execute(result.offset + PAGE_SIZE))
          }
        >
          Далее
        </Button>
      </div>
    </Panel>
  );
}

function QueryGroup({
  group,
  depth,
  onChange,
  onRemove,
  canRemove = false,
  parentScope,
  fieldMap,
}) {
  const rules = group.rules || [];
  const updateRule = (index, rule) =>
    onChange({
      ...group,
      rules: rules.map((item, itemIndex) =>
        itemIndex === index ? rule : item,
      ),
    });
  const remove = (index) => {
    if (rules.length <= 1) return;
    onChange({
      ...group,
      rules: rules.filter((_, itemIndex) => itemIndex !== index),
    });
  };
  const add = (item) => onChange({ ...group, rules: [...rules, item] });
  const changeScope = (matchScope) => {
    const next = { ...group, match_scope: matchScope };
    onChange(
      matchScope === "same_entity"
        ? sanitizeSameEntityGroup(next, fieldMap)
        : next,
    );
  };
  return (
    <fieldset className={`query-group ${depth ? "query-group--nested" : ""}`}>
      <legend>{depth ? `Группа условий ${depth}` : "Условия выборки"}</legend>
      <div className="query-group__controls">
        <label>
          <span>Как объединять условия</span>
          <select
            value={group.combinator}
            onChange={(event) =>
              onChange({ ...group, combinator: event.target.value })
            }
          >
            <option value="and">Должны выполняться все</option>
            <option value="or">Достаточно одного</option>
          </select>
        </label>
        <label>
          <span>Где искать совпадения</span>
          <select
            value={group.match_scope}
            onChange={(event) => changeScope(event.target.value)}
          >
            <option value="host" disabled={parentScope === "same_entity"}>
              Во всей карточке актива
            </option>
            <option value="same_entity">В одной записи списка</option>
          </select>
        </label>
        <span className="query-group__hint">
          {group.match_scope === "same_entity"
            ? "Используйте этот режим, когда несколько условий должны относиться к одной записи, например к одному firewall-правилу."
            : "Условия могут находиться в разных разделах карточки одного актива."}
        </span>
      </div>
      <div className="query-group__rules">
        {rules.map((item, index) =>
          isRuleNode(item) ? (
            <QueryRule
              key={index}
              position={index + 1}
              rule={item}
              onChange={(rule) => updateRule(index, rule)}
              onRemove={() => remove(index)}
              canRemove={rules.length > 1}
              matchScope={group.match_scope}
              fieldMap={fieldMap}
            />
          ) : (
            <QueryGroup
              key={index}
              group={item}
              depth={depth + 1}
              onChange={(next) => updateRule(index, next)}
              onRemove={() => remove(index)}
              canRemove={rules.length > 1}
              parentScope={group.match_scope}
              fieldMap={fieldMap}
            />
          ),
        )}
      </div>
      <div className="query-group__actions">
        <Button
          variant="tiny"
          disabled={countRules(group) >= 20}
          onClick={() => add(EMPTY_RULE())}
        >
          Добавить условие
        </Button>
        <Button
          variant="tiny"
          disabled={depth >= 2 || countRules(group) >= 20}
          onClick={() => add(EMPTY_GROUP(depth + 1))}
        >
          Добавить группу условий
        </Button>
        {depth ? (
          <Button
            variant="tiny-danger"
            disabled={!canRemove}
            title={
              canRemove
                ? "Удалить эту группу"
                : "В родительской группе должно остаться хотя бы одно условие"
            }
            onClick={onRemove}
          >
            Удалить группу
          </Button>
        ) : null}
      </div>
    </fieldset>
  );
}

function QueryRule({
  rule,
  position,
  onChange,
  onRemove,
  canRemove,
  matchScope,
  fieldMap,
}) {
  const field = fieldMap.get(rule.field_path);
  const operators = operatorsFor(field?.value_type, matchScope);
  const safeOperator = operators.some(([value]) => value === rule.operator)
    ? rule.operator
    : operators[0][0];
  const needsValue = !["exists", "not_exists", "is_true", "is_false"].includes(
    safeOperator,
  );
  const changeField = (fieldPath) => {
    const nextField = fieldMap.get(fieldPath);
    if (!nextField) {
      onChange({ ...rule, field_path: fieldPath });
      return;
    }
    const nextOperators = operatorsFor(nextField.value_type, matchScope);
    const operator = nextOperators.some(([value]) => value === rule.operator)
      ? rule.operator
      : nextOperators[0][0];
    onChange({
      ...rule,
      field_path: fieldPath,
      operator,
      value:
        field && field.value_type !== nextField.value_type ? "" : rule.value,
    });
  };
  return (
    <div className="query-rule">
      <label>
        <span>Параметр актива {position}</span>
        <input
          list="asset-query-fields"
          value={rule.field_path}
          onChange={(event) => changeField(event.target.value)}
          placeholder="Начните вводить название или путь параметра"
        />
      </label>
      <label>
        <span>Сравнение {position}</span>
        <select
          value={safeOperator}
          onChange={(event) =>
            onChange({ ...rule, operator: event.target.value })
          }
        >
          {operators.map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
      </label>
      <label>
        <span>Значение {position}</span>
        <input
          disabled={!needsValue}
          type={field?.value_type === "number" ? "number" : "text"}
          value={needsValue ? rule.value : ""}
          onChange={(event) => onChange({ ...rule, value: event.target.value })}
          placeholder={valuePlaceholder(field, safeOperator)}
        />
      </label>
      <span className="query-rule__meta">
        {field
          ? `${field.field_name || friendlyFieldName(field.field_path)} · ${valueTypeLabel(field.value_type)} · в ${field.asset_count} активах`
          : "Выберите параметр из подсказок"}
      </span>
      <Button
        variant="tiny-danger"
        disabled={!canRemove}
        title={
          canRemove
            ? "Удалить условие"
            : "В группе должно остаться хотя бы одно условие"
        }
        aria-label={`Удалить условие ${position}`}
        onClick={onRemove}
      >
        Удалить
      </Button>
    </div>
  );
}

function QueryEvidence({ matches }) {
  if (!matches.length) return "—";
  return (
    <details className="query-evidence-details">
      <summary>
        {matches.length === 1
          ? "Почему актив найден"
          : `Почему актив найден · ${matches.length}`}
      </summary>
      <div className="query-evidence">
        {matches.map((match, index) => (
          <div key={`${match.entity_path}-${match.field_path}-${index}`}>
            <strong>
              {match.field_name || friendlyFieldName(match.field_path)}
            </strong>
            <span>{String(match.value ?? "—")}</span>
            <small>
              <code>{match.field_path}</code>
              {match.entity_path && match.entity_path !== match.field_path ? (
                <code>{match.entity_path}</code>
              ) : null}
            </small>
          </div>
        ))}
      </div>
    </details>
  );
}

function isRuleNode(node) {
  return Boolean(node) && Object.hasOwn(node, "field_path");
}

function normalizeQueryTree(node, fieldMap, depth = 0, parentScope) {
  if (!node || typeof node !== "object") return EMPTY_GROUP(depth);
  if (isRuleNode(node)) {
    const field = fieldMap.get(node.field_path);
    const operators = operatorsFor(field?.value_type, parentScope);
    const operator = operators.some(([value]) => value === node.operator)
      ? node.operator
      : operators[0][0];
    return { ...EMPTY_RULE(), ...node, operator };
  }
  const matchScope =
    parentScope === "same_entity"
      ? "same_entity"
      : ["host", "same_entity"].includes(node.match_scope)
        ? node.match_scope
        : depth
          ? "same_entity"
          : "host";
  const rawRules =
    Array.isArray(node.rules) && node.rules.length
      ? node.rules
      : [EMPTY_RULE()];
  return {
    combinator: node.combinator === "or" ? "or" : "and",
    match_scope: matchScope,
    rules: rawRules.map((item) =>
      normalizeQueryTree(item, fieldMap, depth + 1, matchScope),
    ),
  };
}

function sanitizeSameEntityGroup(group, fieldMap) {
  return {
    ...group,
    match_scope: "same_entity",
    rules: (group.rules || []).map((item) => {
      if (!isRuleNode(item)) return sanitizeSameEntityGroup(item, fieldMap);
      if (item.operator !== "not_exists") return item;
      const field = fieldMap.get(item.field_path);
      return {
        ...item,
        operator: operatorsFor(field?.value_type, "same_entity")[0][0],
      };
    }),
  };
}

function normalizeSort(value) {
  if (!value || typeof value !== "object" || !value.key) return DEFAULT_SORT;
  return {
    key: value.key,
    direction: value.direction === "desc" ? "desc" : "asc",
  };
}

function normalizeColumns(value) {
  if (!Array.isArray(value)) return RESULT_COLUMNS.map(([key]) => key);
  const allowed = value.filter((key) => RESULT_COLUMN_KEYS.has(key));
  return allowed.length ? allowed : RESULT_COLUMNS.map(([key]) => key);
}

function sameViewSettings(saved = {}, current) {
  return (
    JSON.stringify({
      query: saved?.query || EMPTY_GROUP(),
      sort: normalizeSort(saved?.sort),
      columns: normalizeColumns(saved?.columns),
    }) === JSON.stringify(current)
  );
}

function countRules(node) {
  return isRuleNode(node)
    ? 1
    : (node.rules || []).reduce((sum, item) => sum + countRules(item), 0);
}

function operatorsFor(type, matchScope = "host") {
  const existence = [
    ["exists", "заполнено"],
    ...(matchScope === "same_entity" ? [] : [["not_exists", "не заполнено"]]),
  ];
  if (type === "number") {
    return [
      ["equals", "равно"],
      ["not_equals", "не равно"],
      ["gt", "больше"],
      ["gte", "больше или равно"],
      ["lt", "меньше"],
      ["lte", "меньше или равно"],
      ...existence,
    ];
  }
  if (type === "boolean") {
    return [["is_true", "включено"], ["is_false", "выключено"], ...existence];
  }
  return [
    ["equals", "точно равно"],
    ["not_equals", "не равно"],
    ["contains", "содержит"],
    ["starts_with", "начинается с"],
    ["in", "одно из значений"],
    ...existence,
  ];
}

function valueTypeLabel(type) {
  return (
    {
      boolean: "да / нет",
      number: "число",
      text: "текст",
    }[type] || "текст"
  );
}

function valuePlaceholder(field, operator) {
  if (["exists", "not_exists", "is_true", "is_false"].includes(operator)) {
    return "Значение не требуется";
  }
  if (operator === "in") return "Перечислите значения через запятую";
  return String(field?.sample_value || "Введите значение");
}

function friendlyFieldName(path) {
  const value = String(path || "");
  return value.split(".").filter(Boolean).at(-1) || "Параметр";
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString("ru-RU") : "—";
}

function contentDispositionFilename(value) {
  return value?.match(/filename="?([^";]+)"?/i)?.[1] || "";
}
