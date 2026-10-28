import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, createIdempotencyKey } from "../api/client.js";
import { Button, ConfirmDialog, Disclosure, Field, Panel } from "../shared/ui.jsx";

const EMPTY_RULE = () => ({ field_path: "asset.ipAddress", operator: "in_cidr", value: "" });
const EMPTY_QUERY = () => ({ combinator: "and", match_scope: "host", rules: [EMPTY_RULE()] });

export function AssetGroupsPage({ currentUser, showAlert }) {
  const queryClient = useQueryClient();
  const canManage = new Set(currentUser?.permissions || []).has("asset_groups.manage");
  const canRetryPrecheck = new Set(currentUser?.permissions || []).has("tasks.execute");
  const canExecuteTasks = canRetryPrecheck;
  const [selectedId, setSelectedId] = useState(() => typeof window === "undefined" ? null : new URLSearchParams(window.location.search).get("group"));
  const [search, setSearch] = useState("");
  const [archiveTarget, setArchiveTarget] = useState(null);
  const [form, setForm] = useState({ name: "", description: "", parent_id: "", query: EMPTY_QUERY() });
  const [preview, setPreview] = useState(null);
  const [manualAssetId, setManualAssetId] = useState("");
  const [selectedIds, setSelectedIds] = useState([]);
  const [bulkArchiveOpen, setBulkArchiveOpen] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);

  const groupsQuery = useQuery({ queryKey: ["asset-groups"], queryFn: () => api("/api/asset-groups/tree") });
  const precheckStatsQuery = useQuery({ queryKey: ["precheck-stats"], queryFn: () => api("/api/asset-groups/precheck-stats") });
  const precheckRunsQuery = useQuery({ queryKey: ["precheck-runs"], queryFn: () => api("/api/asset-groups/precheck-runs?limit=20") });
  const fieldsQuery = useQuery({ queryKey: ["asset-group-fields"], queryFn: () => api("/api/asset-card-query/fields?limit=500") });
  const membersQuery = useQuery({
    queryKey: ["asset-group-members", selectedId],
    queryFn: () => api(`/api/asset-groups/${encodeURIComponent(selectedId)}/members?limit=500`),
    enabled: Boolean(selectedId),
  });
  const roots = useMemo(() => groupsQuery.data?.rows || [], [groupsQuery.data]);
  const groups = useMemo(() => flattenGroups(roots), [roots]);
  const selected = groups.find((group) => group.group_id === selectedId) || null;
  const visibleRoots = useMemo(() => filterTree(roots, search), [roots, search]);
  const fields = fieldsQuery.data?.rows || [];

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ["asset-groups"] });
    await queryClient.invalidateQueries({ queryKey: ["asset-group-members"] });
  };
  const perform = (action, success) => async (...args) => {
    try {
      const result = await action(...args);
      if (success) showAlert(success, "success");
      return result;
    } catch (error) {
      showAlert(error.operatorMessage || error.message, "error");
      throw error;
    }
  };

  const previewMutation = useMutation({
    mutationFn: perform(() => api("/api/asset-groups/preview", {
      method: "POST",
      body: JSON.stringify({ query: form.query, limit: 20 }),
    })),
    onSuccess: setPreview,
  });
  const createMutation = useMutation({
    mutationFn: perform(() => api("/api/asset-groups", {
      method: "POST",
      body: JSON.stringify({ ...form, parent_id: form.parent_id || null }),
    }), "Группа создана и рассчитана."),
    onSuccess: async (group) => {
      setSelectedId(group.group_id);
      setForm({ name: "", description: "", parent_id: "", query: EMPTY_QUERY() });
      setPreview(null);
      await refresh();
    },
  });
  const evaluateMutation = useMutation({
    mutationFn: perform((groupId) => api(`/api/asset-groups/${encodeURIComponent(groupId)}/evaluate`, { method: "POST" }), "Состав группы пересчитан."),
    onSuccess: refresh,
  });
  const overrideMutation = useMutation({
    mutationFn: perform(({ groupId, assetId, action }) => api(
      `/api/asset-groups/${encodeURIComponent(groupId)}/overrides/${encodeURIComponent(assetId)}`,
      { method: "PUT", body: JSON.stringify({ action }) },
    ), "Изменение состава сохранено. Пересчитайте группу."),
    onSuccess: async () => {
      setManualAssetId("");
      await refresh();
    },
  });
  const archiveMutation = useMutation({
    mutationFn: perform((groupId) => api(`/api/asset-groups/${encodeURIComponent(groupId)}/archive`, { method: "POST" }), "Группа архивирована."),
    onSuccess: async () => {
      setArchiveTarget(null);
      setSelectedId(null);
      await refresh();
    },
  });
  const bulkMutation = useMutation({
    mutationFn: perform((action) => api("/api/asset-groups/bulk-action", {
      method: "POST",
      body: JSON.stringify({ group_ids: selectedIds, action }),
    })),
    onSuccess: async (result) => {
      showAlert(`Обработано: ${result.processed}; ошибок: ${result.failed}.`, result.failed ? "warning" : "success");
      setSelectedIds([]);
      setBulkArchiveOpen(false);
      await refresh();
    },
  });
  const retryFalseMutation = useMutation({
    mutationFn: perform((taskId) => api(`/api/scanner-tasks/${encodeURIComponent(taskId)}/retry-false`, { method: "POST" })),
    onSuccess: async (result) => {
      showAlert(`Повторено: ${result.requested_target_count}; недоступны: ${result.false_target_count}.`, result.false_target_count ? "warning" : "success");
      await queryClient.invalidateQueries({ queryKey: ["precheck-stats"] });
      await queryClient.invalidateQueries({ queryKey: ["precheck-runs"] });
    },
  });
  const groupWorkflowMutation = useMutation({
    mutationFn: perform(({ groupId, action }) => api(`/api/asset-groups/${encodeURIComponent(groupId)}/${action}`, {
      method: "POST",
      headers: { "X-Idempotency-Key": createIdempotencyKey(`asset-group-${action}`) },
      body: JSON.stringify({}),
    })),
    onSuccess: async (result, variables) => {
      const label = variables.action === "verify" ? "Проверка запущена" : "Сканирование запущено";
      showAlert(`${label}: ${result.asset_count || 0} активов.`, "success");
      await queryClient.invalidateQueries({ queryKey: ["vm-overview"] });
    },
  });
  const toggleSelected = (groupId) => setSelectedIds((current) => current.includes(groupId)
    ? current.filter((value) => value !== groupId) : [...current, groupId]);
  const stats = precheckStatsQuery.data || {};

  return (
    <div className="asset-groups-page">
      <Panel
        action={<div className="action-row">{canManage && selectedIds.length ? <><span className="selection-count">Выбрано: {selectedIds.length}</span><Button busy={bulkMutation.isPending} onClick={() => bulkMutation.mutate("evaluate")}>Пересчитать выбранные</Button><Button variant="danger" busy={bulkMutation.isPending} onClick={() => setBulkArchiveOpen(true)}>Архивировать выбранные</Button></> : null}{canManage ? <Button variant="secondary" onClick={() => setCreateOpen(true)}>+ Новая группа</Button> : null}<Button variant="secondary" busy={groupsQuery.isFetching} onClick={() => groupsQuery.refetch()}>Обновить</Button></div>}
      >
        <div className="asset-groups-layout">
          <section className="asset-groups-tree" aria-label="Иерархия групп активов">
            <input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Поиск групп" aria-label="Поиск групп" />
            <div className="asset-group-tree-list">
              {visibleRoots.map((group) => <GroupNode key={group.group_id} group={group} selectedId={selectedId} onSelect={setSelectedId} selectedIds={selectedIds} onToggle={toggleSelected} canManage={canManage} />)}
              {!groupsQuery.isLoading && !visibleRoots.length ? <p className="empty-cell">Групп пока нет.</p> : null}
            </div>
          </section>
          <section className="asset-group-details" aria-label="Сведения о группе">
            {selected ? (
              <GroupDetails
                group={selected}
                fields={fields}
                members={membersQuery.data}
                loading={membersQuery.isLoading}
                canManage={canManage}
                manualAssetId={manualAssetId}
                setManualAssetId={setManualAssetId}
                canExecuteTasks={canExecuteTasks}
                evaluating={evaluateMutation.isPending}
                overriding={overrideMutation.isPending}
                workflowBusy={groupWorkflowMutation.isPending}
                onEvaluate={() => evaluateMutation.mutate(selected.group_id)}
                onScan={() => groupWorkflowMutation.mutate({ groupId: selected.group_id, action: "scan" })}
                onVerify={() => groupWorkflowMutation.mutate({ groupId: selected.group_id, action: "verify" })}
                onExclude={(assetId) => overrideMutation.mutate({ groupId: selected.group_id, assetId, action: "exclude" })}
                onInclude={() => overrideMutation.mutate({ groupId: selected.group_id, assetId: manualAssetId.trim(), action: "include" })}
                onArchive={() => setArchiveTarget(selected)}
              />
            ) : <p className="empty-cell">Выберите группу.</p>}
          </section>
        </div>
      </Panel>

      <Disclosure
        className="precheck-summary"
        title="Проверка доступности"
        meta={stats.false ? `Недоступны: ${stats.false}` : null}
      >
        <div className="metric-grid precheck-metrics" aria-label="Статистика проверки доступности">
          <Metric label="Запуски" value={stats.runs} />
          <Metric label="Доступны" value={stats.success} />
          <Metric label="Недоступны" value={stats.false} />
          <Metric label="Без данных" value={stats.unknown} />
        </div>
        {(precheckRunsQuery.data?.rows || []).length ? <details className="precheck-false-runs"><summary>Недоступные хосты · {stats.false || 0}</summary><div>{precheckRunsQuery.data.rows.map((run) => <article key={run.mp_task_id || run.group_id}><div><strong>{run.name || run.mp_task_id}</strong><small>{formatDate(run.updated_at)} · {run.false_target_count || 0} целей</small><code>{(run.false_targets || []).join(", ")}</code></div>{canRetryPrecheck ? <Button variant="tiny" busy={retryFalseMutation.isPending} disabled={!run.retryable} onClick={() => retryFalseMutation.mutate(run.mp_task_id)}>Повторить недоступные</Button> : null}</article>)}</div></details> : null}
      </Disclosure>

      {canManage && createOpen ? (
        <Panel title="Новая динамическая группа" action={<Button variant="ghost" onClick={() => setCreateOpen(false)}>Отмена</Button>}>
          <div className="form-grid form-grid--two">
            <Field label="Название"><input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></Field>
            <Field label="Родительская группа">
              <select value={form.parent_id} onChange={(event) => setForm({ ...form, parent_id: event.target.value })}>
                <option value="">Без родителя</option>
                {groups.map((group) => <option value={group.group_id} key={group.group_id}>{group.name}</option>)}
              </select>
            </Field>
            <Field label="Описание" wide><input value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} /></Field>
          </div>
          <RuleBuilder query={form.query} fields={fields} onChange={(query) => { setForm({ ...form, query }); setPreview(null); }} />
          <div className="action-row">
            <Button variant="secondary" busy={previewMutation.isPending} onClick={() => previewMutation.mutate()}>Предпросмотр</Button>
            <Button busy={createMutation.isPending} disabled={!form.name.trim() || !validQuery(form.query)} onClick={() => createMutation.mutate()}>Создать группу</Button>
          </div>
          {preview ? <Preview result={preview} /> : null}
        </Panel>
      ) : null}

      <ConfirmDialog
        open={Boolean(archiveTarget)}
        title="Архивировать группу?"
        description="Группа исчезнет из рабочего дерева, но её определение и история останутся в базе."
        confirmLabel="Архивировать"
        requireText={archiveTarget?.name || ""}
        busy={archiveMutation.isPending}
        onClose={() => setArchiveTarget(null)}
        onConfirm={() => archiveMutation.mutate(archiveTarget.group_id)}
      />
      <ConfirmDialog
        open={bulkArchiveOpen}
        title={`Архивировать выбранные группы (${selectedIds.length})?`}
        description="Группы исчезнут из рабочего дерева, их определения и история останутся."
        confirmLabel="Архивировать"
        busy={bulkMutation.isPending}
        onClose={() => setBulkArchiveOpen(false)}
        onConfirm={() => bulkMutation.mutate("archive")}
      />
    </div>
  );
}

function RuleBuilder({ query, fields, onChange }) {
  const rules = query.rules || [];
  const updateRule = (index, next) => onChange({ ...query, rules: rules.map((rule, position) => position === index ? next : rule) });
  return (
    <fieldset className="asset-group-rules">
      <legend>Правило состава</legend>
      <label className="asset-group-combinator">
        <span>Объединение условий</span>
        <select value={query.combinator} onChange={(event) => onChange({ ...query, combinator: event.target.value })}>
          <option value="and">Все условия</option><option value="or">Любое условие</option>
        </select>
      </label>
      {rules.map((rule, index) => (
        <div className="asset-group-rule" key={index}>
          <label><span>Поле</span><select value={rule.field_path} onChange={(event) => updateRule(index, { ...rule, field_path: event.target.value, operator: defaultOperator(event.target.value) })}>{fieldOptions(fields, rule.field_path).map((field) => <option key={field.field_path} value={field.field_path}>{field.field_name || field.field_path}</option>)}</select></label>
          <label><span>Оператор</span><select value={rule.operator} onChange={(event) => updateRule(index, { ...rule, operator: event.target.value })}>{operatorOptions(rule.field_path).map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select></label>
          <label><span>Значение</span><input value={rule.value} onChange={(event) => updateRule(index, { ...rule, value: event.target.value })} placeholder={rule.operator === "in_cidr" ? "10.20.0.0/16" : "prod-"} /></label>
          <Button variant="tiny-danger" disabled={rules.length === 1} onClick={() => onChange({ ...query, rules: rules.filter((_, position) => position !== index) })}>Удалить</Button>
        </div>
      ))}
      <Button variant="tiny" disabled={rules.length >= 20} onClick={() => onChange({ ...query, rules: [...rules, EMPTY_RULE()] })}>Добавить условие</Button>
    </fieldset>
  );
}

function GroupDetails({ group, fields = [], members, loading, canManage, canExecuteTasks, manualAssetId, setManualAssetId, evaluating, overriding, workflowBusy, onEvaluate, onScan, onVerify, onExclude, onInclude, onArchive }) {
  const coverage = `${group.indexed_cards || 0} из ${group.total_cards || 0}`;
  const canRunGroupWorkflow = group.status === "ready" && Boolean(group.member_count);
  return <>
    <div className="asset-group-details__header"><div><span className={`asset-group-status is-${group.status}`}>{statusLabel(group.status)}</span><h3>{group.name}</h3></div>{canManage ? <Button variant="tiny-danger" onClick={onArchive}>Архивировать</Button> : null}</div>
    <dl className="asset-group-facts">
      <div><dt>Участники</dt><dd>{group.member_count || 0}</dd></div>
      <div><dt>Проиндексировано</dt><dd>{coverage}</dd></div>
      <div><dt>Пересчитана</dt><dd>{formatDate(group.last_evaluated_at)}</dd></div>
      <div><dt>Описание</dt><dd>{group.description || "Не задано"}</dd></div>
    </dl>
    <p className="asset-group-predicate">{describeQuery(group.query, fields)}</p>
    {group.last_error ? <p className="inline-error">{group.last_error}</p> : null}
    <div className="action-row">
      {canManage ? <Button busy={evaluating} onClick={onEvaluate}>Пересчитать</Button> : null}
      {canExecuteTasks ? <><Button variant="secondary" busy={workflowBusy} disabled={!canRunGroupWorkflow} onClick={onScan}>Сканировать группу</Button><Button variant="secondary" busy={workflowBusy} disabled={!canRunGroupWorkflow} onClick={onVerify}>Проверить устранение</Button></> : null}
      {canManage ? <><input value={manualAssetId} onChange={(event) => setManualAssetId(event.target.value)} placeholder="ID актива" aria-label="ID актива для включения" /><Button variant="secondary" busy={overriding} disabled={!manualAssetId.trim()} onClick={onInclude}>Включить вручную</Button></> : null}
    </div>
    <h4 className="asset-group-members-title">Состав · {members?.total || 0}</h4>
    {loading ? <p className="empty-cell">Загрузка состава...</p> : null}
    <div className="asset-group-member-list">{(members?.rows || []).map((member) => <article key={member.asset_id}><div><strong>{member.display_name || member.hostname || member.asset_id}</strong><small>{member.ip_address || "IP не указан"} · {member.os_name || "ОС не указана"}</small></div><span>{member.membership_source === "manual_include" ? "вручную" : "по правилу"}</span>{canManage ? <Button variant="tiny-danger" onClick={() => onExclude(member.asset_id)}>Исключить</Button> : null}</article>)}</div>
  </>;
}

function Preview({ result }) {
  return <section className="asset-group-preview"><strong>Совпало: {result.total}</strong><span>Проиндексировано: {result.indexed_cards} из {result.total_cards}</span><div>{(result.rows || []).map((row) => <article key={row.asset_id}><b>{row.display_name || row.asset_id}</b><small>{row.ip_address || row.fqdn || "Без адреса"}</small></article>)}</div></section>;
}

function GroupNode({ group, selectedId, onSelect, selectedIds, onToggle, canManage, level = 0 }) {
  return <div><div className="asset-group-node-row" style={{ "--tree-level": level }}>{canManage ? <input type="checkbox" checked={selectedIds.includes(group.group_id)} onChange={() => onToggle(group.group_id)} aria-label={`Выбрать группу ${group.name}`} /> : null}<button type="button" className={`asset-group-node asset-group-node--button${selectedId === group.group_id ? " is-selected" : ""}`} onClick={() => onSelect(group.group_id)}><span>{group.children?.length ? "▾" : "·"}</span><span><strong>{group.name}</strong><small>{group.member_count || 0} активов · {statusLabel(group.status)}</small></span></button></div>{(group.children || []).map((child) => <GroupNode key={child.group_id} group={child} selectedId={selectedId} onSelect={onSelect} selectedIds={selectedIds} onToggle={onToggle} canManage={canManage} level={level + 1} />)}</div>;
}

function Metric({ label, value }) { return <article className="metric-card"><span>{label}</span><strong>{value ?? 0}</strong></article>; }

function fieldOptions(fields, current) {
  const unique = [...new Map(fields.map((field) => [field.field_path, field])).values()];
  const known = unique.some((field) => field.field_path === current);
  return known || !current ? unique : [{ field_path: current, field_name: current }, ...unique];
}
function describeQuery(query, fields) {
  const rules = query?.rules || [];
  if (!rules.length) return "Правило не задано";
  const names = new Map(fields.map((field) => [field.field_path, field.field_name]));
  const joiner = query.combinator === "or" ? " или " : " и ";
  return rules.map((rule) => {
    const operator = operatorOptions(rule.field_path).find(([value]) => value === rule.operator)?.[1] || rule.operator;
    const value = Array.isArray(rule.value) ? rule.value.join(", ") : rule.value;
    return `${names.get(rule.field_path) || rule.field_path} ${operator} ${value}`;
  }).join(joiner);
}
function operatorOptions(fieldPath) { return fieldPath === "asset.ipAddress" ? [["in_cidr", "входит в подсеть"], ["equals", "равно"], ["in", "в списке"]] : [["contains", "содержит"], ["starts_with", "начинается с"], ["equals", "равно"], ["not_equals", "не равно"], ["in", "в списке"]]; }
function defaultOperator(fieldPath) { return fieldPath === "asset.ipAddress" ? "in_cidr" : "contains"; }
function validQuery(query) { return Boolean(query.rules?.length) && query.rules.every((rule) => rule.field_path && rule.operator && String(rule.value).trim()); }
function flattenGroups(groups) { return groups.flatMap((group) => [group, ...flattenGroups(group.children || [])]); }
function filterTree(groups, search) { const query = search.trim().toLocaleLowerCase("ru"); if (!query) return groups; return groups.flatMap((group) => { const children = filterTree(group.children || [], search); return group.name.toLocaleLowerCase("ru").includes(query) || children.length ? [{ ...group, children }] : []; }); }
function statusLabel(status) { return { ready: "актуальна", stale: "требует пересчёта", evaluating: "пересчитывается", error: "ошибка" }[status] || status; }
function formatDate(value) { if (!value) return "Ещё не рассчитывалась"; const date = new Date(value); return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ru-RU"); }
