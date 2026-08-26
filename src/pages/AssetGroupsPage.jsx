import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client.js";
import { Button, ConfirmDialog, Field, Panel } from "../shared/ui.jsx";

const ROOT_GROUP_ID = "00000000-0000-0000-0000-000000000002";

export function AssetGroupsPage({ currentUser, showAlert }) {
  const queryClient = useQueryClient();
  const permissions = new Set(currentUser?.permissions || []);
  const canManage = permissions.has("asset_groups.manage");
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState(null);
  const [expanded, setExpanded] = useState(() => new Set());
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [form, setForm] = useState({
    name: "",
    description: "",
    predicate: "",
    parent_id: ROOT_GROUP_ID,
  });

  const groupsQuery = useQuery({
    queryKey: ["asset-groups"],
    queryFn: () => api("/api/asset-groups"),
  });
  const roots = useMemo(() => groupsQuery.data?.rows || [], [groupsQuery.data]);
  const allGroups = useMemo(() => flattenGroups(roots), [roots]);
  const selected = allGroups.find((item) => groupId(item) === selectedId) || null;
  const visibleRoots = useMemo(() => filterTree(roots, search), [roots, search]);

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["asset-groups"] });
  const createMutation = useMutation({
    mutationFn: () => api("/api/asset-groups", {
      method: "POST",
      body: JSON.stringify({
        ...form,
        description: form.description.trim() || null,
      }),
    }),
    onSuccess: async (result) => {
      setForm({ name: "", description: "", predicate: "", parent_id: ROOT_GROUP_ID });
      setSelectedId(result.id);
      await refresh();
      showAlert("Группа активов создана в MP VM.", "success");
    },
    onError: (error) => showAlert(error.operatorMessage || error.message, "error"),
  });
  const deleteMutation = useMutation({
    mutationFn: (group) => api(`/api/asset-groups/${encodeURIComponent(groupId(group))}/delete`, {
      method: "POST",
      body: JSON.stringify({ confirm_name: groupName(group) }),
    }),
    onSuccess: async () => {
      setSelectedId(null);
      setDeleteTarget(null);
      await refresh();
      showAlert("Группа активов удалена из MP VM.", "success");
    },
    onError: (error) => showAlert(error.operatorMessage || error.message, "error"),
  });

  const toggle = (id) => setExpanded((current) => {
    const next = new Set(current);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    return next;
  });
  const selectParent = (group) => {
    const id = groupId(group);
    setForm((current) => ({ ...current, parent_id: id }));
    showAlert(`Родительская группа выбрана: ${groupName(group)}`, "success");
  };

  return (
    <div className="asset-groups-page">
      <Panel
        title="Группы активов MP VM"
        description="Иерархия групп из MP VM. Выберите узел для просмотра или создайте динамическую группу по predicate."
        action={<Button variant="secondary" busy={groupsQuery.isFetching} onClick={() => groupsQuery.refetch()}>Обновить</Button>}
      >
        <div className="asset-groups-layout">
          <section className="asset-groups-tree" aria-label="Иерархия групп активов">
            <input
              type="search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Поиск по имени или ID"
              aria-label="Поиск групп"
            />
            {groupsQuery.isLoading ? <p className="empty-cell">Загрузка групп...</p> : null}
            {groupsQuery.isError ? <p className="inline-error" role="alert">{groupsQuery.error.message}</p> : null}
            {!groupsQuery.isLoading && !visibleRoots.length ? <p className="empty-cell">Группы не найдены.</p> : null}
            <div className="asset-group-tree-list">
              {visibleRoots.map((group) => (
                <GroupNode
                  key={groupId(group)}
                  group={group}
                  level={0}
                  selectedId={selectedId}
                  expanded={expanded}
                  forceOpen={Boolean(search.trim())}
                  onToggle={toggle}
                  onSelect={setSelectedId}
                />
              ))}
            </div>
          </section>

          <section className="asset-group-details" aria-label="Сведения о группе">
            {selected ? (
              <>
                <div className="asset-group-details__header">
                  <div>
                    <span>{groupType(selected)}</span>
                    <h3>{groupName(selected)}</h3>
                  </div>
                  {canManage ? <Button variant="tiny-danger" onClick={() => setDeleteTarget(selected)}>Удалить</Button> : null}
                </div>
                <dl className="asset-group-facts">
                  <div><dt>ID</dt><dd>{groupId(selected)}</dd></div>
                  <div><dt>Дочерние группы</dt><dd>{groupChildren(selected).length}</dd></div>
                  <div><dt>Описание</dt><dd>{selected.description || "Не задано"}</dd></div>
                </dl>
                {selected.predicate ? <pre className="asset-group-predicate">{selected.predicate}</pre> : null}
                {canManage ? <Button variant="secondary" onClick={() => selectParent(selected)}>Создать внутри этой группы</Button> : null}
              </>
            ) : <p className="empty-cell">Выберите группу в иерархии.</p>}
          </section>
        </div>
      </Panel>

      {canManage ? (
        <Panel title="Новая динамическая группа" description="Predicate отправляется в MP VM без преобразования.">
          <div className="form-grid form-grid--two">
            <Field label="Название">
              <input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} />
            </Field>
            <Field label="Родительская группа">
              <select value={form.parent_id} onChange={(event) => setForm({ ...form, parent_id: event.target.value })}>
                <option value={ROOT_GROUP_ID}>Корневая группа активов</option>
                {allGroups.map((group) => <option value={groupId(group)} key={groupId(group)}>{groupName(group)}</option>)}
              </select>
            </Field>
            <Field label="Описание" wide>
              <input value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} />
            </Field>
            <Field label="Predicate" wide>
              <textarea rows="5" value={form.predicate} onChange={(event) => setForm({ ...form, predicate: event.target.value })} placeholder="(ImageSet)" />
            </Field>
          </div>
          <div className="action-row">
            <Button
              busy={createMutation.isPending}
              disabled={!form.name.trim() || !form.predicate.trim()}
              onClick={() => createMutation.mutate()}
            >Создать группу</Button>
          </div>
        </Panel>
      ) : null}

      <ConfirmDialog
        open={Boolean(deleteTarget)}
        title="Удалить группу активов?"
        description="Группа будет удалена непосредственно из MP VM. Активы при этом не удаляются."
        impact={["Операция изменяет иерархию групп MP VM."]}
        confirmLabel="Удалить группу"
        requireText={deleteTarget ? groupName(deleteTarget) : ""}
        busy={deleteMutation.isPending}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => deleteMutation.mutate(deleteTarget)}
      />
    </div>
  );
}

function GroupNode({ group, level, selectedId, expanded, forceOpen, onToggle, onSelect }) {
  const id = groupId(group);
  const children = groupChildren(group);
  const open = forceOpen || expanded.has(id);
  return (
    <div>
      <div className={`asset-group-node${selectedId === id ? " is-selected" : ""}`} style={{ "--tree-level": level }}>
        <button
          type="button"
          className="asset-group-node__toggle"
          disabled={!children.length}
          aria-label={open ? "Свернуть группу" : "Развернуть группу"}
          onClick={() => onToggle(id)}
        >{children.length ? (open ? "−" : "+") : "·"}</button>
        <button type="button" className="asset-group-node__label" onClick={() => onSelect(id)}>
          <strong>{groupName(group)}</strong>
          <small>{groupType(group)} · {id}</small>
        </button>
      </div>
      {open ? children.map((child) => (
        <GroupNode key={groupId(child)} group={child} level={level + 1} selectedId={selectedId} expanded={expanded} forceOpen={forceOpen} onToggle={onToggle} onSelect={onSelect} />
      )) : null}
    </div>
  );
}

function groupId(group) { return String(group?.id || group?.groupId || ""); }
function groupName(group) { return String(group?.name || group?.displayName || groupId(group) || "Без имени"); }
function groupType(group) { return String(group?.groupType || group?.type || "group"); }
function groupChildren(group) { return Array.isArray(group?.children) ? group.children.filter(Boolean) : []; }
function flattenGroups(groups) { return groups.flatMap((group) => [group, ...flattenGroups(groupChildren(group))]); }
function filterTree(groups, search) {
  const query = search.trim().toLocaleLowerCase("ru");
  if (!query) return groups;
  return groups.flatMap((group) => {
    const children = filterTree(groupChildren(group), search);
    const matches = `${groupName(group)} ${groupId(group)}`.toLocaleLowerCase("ru").includes(query);
    return matches || children.length ? [{ ...group, children }] : [];
  });
}
