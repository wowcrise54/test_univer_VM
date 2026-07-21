import { useEffect, useMemo, useState } from "react";
import { api } from "../../api/client.js";

const EMPTY_USER = { username: "", display_name: "", password: "", role_ids: [] };

export function UsersPage({ currentUser, showAlert }) {
  const [tab, setTab] = useState(() => currentUser?.permissions?.includes("security.users.read") ? "users" : currentUser?.permissions?.includes("security.roles.read") ? "roles" : "audit");
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);
  const [permissions, setPermissions] = useState([]);
  const [audit, setAudit] = useState([]);
  const [form, setForm] = useState(EMPTY_USER);
  const canReadUsers = currentUser?.permissions?.includes("security.users.read");
  const canReadRoles = currentUser?.permissions?.includes("security.roles.read");
  const canReadAudit = currentUser?.permissions?.includes("security.audit.read");

  const load = async () => {
    const [userData, roleData, permissionData] = await Promise.all([
      canReadUsers ? api("/api/auth/users") : Promise.resolve({ rows: [] }),
      canReadRoles ? api("/api/auth/roles") : Promise.resolve({ rows: [] }),
      canReadRoles ? api("/api/auth/permissions") : Promise.resolve({ rows: [] }),
    ]);
    setUsers(userData.rows || []); setRoles(roleData.rows || []); setPermissions(permissionData.rows || []);
  };
  useEffect(() => { load().catch((error) => showAlert(error.operatorMessage || error.message, "error")); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (tab === "audit" && canReadAudit) api("/api/auth/audit?limit=200").then((value) => setAudit(value.rows || [])).catch((error) => showAlert(error.operatorMessage || error.message, "error"));
  }, [tab, canReadAudit, showAlert]);

  const mutate = async (request, success) => {
    try { await request(); await load(); if (success) showAlert(success, "success"); }
    catch (error) { showAlert(error.operatorMessage || error.message, "error"); }
  };

  if (!canReadUsers && !canReadRoles && !canReadAudit) return <section className="panel"><p>Недостаточно прав.</p></section>;
  return <section className="panel users-page">
    <div className="panel__header"><div><h2>Доступ к приложению</h2><p>Пользователи могут иметь несколько ролей; их разрешения объединяются.</p></div></div>
    <nav className="access-tabs" aria-label="Управление доступом">
      {canReadUsers ? <button className={tab === "users" ? "is-active" : ""} onClick={() => setTab("users")}>Пользователи</button> : null}
      {canReadRoles ? <button className={tab === "roles" ? "is-active" : ""} onClick={() => setTab("roles")}>Роли</button> : null}
      {canReadAudit ? <button className={tab === "audit" ? "is-active" : ""} onClick={() => setTab("audit")}>Аудит</button> : null}
    </nav>
    {tab === "users" && canReadUsers ? <UsersTab users={users} roles={roles} form={form} setForm={setForm} currentUser={currentUser} mutate={mutate} /> : null}
    {tab === "roles" && canReadRoles ? <RolesTab roles={roles} permissions={permissions} canManage={currentUser.permissions.includes("security.roles.manage")} mutate={mutate} /> : null}
    {tab === "audit" && canReadAudit ? <AuditTab rows={audit} /> : null}
  </section>;
}

function UsersTab({ users, roles, form, setForm, currentUser, mutate }) {
  const canManage = currentUser.permissions.includes("security.users.manage");
  const create = (event) => {
    event.preventDefault();
    mutate(() => api("/api/auth/users", { method: "POST", body: JSON.stringify(form) }), "Пользователь создан.");
    setForm(EMPTY_USER);
  };
  const selectedIds = (event) => [...event.target.selectedOptions].map((item) => Number(item.value));
  return <div className="access-tab-panel">
    {canManage ? <form className="user-create-form" onSubmit={create}>
      <label><span>Логин</span><input value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} required minLength="3" /></label>
      <label><span>Имя</span><input value={form.display_name} onChange={(event) => setForm({ ...form, display_name: event.target.value })} required /></label>
      <label><span>Пароль</span><input type="password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} required minLength="12" autoComplete="new-password" /></label>
      <label><span>Роли</span><select multiple value={form.role_ids.map(String)} onChange={(event) => setForm({ ...form, role_ids: selectedIds(event) })}>{roles.map((role) => <option key={role.id} value={role.id}>{role.name}</option>)}</select></label>
      <button type="submit" disabled={!form.role_ids.length}>Создать</button>
    </form> : null}
    <div className="table-shell"><table><thead><tr><th>Пользователь</th><th>Роли</th><th>Состояние</th><th>Последний вход</th><th></th></tr></thead><tbody>{users.map((user) => <tr key={user.id}>
      <td><strong>{user.display_name}</strong><small>{user.username}</small></td>
      <td><select multiple disabled={!canManage || user.id === currentUser.id} value={(user.roles || []).map((role) => String(role.id))} onChange={(event) => mutate(() => api(`/api/auth/users/${user.id}`, { method: "PATCH", body: JSON.stringify({ role_ids: selectedIds(event) }) }))}>{roles.map((role) => <option key={role.id} value={role.id}>{role.name}</option>)}</select></td>
      <td>{user.is_active ? "Активен" : "Отключён"}</td><td>{user.last_login_at ? new Date(user.last_login_at).toLocaleString("ru-RU") : "—"}</td>
      <td>{canManage ? <button type="button" disabled={user.id === currentUser.id} onClick={() => mutate(() => api(`/api/auth/users/${user.id}`, { method: "PATCH", body: JSON.stringify({ is_active: !user.is_active }) }))}>{user.is_active ? "Отключить" : "Включить"}</button> : null}</td>
    </tr>)}</tbody></table></div>
  </div>;
}

function RolesTab({ roles, permissions, canManage, mutate }) {
  const [selectedId, setSelectedId] = useState(null);
  const selected = roles.find((role) => role.id === selectedId) || roles[0];
  const [draft, setDraft] = useState(null);
  const [clone, setClone] = useState({ source_role_id: "", name: "", description: "" });
  useEffect(() => { if (selected) { setSelectedId(selected.id); setDraft({ name: selected.name, description: selected.description, permission_keys: selected.permission_keys }); } }, [selected?.id]); // eslint-disable-line react-hooks/exhaustive-deps
  const grouped = useMemo(() => Object.groupBy ? Object.groupBy(permissions, (item) => item.domain) : permissions.reduce((all, item) => ({ ...all, [item.domain]: [...(all[item.domain] || []), item] }), {}), [permissions]);
  if (!selected || !draft) return <p>Роли не найдены.</p>;
  const toggle = (key) => setDraft({ ...draft, permission_keys: draft.permission_keys.includes(key) ? draft.permission_keys.filter((item) => item !== key) : [...draft.permission_keys, key] });
  return <div className="roles-layout">
    <aside className="role-list">{roles.map((role) => <button key={role.id} className={role.id === selected.id ? "is-active" : ""} onClick={() => setSelectedId(role.id)}><strong>{role.name}</strong><span>{role.user_count} пользователей · {role.permission_keys.length} прав</span></button>)}</aside>
    <div className="role-editor">
      <div className="role-editor__header"><label><span>Название</span><input value={draft.name} disabled={selected.is_system || !canManage} onChange={(event) => setDraft({ ...draft, name: event.target.value })} /></label><label><span>Описание</span><input value={draft.description} disabled={selected.is_system || !canManage} onChange={(event) => setDraft({ ...draft, description: event.target.value })} /></label></div>
      {selected.is_system ? <p className="role-notice">Системная роль неизменяема. Клонируйте её для особого набора прав.</p> : null}
      <div className="permission-groups">{Object.entries(grouped).map(([domain, items]) => <fieldset key={domain}><legend>{domain}</legend>{items.map((permission) => <label key={permission.key}><input type="checkbox" checked={draft.permission_keys.includes(permission.key)} disabled={selected.is_system || !canManage} onChange={() => toggle(permission.key)} /><span><strong>{permission.key}</strong>{permission.description}</span></label>)}</fieldset>)}</div>
      {!selected.is_system && canManage ? <div className="role-actions"><button onClick={() => mutate(() => api(`/api/auth/roles/${selected.id}`, { method: "PATCH", body: JSON.stringify(draft) }), "Роль сохранена.")}>Сохранить</button><button onClick={() => mutate(() => api(`/api/auth/roles/${selected.id}`, { method: "DELETE" }), "Роль удалена.")}>Удалить</button></div> : null}
      {canManage ? <form className="role-clone" onSubmit={(event) => { event.preventDefault(); mutate(() => api("/api/auth/roles/clone", { method: "POST", body: JSON.stringify({ ...clone, source_role_id: Number(clone.source_role_id) }) }), "Роль создана."); setClone({ source_role_id: "", name: "", description: "" }); }}><h3>Клонировать роль</h3><select required value={clone.source_role_id} onChange={(event) => setClone({ ...clone, source_role_id: event.target.value })}><option value="">Исходная роль</option>{roles.map((role) => <option key={role.id} value={role.id}>{role.name}</option>)}</select><input required value={clone.name} onChange={(event) => setClone({ ...clone, name: event.target.value })} placeholder="Название новой роли" /><button>Клонировать</button></form> : null}
    </div>
  </div>;
}

function AuditTab({ rows }) {
  return <div className="table-shell"><table><thead><tr><th>Время</th><th>Пользователь</th><th>Событие</th><th>Решение</th><th>Разрешение / цель</th></tr></thead><tbody>{rows.map((row) => <tr key={row.id}><td>{new Date(row.created_at).toLocaleString("ru-RU")}</td><td>{row.actor_username || "—"}</td><td>{row.event_type}</td><td><span className={`audit-decision audit-decision--${row.decision}`}>{row.decision === "allow" ? "Разрешено" : "Отклонено"}</span></td><td><code>{row.permission_key || "—"}</code><small>{row.target_id || ""}</small></td></tr>)}</tbody></table></div>;
}
