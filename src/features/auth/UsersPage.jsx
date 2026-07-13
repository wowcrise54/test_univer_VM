import { useEffect, useState } from "react";
import { api } from "../../api/client.js";

const EMPTY_FORM = { username: "", display_name: "", password: "", role: "operator" };

export function UsersPage({ currentUser, showAlert }) {
  const [users, setUsers] = useState([]);
  const [form, setForm] = useState(EMPTY_FORM);
  const [loading, setLoading] = useState(true);

  const load = () => api("/api/auth/users").then((result) => setUsers(result.rows || [])).finally(() => setLoading(false));
  useEffect(() => { load().catch((error) => showAlert(error.operatorMessage || error.message, "error")); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const create = async (event) => {
    event.preventDefault();
    try {
      await api("/api/auth/users", { method: "POST", body: JSON.stringify(form) });
      setForm(EMPTY_FORM);
      await load();
      showAlert("Пользователь создан.", "success");
    } catch (error) { showAlert(error.operatorMessage || error.message, "error"); }
  };

  const patch = async (user, changes) => {
    try {
      await api(`/api/auth/users/${user.id}`, { method: "PATCH", body: JSON.stringify(changes) });
      await load();
    } catch (error) { showAlert(error.operatorMessage || error.message, "error"); }
  };

  if (currentUser?.role !== "admin") return <section className="panel"><p>Раздел доступен только администратору.</p></section>;
  return (
    <section className="panel users-page">
      <div className="panel__header"><div><h2>Учётные записи</h2><p>Администратор управляет доступом; оператор изменяет данные; наблюдатель работает только на чтение.</p></div></div>
      <form className="user-create-form" onSubmit={create}>
        <label><span>Логин</span><input value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} required minLength="3" /></label>
        <label><span>Имя</span><input value={form.display_name} onChange={(event) => setForm({ ...form, display_name: event.target.value })} required /></label>
        <label><span>Пароль</span><input type="password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} required minLength="12" autoComplete="new-password" /></label>
        <label><span>Роль</span><select value={form.role} onChange={(event) => setForm({ ...form, role: event.target.value })}><option value="operator">Оператор</option><option value="viewer">Наблюдатель</option><option value="admin">Администратор</option></select></label>
        <button type="submit">Создать</button>
      </form>
      <div className="table-shell"><table><thead><tr><th>Пользователь</th><th>Роль</th><th>Состояние</th><th>Последний вход</th><th></th></tr></thead><tbody>
        {loading ? <tr><td colSpan="5">Загрузка…</td></tr> : users.map((user) => <tr key={user.id}>
          <td><strong>{user.display_name}</strong><small>{user.username}</small></td>
          <td><select value={user.role} disabled={user.id === currentUser.id} onChange={(event) => patch(user, { role: event.target.value })}><option value="admin">Администратор</option><option value="operator">Оператор</option><option value="viewer">Наблюдатель</option></select></td>
          <td>{user.is_active ? "Активен" : "Отключён"}</td><td>{user.last_login_at ? new Date(user.last_login_at).toLocaleString("ru-RU") : "—"}</td>
          <td><button type="button" disabled={user.id === currentUser.id} onClick={() => patch(user, { is_active: !user.is_active })}>{user.is_active ? "Отключить" : "Включить"}</button></td>
        </tr>)}</tbody></table></div>
    </section>
  );
}
