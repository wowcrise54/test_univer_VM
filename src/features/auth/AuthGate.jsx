import { useEffect, useState } from "react";
import { api } from "../../api/client.js";

export function AuthGate({ children }) {
  const [state, setState] = useState({ loading: true, user: null, error: null, configured: true });

  useEffect(() => {
    let active = true;
    api("/api/auth/me")
      .then((result) => active && setState({ loading: false, user: result.user, error: null, configured: true }))
      .catch(async (error) => {
        let configured = true;
        try {
          configured = (await api("/api/auth/bootstrap-status")).configured;
        } catch {
          // The login form will show the original availability error.
        }
        if (active) setState({ loading: false, user: null, error: error.status === 401 ? null : error, configured });
      });
    return () => { active = false; };
  }, []);

  const login = async (credentials) => {
    const result = await api("/api/auth/login", { method: "POST", body: JSON.stringify(credentials) });
    setState({ loading: false, user: result.user, error: null, configured: true });
  };
  const logout = async () => {
    try { await api("/api/auth/logout", { method: "POST" }); } finally {
      setState({ loading: false, user: null, error: null, configured: true });
    }
  };

  if (state.loading) return <div className="auth-screen"><div className="auth-card"><p>Проверяем доступ…</p></div></div>;
  if (!state.user) return <LoginForm onLogin={login} error={state.error} configured={state.configured} />;
  return children({ user: state.user, logout });
}

function LoginForm({ onLogin, error, configured }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState(error?.operatorMessage || error?.message || "");

  const submit = async (event) => {
    event.preventDefault();
    setPending(true);
    setMessage("");
    try { await onLogin({ username, password }); }
    catch (nextError) { setMessage(nextError.operatorMessage || nextError.message); }
    finally { setPending(false); }
  };

  return (
    <main className="auth-screen">
      <form className="auth-card" onSubmit={submit}>
        <div className="auth-brand">MP</div>
        <span>MP VM Client</span>
        <h1>Вход в приложение</h1>
        <p>Используйте локальную учётную запись. Подключение к MP VM настраивается отдельно.</p>
        {!configured ? <div className="auth-warning">Первый администратор ещё не создан. Задайте MPVM_BOOTSTRAP_ADMIN_PASSWORD и перезапустите приложение.</div> : null}
        <label><span>Имя пользователя</span><input autoFocus autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} required /></label>
        <label><span>Пароль</span><input type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required /></label>
        {message ? <div className="auth-error" role="alert">{message}</div> : null}
        <button type="submit" disabled={pending || !configured}>{pending ? "Входим…" : "Войти"}</button>
      </form>
    </main>
  );
}
