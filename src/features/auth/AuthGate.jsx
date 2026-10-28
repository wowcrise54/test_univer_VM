import { useEffect, useState } from "react";
import { ACCESS_CHANGED_EVENT } from "../../api/accessEvents.js";
import { api } from "../../api/client.js";

// Role and permission changes apply on the server immediately, so the user
// record is re-read to keep navigation in sync without a re-login.
export const USER_REFRESH_INTERVAL_MS = 60_000;
export const USER_REFRESH_MIN_GAP_MS = 5_000;
const SESSION_ENDED = { operatorMessage: "Сеанс завершён: доступ изменился или истёк. Войдите снова." };

function accessSignature(user) {
  return JSON.stringify([
    user?.id,
    user?.username,
    user?.display_name,
    user?.is_active,
    user?.role,
    (user?.roles || []).map((role) => [role.id, role.name]),
    [...(user?.permissions || [])].sort(),
  ]);
}

export function AuthGate({ children }) {
  const [state, setState] = useState({ loading: true, user: null, error: null, configured: true });
  const userId = state.user?.id;

  useEffect(() => {
    if (userId == null) return undefined;
    let active = true;
    let inFlight = false;
    // The user record was just loaded by login or the initial /api/auth/me.
    let lastStarted = Date.now();
    const refresh = async () => {
      const now = Date.now();
      if (inFlight || now - lastStarted < USER_REFRESH_MIN_GAP_MS) return;
      inFlight = true;
      lastStarted = now;
      try {
        const result = await api("/api/auth/me");
        if (!active) return;
        setState((previous) =>
          previous.user && accessSignature(previous.user) === accessSignature(result.user)
            ? previous
            : { ...previous, user: result.user },
        );
      } catch (error) {
        // Only a rejected session ends the workspace; network and server
        // failures keep the current view and the next trigger retries.
        if (active && error.status === 401) {
          setState({ loading: false, user: null, error: SESSION_ENDED, configured: true });
        }
      } finally {
        inFlight = false;
      }
    };
    const refreshWhenVisible = () => {
      if (document.visibilityState !== "hidden") refresh();
    };
    const timer = window.setInterval(refreshWhenVisible, USER_REFRESH_INTERVAL_MS);
    document.addEventListener("visibilitychange", refreshWhenVisible);
    window.addEventListener("focus", refreshWhenVisible);
    window.addEventListener(ACCESS_CHANGED_EVENT, refresh);
    return () => {
      active = false;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", refreshWhenVisible);
      window.removeEventListener("focus", refreshWhenVisible);
      window.removeEventListener(ACCESS_CHANGED_EVENT, refresh);
    };
  }, [userId]);

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
  const [authType, setAuthType] = useState("local");
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState(error?.operatorMessage || error?.message || "");

  const submit = async (event) => {
    event.preventDefault();
    setPending(true);
    setMessage("");
    try { await onLogin({ username, password, auth_type: authType }); }
    catch (nextError) { setMessage(nextError.operatorMessage || nextError.message); }
    finally { setPending(false); }
  };

  return (
    <main className="auth-screen">
      <form className="auth-card" onSubmit={submit}>
        <div className="auth-brand">MP</div>
        <h1>Вход в приложение</h1>
        <div className="auth-mode" role="group" aria-label="Способ авторизации">
          <button type="button" className={authType === "local" ? "is-active" : ""} aria-pressed={authType === "local"} onClick={() => setAuthType("local")}>
            Локально
          </button>
          <button type="button" className={authType === "ldap" ? "is-active" : ""} aria-pressed={authType === "ldap"} onClick={() => setAuthType("ldap")}>
            LDAP
          </button>
        </div>
        {!configured ? <div className="auth-warning">Первый администратор ещё не создан. Задайте MPVM_BOOTSTRAP_ADMIN_PASSWORD и перезапустите приложение.</div> : null}
        <label><span>Логин</span><input autoFocus autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} required /></label>
        <label><span>Пароль</span><input type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required /></label>
        {message ? <div className="auth-error" role="alert">{message}</div> : null}
        <button type="submit" disabled={pending || !configured}>{pending ? "Входим…" : authType === "ldap" ? "Войти через LDAP" : "Войти"}</button>
      </form>
    </main>
  );
}
