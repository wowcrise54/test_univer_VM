import { api } from "../../api/client.js";
import { Button, Disclosure, Field, Panel, Toggle } from "../../shared/ui.jsx";

export function ConnectionPanel({
  connectionDraft: form,
  setConnectionDraft: setForm,
  session,
  setSession,
  lookupsError,
  lookupsUpdatedAt,
  refreshLookups,
  setLookups,
  busy,
  runBusy,
  showAlert,
  onNavigate,
}) {
  const update = (key, value) =>
    setForm((current) => ({ ...current, [key]: value }));

  const connect = () =>
    runBusy("session", async () => {
      const payload = Object.fromEntries(
        Object.entries(form).map(([key, value]) => [
          key,
          value === "" ? null : value,
        ]),
      );
      const result = await api("/api/session/connect", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setSession(result);
      setForm((current) => ({
        ...current,
        api_url: result.api_url || current.api_url,
        token_url: result.token_url || current.token_url,
        username: result.username ?? current.username,
        verify_tls: result.verify_tls ?? current.verify_tls,
      }));
      // Lookups load automatically once the session is marked connected.
      showAlert("Подключение к MP VM установлено.", "success");
      onNavigate?.("/vm");
    });

  const disconnect = () =>
    runBusy("session", async () => {
      const result = await api("/api/session/disconnect", { method: "POST" });
      setSession(result);
      setLookups({
        credentials: [],
        scopes: [],
        scanner_profiles: [],
        agents: [],
      });
      showAlert("Сессия MP VM отключена.", "info");
    });

  const loadLookups = () =>
    runBusy("lookups", async () => {
      await refreshLookups();
      showAlert("Справочники обновлены.", "success");
    });

  return (
    <Panel
      id="connection"
      action={
        session.connected ? (
          <Button
            variant="secondary"
            busy={busy.lookups}
            disabled={busy.session}
            onClick={loadLookups}
          >
            Обновить справочники
          </Button>
        ) : null
      }
    >
      {!session.connected && session.env_connect_error ? (
        <div className="query-state query-state--error" role="alert">
          <span>
            Автоподключение не выполнено: {session.env_connect_error}
          </span>
        </div>
      ) : null}
      <div className="form-grid form-grid--two connection-primary-fields">
        <Field label="Адрес MP VM">
          <input
            value={form.api_url}
            onChange={(event) => update("api_url", event.target.value)}
            placeholder="https://srv-siem.local"
          />
        </Field>
        <Field label="Логин">
          <input
            value={form.username}
            onChange={(event) => update("username", event.target.value)}
            autoComplete="username"
          />
        </Field>
        <Field label="Пароль">
          <input
            value={form.password}
            onChange={(event) => update("password", event.target.value)}
            type="password"
            autoComplete="current-password"
          />
          <small className="field-note">Хранится только в памяти.</small>
        </Field>
      </div>
      <Disclosure
        title="Дополнительная авторизация"
        meta={form.access_token ? "Токен задан" : null}
      >
        <div className="form-grid form-grid--two">
          <Field label="Адрес выдачи токена">
            <input
              value={form.token_url}
              onChange={(event) => update("token_url", event.target.value)}
              placeholder="https://srv-siem.local:3334/connect/token"
            />
          </Field>
          <Field label="ID клиента">
            <input
              value={form.client_id}
              onChange={(event) => update("client_id", event.target.value)}
            />
          </Field>
          <Field label="Секрет клиента">
            <input
              value={form.client_secret}
              onChange={(event) => update("client_secret", event.target.value)}
              type="password"
            />
          </Field>
          <Field label="Область доступа" wide>
            <input
              value={form.scope}
              onChange={(event) => update("scope", event.target.value)}
            />
          </Field>
          <Field label="Токен доступа" wide>
            <input
              value={form.access_token}
              onChange={(event) => update("access_token", event.target.value)}
              type="password"
              placeholder="Вместо логина и пароля"
            />
          </Field>
          <Toggle
            label="Проверять TLS-сертификат"
            checked={form.verify_tls}
            onChange={(value) => update("verify_tls", value)}
          />
        </div>
      </Disclosure>
      <div className="action-row">
        <Button busy={busy.session} onClick={connect}>
          Подключиться
        </Button>
        {session.connected ? (
          <Button variant="ghost" busy={busy.session} onClick={disconnect}>
            Отключиться
          </Button>
        ) : null}
        {session.connected && lookupsUpdatedAt ? (
          <div className="inline-metric">
            Справочники обновлены{" "}
            {new Date(lookupsUpdatedAt).toLocaleTimeString("ru-RU", {
              hour: "2-digit",
              minute: "2-digit",
            })}
          </div>
        ) : null}
        {session.connected && lookupsError ? (
          <div className="query-state query-state--error" role="alert">
            <span>
              Не удалось обновить справочники:{" "}
              {lookupsError.operatorMessage || lookupsError.message}
            </span>
          </div>
        ) : null}
        {session.connected ? (
          <div className="mini-state mini-state--ok">{session.api_url}</div>
        ) : null}
      </div>
    </Panel>
  );
}
