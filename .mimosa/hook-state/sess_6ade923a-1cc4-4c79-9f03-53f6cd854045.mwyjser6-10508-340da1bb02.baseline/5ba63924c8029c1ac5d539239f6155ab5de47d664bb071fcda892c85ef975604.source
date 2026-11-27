import { useEffect, useState } from "react";
import { api } from "../../api/client.js";
import { formatDate } from "../../shared/format.js";
import {
  Button,
  ConfirmDialog,
  Disclosure,
  Toggle,
} from "../../shared/ui.jsx";

const STATUS_LABELS = {
  active: "Действует",
  expired: "Истёк",
  revoked: "Отозван",
};
const EMPTY_FORM = {
  name: "",
  scopes: [],
  expires_in_days: 90,
  ip_allowlist: "",
  owner_user_id: "",
};

export function McpTokensTab({ currentUser, users = [], showAlert }) {
  const canManage = currentUser.permissions.includes(
    "security.mcp_tokens.manage",
  );
  const [tokens, setTokens] = useState([]);
  const [scopes, setScopes] = useState([]);
  const [form, setForm] = useState(EMPTY_FORM);
  const [issued, setIssued] = useState(null);
  const [pending, setPending] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    const data = await api("/api/auth/mcp-tokens");
    setTokens(data.rows || []);
    setScopes(data.scopes || []);
  };
  useEffect(() => {
    load().catch((error) =>
      showAlert(error.operatorMessage || error.message, "error"),
    );
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const run = async (request, success) => {
    try {
      const result = await request();
      await load();
      if (success) showAlert(success, "success");
      return result;
    } catch (error) {
      showAlert(error.operatorMessage || error.message, "error");
      return null;
    }
  };

  const toggleScope = (key, checked) =>
    setForm((current) => ({
      ...current,
      scopes: checked
        ? [...current.scopes, key]
        : current.scopes.filter((scope) => scope !== key),
    }));

  const create = async (event) => {
    event.preventDefault();
    const body = {
      name: form.name.trim(),
      scopes: form.scopes,
      expires_in_days: Number(form.expires_in_days),
      ip_allowlist: form.ip_allowlist
        .split(/[\s,]+/)
        .filter(Boolean),
    };
    if (form.owner_user_id) body.owner_user_id = Number(form.owner_user_id);
    const token = await run(
      () => api("/api/auth/mcp-tokens", { method: "POST", body: JSON.stringify(body) }),
      "Токен выпущен.",
    );
    if (token) {
      setIssued(token);
      setForm(EMPTY_FORM);
    }
  };

  const confirm = async () => {
    setBusy(true);
    try {
      const { kind, token } = pending;
      const result = await run(
        () =>
          kind === "revoke"
            ? api(`/api/auth/mcp-tokens/${token.id}/revoke`, { method: "POST" })
            : api(`/api/auth/mcp-tokens/${token.id}/rotate`, {
                method: "POST",
                body: JSON.stringify({ grace_hours: 24 }),
              }),
        kind === "revoke" ? "Токен отозван." : "Токен заменён.",
      );
      if (result) {
        if (kind === "rotate") setIssued(result);
        setPending(null);
      }
    } finally {
      setBusy(false);
    }
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(issued.token);
      showAlert("Токен скопирован.", "success");
    } catch {
      showAlert("Не удалось скопировать: выделите токен и скопируйте вручную.", "error");
    }
  };

  const scopeLabel = (key) => scopes.find((scope) => scope.key === key)?.label || key;

  return (
    <div className="access-tab-panel">
      <p>
        Персональные токены дают AI-клиентам только чтение через MCP. Секрет
        показывается один раз при выпуске.
      </p>
      {issued ? (
        <div className="panel" role="status" aria-label="Выпущенный токен">
          <strong>
            Сохраните токен «{issued.name}»: больше он не будет показан.
          </strong>
          <p>
            <code data-testid="issued-token">{issued.token}</code>
          </p>
          <div className="user-row-actions">
            <Button variant="secondary" onClick={copy}>
              Скопировать
            </Button>
            <Button variant="secondary" onClick={() => setIssued(null)}>
              Я сохранил токен
            </Button>
          </div>
        </div>
      ) : null}
      {canManage ? (
        <Disclosure title="Новый токен">
          <form className="user-create-form" onSubmit={create}>
            <label>
              <span>Название клиента</span>
              <input
                value={form.name}
                onChange={(event) => setForm({ ...form, name: event.target.value })}
                required
                maxLength="100"
                placeholder="Например, claude-code-ivanov"
              />
            </label>
            <fieldset>
              <legend>Области доступа</legend>
              {scopes.map((scope) => (
                <Toggle
                  key={scope.key}
                  label={scope.label}
                  checked={form.scopes.includes(scope.key)}
                  onChange={(checked) => toggleScope(scope.key, checked)}
                />
              ))}
            </fieldset>
            <label>
              <span>Срок действия, дней</span>
              <input
                type="number"
                min="1"
                max="365"
                value={form.expires_in_days}
                onChange={(event) =>
                  setForm({ ...form, expires_in_days: event.target.value })
                }
                required
              />
            </label>
            <label>
              <span>Разрешённые адреса (необязательно)</span>
              <input
                value={form.ip_allowlist}
                onChange={(event) =>
                  setForm({ ...form, ip_allowlist: event.target.value })
                }
                placeholder="10.0.0.0/24, 192.168.1.5"
              />
            </label>
            {users.length ? (
              <label>
                <span>Владелец</span>
                <select
                  value={form.owner_user_id}
                  onChange={(event) =>
                    setForm({ ...form, owner_user_id: event.target.value })
                  }
                >
                  <option value="">Я ({currentUser.username})</option>
                  {users
                    .filter((user) => user.is_active)
                    .map((user) => (
                      <option key={user.id} value={user.id}>
                        {user.display_name} ({user.username})
                      </option>
                    ))}
                </select>
              </label>
            ) : null}
            <div className="user-create-form__actions">
              <Button type="submit" disabled={!form.name.trim() || !form.scopes.length}>
                Выпустить
              </Button>
            </div>
          </form>
        </Disclosure>
      ) : null}
      <div className="table-shell">
        <table>
          <thead>
            <tr>
              <th>Токен</th>
              <th>Владелец</th>
              <th>Области</th>
              <th>Состояние</th>
              <th>Действует до</th>
              <th>Последнее использование</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {tokens.map((token) => (
              <tr key={token.id}>
                <td>
                  <strong>{token.name}</strong>
                  <small>{token.token_id}</small>
                </td>
                <td>{token.owner.display_name}</td>
                <td>{token.scopes.map(scopeLabel).join(", ")}</td>
                <td>{STATUS_LABELS[token.status] || token.status}</td>
                <td>{formatDate(token.expires_at)}</td>
                <td>
                  {token.last_used_at
                    ? `${formatDate(token.last_used_at)}${token.last_used_ip ? ` · ${token.last_used_ip}` : ""}`
                    : "Не использовался"}
                </td>
                <td>
                  {canManage && token.status === "active" ? (
                    <div className="user-row-actions">
                      <Button
                        variant="secondary"
                        aria-label={`Заменить токен: ${token.name}`}
                        onClick={() => setPending({ kind: "rotate", token })}
                      >
                        Заменить
                      </Button>
                      <Button
                        variant="danger"
                        aria-label={`Отозвать токен: ${token.name}`}
                        onClick={() => setPending({ kind: "revoke", token })}
                      >
                        Отозвать
                      </Button>
                    </div>
                  ) : null}
                </td>
              </tr>
            ))}
            {!tokens.length ? (
              <tr>
                <td colSpan="7">Токены ещё не выпускались.</td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
      <ConfirmDialog
        open={Boolean(pending)}
        title={
          pending?.kind === "revoke"
            ? `Отозвать токен «${pending?.token.name}»?`
            : `Заменить токен «${pending?.token.name}»?`
        }
        description={
          pending?.kind === "revoke"
            ? "Клиент потеряет доступ сразу, все его сессии будут закрыты."
            : "Будет выпущен новый токен с теми же правами. Старый продолжит работать ещё 24 часа, чтобы клиент успел перейти."
        }
        confirmLabel={pending?.kind === "revoke" ? "Отозвать" : "Заменить"}
        busy={busy}
        onConfirm={confirm}
        onClose={() => setPending(null)}
      />
    </div>
  );
}
