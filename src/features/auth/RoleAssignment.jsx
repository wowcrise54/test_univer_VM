import { useId, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { Button, useDialogAccessibility } from "../../shared/ui.jsx";

const SEARCH_THRESHOLD = 8;

export function permissionUnion(roles, roleIds) {
  const ids = new Set(roleIds);
  return new Set(
    roles
      .filter((role) => ids.has(role.id))
      .flatMap((role) => role.permission_keys || []),
  );
}

function pluralRoles(count) {
  const mod10 = count % 10;
  const mod100 = count % 100;
  if (mod10 === 1 && mod100 !== 11) return `${count} роль`;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14))
    return `${count} роли`;
  return `${count} ролей`;
}

export function RoleChips({ roles }) {
  if (!roles?.length)
    return <span className="role-chips__empty">Нет ролей</span>;
  return (
    <ul className="role-chips" aria-label="Роли пользователя">
      {roles.map((role) => (
        <li
          key={role.id}
          className={
            role.is_system ? "role-chip role-chip--system" : "role-chip"
          }
        >
          {role.name}
        </li>
      ))}
    </ul>
  );
}

export function RolePicker({ roles, value, onChange, legend = "Роли" }) {
  const [query, setQuery] = useState("");
  const selected = new Set(value);
  const needle = query.trim().toLowerCase();
  const visible = needle
    ? roles.filter((role) =>
        `${role.name} ${role.description || ""}`.toLowerCase().includes(needle),
      )
    : roles;
  const toggle = (id) =>
    onChange(
      selected.has(id)
        ? value.filter((item) => item !== id)
        : [...value, id].sort((a, b) => a - b),
    );
  const permissionCount = permissionUnion(roles, value).size;
  return (
    <fieldset className="role-picker">
      <legend>{legend}</legend>
      {roles.length > SEARCH_THRESHOLD ? (
        <input
          className="role-picker__search"
          type="search"
          aria-label="Поиск роли"
          placeholder="Найти роль"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
      ) : null}
      <div className="role-picker__list">
        {visible.map((role) => (
          <label
            key={role.id}
            className={
              selected.has(role.id) ? "role-option is-selected" : "role-option"
            }
          >
            <input
              type="checkbox"
              checked={selected.has(role.id)}
              onChange={() => toggle(role.id)}
            />
            <span className="role-option__body">
              <span className="role-option__title">
                <strong>{role.name}</strong>
                {role.is_system ? (
                  <span className="role-option__badge">системная</span>
                ) : null}
              </span>
              {role.description ? <small>{role.description}</small> : null}
              <small className="role-option__meta">
                {(role.permission_keys || []).length} прав
              </small>
            </span>
          </label>
        ))}
        {!visible.length ? (
          <p className="role-picker__empty">Роли не найдены.</p>
        ) : null}
      </div>
      <p className="role-picker__summary" aria-live="polite">
        {value.length
          ? `Выбрано: ${pluralRoles(value.length)} · ${permissionCount} уникальных прав`
          : "Выберите хотя бы одну роль."}
      </p>
    </fieldset>
  );
}

export function RoleAssignmentDialog({ user, roles, onClose, onSave }) {
  const initial = useMemo(
    () => (user.roles || []).map((role) => role.id).sort((a, b) => a - b),
    [user],
  );
  const [selected, setSelected] = useState(initial);
  const [busy, setBusy] = useState(false);
  const titleId = useId();
  const dialogRef = useDialogAccessibility(true, busy ? undefined : onClose);
  const added = roles.filter(
    (role) => selected.includes(role.id) && !initial.includes(role.id),
  );
  const removed = roles.filter(
    (role) => initial.includes(role.id) && !selected.includes(role.id),
  );
  const changed = added.length > 0 || removed.length > 0;
  const save = async () => {
    setBusy(true);
    try {
      if (await onSave(selected)) onClose();
    } finally {
      setBusy(false);
    }
  };
  const dialog = (
    <div
      className="confirm-overlay"
      role="presentation"
      onMouseDown={(event) => {
        if (!busy && event.target === event.currentTarget) onClose();
      }}
    >
      <section
        ref={dialogRef}
        className="confirm-dialog role-assign-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <span className="confirm-dialog__eyebrow">Роли пользователя</span>
        <h2 id={titleId}>{user.display_name}</h2>
        <p className="role-assign-dialog__login">{user.username}</p>
        <RolePicker
          roles={roles}
          value={selected}
          onChange={setSelected}
          legend="Назначенные роли"
        />
        {changed ? (
          <div className="role-assign-dialog__diff" aria-live="polite">
            {added.length ? (
              <p>
                <span className="role-diff role-diff--add">Добавить</span>
                {added.map((role) => role.name).join(", ")}
              </p>
            ) : null}
            {removed.length ? (
              <p>
                <span className="role-diff role-diff--remove">Снять</span>
                {removed.map((role) => role.name).join(", ")}
              </p>
            ) : null}
            <small>
              После сохранения активные сессии пользователя будут завершены.
            </small>
          </div>
        ) : null}
        <div className="confirm-dialog__actions">
          <Button variant="secondary" disabled={busy} onClick={onClose}>
            Отмена
          </Button>
          <Button
            disabled={!changed || !selected.length}
            busy={busy}
            onClick={save}
          >
            Сохранить роли
          </Button>
        </div>
      </section>
    </div>
  );
  return typeof document === "undefined"
    ? dialog
    : createPortal(dialog, document.body);
}
