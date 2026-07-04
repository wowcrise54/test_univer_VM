import { useEffect, useState } from "react";

export function Button({ children, variant = "primary", busy, ...props }) {
  return (
    <button className={`button ${variant}`} disabled={busy || props.disabled} {...props}>
      {busy ? "Выполняю..." : children}
    </button>
  );
}

export function Field({ label, children, wide }) {
  return (
    <label className={wide ? "field field--wide" : "field"}>
      <span>{label}</span>
      {children}
    </label>
  );
}

export function Toggle({ label, checked, onChange }) {
  return (
    <label className="toggle">
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      <span>{label}</span>
    </label>
  );
}

export function Panel({ id, eyebrow, title, description, action, children, className = "" }) {
  return (
    <section id={id} className={`panel ${className}`}>
      <div className="panel__header">
        <div>
          {eyebrow ? <div className="section-number">{eyebrow}</div> : null}
          <h2>{title}</h2>
          {description ? <p>{description}</p> : null}
        </div>
        {action ? <div className="panel__action">{action}</div> : null}
      </div>
      {children}
    </section>
  );
}

export function ConfirmDialog({ open, title, description, impact = [], confirmLabel = "Подтвердить", requireText = "", busy, onConfirm, onClose }) {
  const [typed, setTyped] = useState("");
  useEffect(() => {
    if (open) setTyped("");
  }, [open]);
  if (!open) return null;
  const allowed = !requireText || typed === requireText;
  return (
    <div className="confirm-overlay" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <section className="confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
        <span className="confirm-dialog__eyebrow">Подтверждение действия</span>
        <h2 id="confirm-title">{title}</h2>
        <p>{description}</p>
        {impact.length ? <ul>{impact.map((item) => <li key={item}>{item}</li>)}</ul> : null}
        {requireText ? (
          <label className="field">
            <span>Введите <code>{requireText}</code>, чтобы подтвердить изменение MP VM</span>
            <input value={typed} onChange={(event) => setTyped(event.target.value)} autoFocus />
          </label>
        ) : null}
        <div className="confirm-dialog__actions">
          <Button variant="secondary" onClick={onClose}>Отмена</Button>
          <Button variant="danger" disabled={!allowed} busy={busy} onClick={onConfirm}>{confirmLabel}</Button>
        </div>
      </section>
    </div>
  );
}
