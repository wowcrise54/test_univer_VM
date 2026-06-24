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
