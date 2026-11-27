import { useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";

const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "[tabindex]:not([tabindex='-1'])",
].join(",");

function topLevelElement(element) {
  let current = element;
  while (current?.parentElement && current.parentElement !== document.body) {
    current = current.parentElement;
  }
  return current;
}

export function useDialogAccessibility(open, onClose, restoreFocusTo = null) {
  const dialogRef = useRef(null);
  const closeRef = useRef(onClose);

  useEffect(() => {
    closeRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    if (!open || typeof document === "undefined") return undefined;
    const dialog = dialogRef.current;
    if (!dialog) return undefined;

    const previousFocus = document.activeElement;
    const requestedRestore =
      typeof restoreFocusTo === "function"
        ? restoreFocusTo()
        : restoreFocusTo?.current || restoreFocusTo;
    const previousOverflow = document.body.style.overflow;
    const modalRoot = topLevelElement(dialog);
    const background = Array.from(document.body.children)
      .filter((element) => element !== modalRoot)
      .map((element) => ({
        element,
        inert: Boolean(element.inert),
        ariaHidden: element.getAttribute("aria-hidden"),
      }));

    document.body.style.overflow = "hidden";
    background.forEach(({ element }) => {
      element.inert = true;
      element.setAttribute("aria-hidden", "true");
    });

    const focusFirst = () => {
      const target =
        dialog.querySelector("[autofocus]") ||
        dialog.querySelector(FOCUSABLE_SELECTOR) ||
        dialog;
      target.focus({ preventScroll: true });
    };
    const frame = window.requestAnimationFrame(focusFirst);

    const onKeyDown = (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        closeRef.current?.();
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = Array.from(dialog.querySelectorAll(FOCUSABLE_SELECTOR));
      if (!focusable.length) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable.at(-1);
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", onKeyDown);
    return () => {
      window.cancelAnimationFrame(frame);
      document.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = previousOverflow;
      background.forEach(({ element, inert, ariaHidden }) => {
        element.inert = inert;
        if (ariaHidden === null) element.removeAttribute("aria-hidden");
        else element.setAttribute("aria-hidden", ariaHidden);
      });
      const focusTarget =
        requestedRestore instanceof HTMLElement && requestedRestore.isConnected
          ? requestedRestore
          : previousFocus;
      if (focusTarget instanceof HTMLElement && focusTarget.isConnected) {
        focusTarget.focus({ preventScroll: true });
      }
    };
  }, [open, restoreFocusTo]);

  return dialogRef;
}

export function Button({
  children,
  variant = "primary",
  busy = false,
  disabled = false,
  onClick,
  type = "button",
  className = "",
  ...props
}) {
  const pendingRef = useRef(false);
  const blocked = Boolean(busy || disabled);

  const handleClick = (event) => {
    if (blocked || pendingRef.current) {
      event.preventDefault();
      return;
    }
    const result = onClick?.(event);
    if (result && typeof result.then === "function") {
      pendingRef.current = true;
      Promise.resolve(result).then(
        () => {
          pendingRef.current = false;
        },
        () => {
          pendingRef.current = false;
        },
      );
    }
  };

  return (
    <button
      {...props}
      className={`button ${variant} ${className}`.trim()}
      type={type}
      disabled={blocked}
      aria-busy={busy ? "true" : undefined}
      onClick={handleClick}
    >
      {busy ? <span className="button__spinner" aria-hidden="true" /> : null}
      {children}
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
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
      />
      <span>{label}</span>
    </label>
  );
}

/**
 * A panel without a title belongs to the page heading: it only renders its
 * actions row and is labelled by the workspace H1.
 */
export function Panel({
  id,
  title,
  action,
  children,
  className = "",
  ...props
}) {
  const labelledBy =
    !title && !props["aria-label"] && !props["aria-labelledby"]
      ? { "aria-labelledby": "workspace-title" }
      : {};
  return (
    <section
      id={id}
      className={`panel ${className}`}
      {...labelledBy}
      {...props}
    >
      {title || action ? (
        <div
          className={`panel__header${title ? "" : " panel__header--actions"}`}
        >
          {title ? (
            <div>
              <h2>{title}</h2>
            </div>
          ) : null}
          {action ? <div className="panel__action">{action}</div> : null}
        </div>
      ) : null}
      {children}
    </section>
  );
}

export function Disclosure({
  title,
  meta,
  defaultOpen = false,
  children,
  className = "",
  onToggle,
  ...props
}) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <details
      {...props}
      className={`disclosure ${className}`.trim()}
      open={open}
      onToggle={(event) => {
        setOpen(event.currentTarget.open);
        onToggle?.(event);
      }}
    >
      <summary>
        <span className="disclosure__label">
          <strong>{title}</strong>
        </span>
        {meta ? <span className="disclosure__meta">{meta}</span> : null}
        <span className="disclosure__chevron" aria-hidden="true">
          {open ? "−" : "+"}
        </span>
      </summary>
      <div className="disclosure__content">{children}</div>
    </details>
  );
}

export function ActionMenu({
  label = "Ещё",
  children,
  className = "",
  align = "end",
}) {
  const [open, setOpen] = useState(false);
  const summaryRef = useRef(null);

  return (
    <details
      className={`action-menu action-menu--${align} ${className}`.trim()}
      open={open}
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary ref={summaryRef}>{label}</summary>
      <div
        className="action-menu__content"
        onClick={(event) => {
          if (!event.target.closest("button, a")) return;
          event.currentTarget.closest("details")?.removeAttribute("open");
          setOpen(false);
          summaryRef.current?.focus({ preventScroll: true });
        }}
      >
        {children}
      </div>
    </details>
  );
}

export function ConfirmDialog({
  open,
  title,
  description,
  impact = [],
  confirmLabel = "Подтвердить",
  requireText = "",
  requireHint = "для подтверждения",
  busy,
  onConfirm,
  onClose,
}) {
  const [typed, setTyped] = useState("");
  const titleId = useId();
  const descriptionId = useId();
  const dialogRef = useDialogAccessibility(open, busy ? undefined : onClose);

  useEffect(() => {
    if (open) setTyped("");
  }, [open]);
  if (!open) return null;
  const allowed = !requireText || typed === requireText;
  const dialog = (
    <div
      className="confirm-overlay"
      role="presentation"
      onMouseDown={(event) => {
        if (!busy && event.target === event.currentTarget) onClose?.();
      }}
    >
      <section
        ref={dialogRef}
        className="confirm-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descriptionId : undefined}
        tabIndex={-1}
      >
        <h2 id={titleId}>{title}</h2>
        {description ? <p id={descriptionId}>{description}</p> : null}
        {impact.length ? (
          <ul>
            {impact.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        ) : null}
        {requireText ? (
          <label className="field">
            <span>
              Введите <code>{requireText}</code>, {requireHint}
            </span>
            <input
              value={typed}
              onChange={(event) => setTyped(event.target.value)}
              autoFocus
            />
          </label>
        ) : null}
        <div className="confirm-dialog__actions">
          <Button variant="secondary" disabled={busy} onClick={onClose}>
            Отмена
          </Button>
          <Button
            variant="danger"
            disabled={!allowed}
            busy={busy}
            onClick={onConfirm}
          >
            {confirmLabel}
          </Button>
        </div>
      </section>
    </div>
  );
  return typeof document === "undefined"
    ? dialog
    : createPortal(dialog, document.body);
}
