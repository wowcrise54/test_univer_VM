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
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
      />
      <span>{label}</span>
    </label>
  );
}

export function Panel({
  id,
  eyebrow,
  title,
  description,
  action,
  children,
  className = "",
  ...props
}) {
  return (
    <section id={id} className={`panel ${className}`} {...props}>
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

export function ConfirmDialog({
  open,
  title,
  description,
  impact = [],
  confirmLabel = "Подтвердить",
  requireText = "",
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
        aria-describedby={descriptionId}
        tabIndex={-1}
      >
        <span className="confirm-dialog__eyebrow">Подтверждение действия</span>
        <h2 id={titleId}>{title}</h2>
        <p id={descriptionId}>{description}</p>
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
              Введите <code>{requireText}</code>, чтобы подтвердить изменение MP
              VM
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
