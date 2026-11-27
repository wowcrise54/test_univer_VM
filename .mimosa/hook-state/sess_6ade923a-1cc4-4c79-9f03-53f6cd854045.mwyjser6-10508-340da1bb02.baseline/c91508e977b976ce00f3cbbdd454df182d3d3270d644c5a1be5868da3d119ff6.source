// Raised when the server rejects a request because the session's access no
// longer matches what the UI shows: a permission was removed or added through
// a role change, or the session was revoked. AuthGate listens for it and
// re-reads the current user.
export const ACCESS_CHANGED_EVENT = "mpvm:access-changed";

const ACCESS_CHANGE_CODES = new Map([
  [401, "AUTH_REQUIRED"],
  [403, "PERMISSION_DENIED"],
]);

export function notifyAccessChangedIfNeeded({ path, status, code }) {
  if (typeof window === "undefined") return;
  // /api/auth/* answers describe the session itself; re-reading it would loop.
  if (String(path || "").startsWith("/api/auth/")) return;
  if (ACCESS_CHANGE_CODES.get(status) !== code) return;
  window.dispatchEvent(
    new CustomEvent(ACCESS_CHANGED_EVENT, { detail: { path, status, code } }),
  );
}
