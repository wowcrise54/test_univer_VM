import { useCallback, useEffect, useMemo, useState } from "react";
import { recordFrontendEvent } from "../diagnostics.js";
import { defaultRoutePath, normalizeRoutePath, routeById, routeByPath } from "./navigation.js";

function routePathFromHash(hash) {
  const id = String(hash || "").replace(/^#/, "");
  return routeById(id)?.path || null;
}

function currentBrowserPath() {
  if (typeof window === "undefined") return defaultRoutePath;
  const legacyPath = window.location.pathname === "/" ? routePathFromHash(window.location.hash) : null;
  return normalizeRoutePath(legacyPath || window.location.pathname);
}

export function useRouter() {
  const [path, setPath] = useState(currentBrowserPath);

  useEffect(() => {
    const initialPath = currentBrowserPath();
    if (typeof window !== "undefined" && window.location.pathname !== initialPath) {
      window.history.replaceState({}, "", initialPath);
    }
    setPath(initialPath);

    const handlePopState = () => {
      const nextPath = currentBrowserPath();
      setPath((currentPath) => {
        recordFrontendEvent("ui.navigation", { from: currentPath, to: nextPath, navigation_type: "popstate" });
        return nextPath;
      });
    };
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  const navigate = useCallback((targetPath) => {
    const nextPath = normalizeRoutePath(targetPath);
    if (nextPath === path) return;
    recordFrontendEvent("ui.navigation", { from: path, to: nextPath, navigation_type: "push" });
    window.history.pushState({}, "", nextPath);
    setPath(nextPath);
    window.scrollTo({ top: 0, behavior: "instant" });
  }, [path]);

  const route = useMemo(() => routeByPath(path), [path]);
  return { navigate, path, route };
}
