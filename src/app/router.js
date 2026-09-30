import { useCallback, useEffect, useMemo, useState } from "react";
import { recordFrontendEvent } from "../diagnostics.js";
import {
  defaultRoutePath,
  normalizeRoutePath,
  routeById,
  routeByPath,
} from "./navigation.js";

function routePathFromHash(hash) {
  const id = String(hash || "").replace(/^#/, "");
  return routeById(id)?.path || null;
}

function currentBrowserLocation() {
  if (typeof window === "undefined")
    return { path: defaultRoutePath, search: "" };
  const legacyPath =
    window.location.pathname === "/"
      ? routePathFromHash(window.location.hash)
      : null;
  return {
    path: normalizeRoutePath(legacyPath || window.location.pathname),
    search: window.location.search,
  };
}

export function useRouter() {
  const [location, setLocation] = useState(currentBrowserLocation);
  const { path, search } = location;

  useEffect(() => {
    const initialLocation = currentBrowserLocation();
    if (
      typeof window !== "undefined" &&
      window.location.pathname !== initialLocation.path
    ) {
      window.history.replaceState(
        {},
        "",
        initialLocation.path + initialLocation.search,
      );
    }
    setLocation(initialLocation);

    const handlePopState = () => {
      const nextLocation = currentBrowserLocation();
      setLocation((currentLocation) => {
        recordFrontendEvent("ui.navigation", {
          from: currentLocation.path,
          to: nextLocation.path,
          navigation_type: "popstate",
        });
        return nextLocation;
      });
    };
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  const navigate = useCallback(
    (targetPath) => {
      const target = new URL(String(targetPath || "/"), window.location.origin);
      const nextPath = normalizeRoutePath(target.pathname);
      const nextSearch = target.search;
      if (nextPath === path && nextSearch === search) return;
      recordFrontendEvent("ui.navigation", {
        from: path,
        to: nextPath,
        navigation_type: "push",
      });
      window.history.pushState({}, "", nextPath + nextSearch);
      setLocation({ path: nextPath, search: nextSearch });
      window.scrollTo({ top: 0, behavior: "instant" });
    },
    [path, search],
  );

  const route = useMemo(() => routeByPath(path), [path]);
  return { navigate, path, search, route };
}
