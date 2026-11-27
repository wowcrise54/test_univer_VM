import { createContext, useContext, useEffect, useState } from "react";

const THEME_STORAGE_KEY = "mpvm-client-theme";
const ThemeContext = createContext(null);

function readThemePreference() {
  if (typeof window === "undefined") return "light";

  try {
    return globalThis.localStorage.getItem(THEME_STORAGE_KEY) === "dark"
      ? "dark"
      : "light";
  } catch {
    return "light";
  }
}

function applyTheme(theme) {
  if (typeof document === "undefined") return;
  document.documentElement.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;
}

export function initializeTheme() {
  const theme = readThemePreference();
  applyTheme(theme);
  return theme;
}

export function ThemeProvider({ children, initialTheme }) {
  const [theme, setTheme] = useState(() =>
    initialTheme === "dark" || initialTheme === "light"
      ? initialTheme
      : readThemePreference(),
  );

  useEffect(() => {
    applyTheme(theme);
    try {
      globalThis.localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      // The theme still works for this session when storage is unavailable.
    }
  }, [theme]);

  const toggleTheme = () => {
    setTheme((currentTheme) => (currentTheme === "dark" ? "light" : "dark"));
  };

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  const theme = useContext(ThemeContext);
  if (!theme) throw new Error("useTheme must be used inside ThemeProvider");
  return theme;
}
