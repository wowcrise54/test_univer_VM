import { createRoot } from "react-dom/client";
import { App } from "./app/App.jsx";
import { AppProviders } from "./app/providers.jsx";
import { initializeTheme } from "./app/theme.jsx";
import { installGlobalDiagnostics } from "./diagnostics.js";
import "./styles/index.css";

installGlobalDiagnostics();
const initialTheme = initializeTheme();

createRoot(document.getElementById("root")).render(
  <AppProviders initialTheme={initialTheme}>
    <App />
  </AppProviders>,
);
