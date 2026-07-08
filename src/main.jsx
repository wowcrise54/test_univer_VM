import { createRoot } from "react-dom/client";
import { App } from "./app/App.jsx";
import { AppProviders } from "./app/providers.jsx";
import { installGlobalDiagnostics } from "./diagnostics.js";
import "./styles/index.css";

installGlobalDiagnostics();

createRoot(document.getElementById("root")).render(
  <AppProviders>
    <App />
  </AppProviders>,
);
