import { createRoot } from "react-dom/client";
import { App } from "./app/App.jsx";
import { installGlobalDiagnostics } from "./diagnostics.js";
import "./styles.css";

installGlobalDiagnostics();

createRoot(document.getElementById("root")).render(<App />);
