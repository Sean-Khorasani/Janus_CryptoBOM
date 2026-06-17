import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { I18nProvider } from "./i18n";
import { ToastProvider } from "./hooks/useToast";
import { ErrorBoundary } from "./components/ErrorBoundary";
import "./index.css";

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary label="Janus">
      <I18nProvider>
        <ToastProvider>
          <App />
        </ToastProvider>
      </I18nProvider>
    </ErrorBoundary>
  </React.StrictMode>
);
