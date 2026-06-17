import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server is configurable via env (defaults match the server's own defaults):
//   JANUS_UI_DEV_PORT     — port the Vite dev server listens on (default 5173)
//   JANUS_DEV_API_TARGET  — where /api (and the /api/ws WebSocket) are proxied
//                           (default http://127.0.0.1:8080, the server's HTTP addr)
const devPort = Number(process.env.JANUS_UI_DEV_PORT ?? 5173);
const apiTarget = process.env.JANUS_DEV_API_TARGET ?? "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    port: devPort,
    proxy: {
      // ws:true proxies the /api/ws WebSocket upgrade too — without it the dev
      // dashboard can't establish the live connection and silently falls back to
      // polling. (Production serves the SPA same-origin, so this only affects dev.)
      "/api": { target: apiTarget, ws: true }
    }
  }
});

