import { useEffect, useRef, useState } from "react";

export type WsEvent = { type: string; [key: string]: unknown };

/**
 * Subscribe to the server's /api/ws event stream with auto-reconnect.
 *
 * The server hub broadcasts telemetry_update / finding_status /
 * migration_enqueued / migration_status / policy_switched / agent_progress /
 * agent_registered. Pass an onEvent callback; it receives each parsed message.
 *
 * Returns `connected` for a live-status indicator. Reconnects with capped
 * exponential backoff. Disabled (and any open socket closed) when `enabled`
 * is false, so it never runs on the login screen.
 *
 * NOTE: the access token is passed as a query parameter to match the server's
 * /api/ws auth path. This is a known security caveat (token leaks into logs);
 * see docs/analysis/PROJECT-REVIEW.md S3 — tracked for a signed-ticket fix.
 */
export function useWebSocket(onEvent: (event: WsEvent) => void, enabled = true): { connected: boolean } {
  const [connected, setConnected] = useState(false);
  // Keep the latest callback without forcing the connect effect to re-run.
  const handlerRef = useRef(onEvent);
  handlerRef.current = onEvent;

  useEffect(() => {
    if (!enabled) {
      setConnected(false);
      return;
    }

    let socket: WebSocket | null = null;
    let reconnectTimer: number | undefined;
    let attempt = 0;
    let closedByUs = false;

    const connect = () => {
      const token = localStorage.getItem("janus_token") || "";
      const scheme = window.location.protocol === "https:" ? "wss" : "ws";
      const url = `${scheme}://${window.location.host}/api/ws?access_token=${encodeURIComponent(token)}`;

      try {
        socket = new WebSocket(url);
      } catch {
        scheduleReconnect();
        return;
      }

      socket.onopen = () => {
        attempt = 0;
        setConnected(true);
      };
      socket.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data) as WsEvent;
          if (parsed && typeof parsed.type === "string") handlerRef.current(parsed);
        } catch {
          // Ignore non-JSON frames (e.g. keepalive pings).
        }
      };
      socket.onclose = () => {
        setConnected(false);
        if (!closedByUs) scheduleReconnect();
      };
      socket.onerror = () => {
        // onclose follows and handles reconnect; close here to be deterministic.
        socket?.close();
      };
    };

    const scheduleReconnect = () => {
      attempt += 1;
      // 1s, 2s, 4s … capped at 30s.
      const delay = Math.min(30000, 1000 * 2 ** Math.min(attempt, 5));
      reconnectTimer = window.setTimeout(connect, delay);
    };

    connect();

    return () => {
      closedByUs = true;
      if (reconnectTimer) window.clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, [enabled]);

  return { connected };
}
