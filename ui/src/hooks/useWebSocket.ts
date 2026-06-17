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
 * Auth: the connection is authorized by a short-lived single-use ticket. We
 * POST /api/ws/ticket with the bearer token in the Authorization header, then
 * connect with ?ticket=. This keeps the session JWT out of the URL (it would
 * otherwise leak into proxy/access logs and browser history).
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

    const connect = async () => {
      const token = localStorage.getItem("janus_token") || "";

      // Exchange the session token for a single-use WS ticket (token stays in
      // the Authorization header, never the URL).
      let ticket = "";
      try {
        const res = await fetch("/api/ws/ticket", {
          method: "POST",
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        });
        if (!res.ok) {
          scheduleReconnect();
          return;
        }
        ticket = ((await res.json()) as { ticket?: string }).ticket || "";
      } catch {
        scheduleReconnect();
        return;
      }
      // The effect may have been torn down while awaiting the ticket.
      if (closedByUs) return;

      const scheme = window.location.protocol === "https:" ? "wss" : "ws";
      const url = `${scheme}://${window.location.host}/api/ws?ticket=${encodeURIComponent(ticket)}`;

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
