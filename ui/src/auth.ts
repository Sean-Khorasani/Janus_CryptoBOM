export const authChangedEvent = "janus:auth-changed";

export function clearSession() {
  localStorage.removeItem("janus_token");
  localStorage.removeItem("janus_user");
  localStorage.removeItem("janus_role");
}

export function hasSession(): boolean {
  const token = localStorage.getItem("janus_token");
  const user = localStorage.getItem("janus_user");
  const role = localStorage.getItem("janus_role");
  if (!token || !user || !role) return false;

  try {
    const payload = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    if (typeof payload.exp === "number" && payload.exp * 1000 <= Date.now()) {
      clearSession();
      return false;
    }
  } catch {
    clearSession();
    return false;
  }

  return true;
}

export function notifyAuthChanged() {
  window.dispatchEvent(new Event(authChangedEvent));
}
