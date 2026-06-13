export function authenticatedHeaders(): Record<string, string> {
  const token = localStorage.getItem("janus_token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function escapeHTML(value: string) {
  return value.replace(/[&<>"']/g, character => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;"
  })[character] || character);
}

function jsonReportDocument(value: string) {
  let formatted = value;
  try {
    formatted = JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    // Preserve the server response when it is not valid JSON.
  }
  return `<!doctype html><html><head><meta charset="utf-8"><title>Janus Findings JSON</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#17211c;background:#f7f8f5}.toolbar{display:flex;gap:8px;margin-bottom:16px}.toolbar button,.toolbar a{border:1px solid #dfe5dc;border-radius:5px;background:#fff;color:#17211c;padding:8px 12px;text-decoration:none;cursor:pointer}pre{overflow:auto;border:1px solid #dfe5dc;border-radius:6px;background:#fff;padding:16px;white-space:pre-wrap;word-break:break-word}</style>
</head><body><nav class="toolbar" aria-label="Report navigation"><button type="button" onclick="history.length > 1 ? history.back() : location.assign('/')">Back</button><a href="/">Home</a></nav><h1>Findings JSON</h1><pre>${escapeHTML(formatted)}</pre></body></html>`;
}

function withApplicationBase(document: string) {
  const base = `<base href="${escapeHTML(window.location.origin)}/">`;
  return /<head(?:\s[^>]*)?>/i.test(document)
    ? document.replace(/<head(?:\s[^>]*)?>/i, match => `${match}${base}`)
    : `${base}${document}`;
}

export async function openAuthenticatedResource(url: string, mediaType: string) {
  // `noopener` in window.open features makes modern browsers return null, which
  // previously left a blank tab and navigated the dashboard as a fallback.
  const popup = window.open("about:blank", "_blank");
  if (!popup) throw new Error("The report tab was blocked by the browser. Allow pop-ups for Janus and try again.");
  popup.document.title = "Loading Janus report";
  popup.document.body.textContent = "Loading report...";

  try {
    const response = await fetch(url, { headers: authenticatedHeaders() });
    if (!response.ok) throw new Error((await response.text()) || `HTTP ${response.status}`);
    const body = await response.text();
    const content = withApplicationBase(mediaType === "application/json" ? jsonReportDocument(body) : body);
    popup.document.open();
    popup.document.write(content);
    popup.document.close();
  } catch (error) {
    popup.close();
    throw error;
  }
}
