// errorMessage extracts a user-facing message from a failed API response and appends
// the server correlation ID (OPS-004) so users can quote it when reporting an issue.
// The server returns the ID as `correlation_id` in 500 bodies and on the
// `X-Correlation-ID` response header of every request; we prefer the body value.
export async function errorMessage(res: Response): Promise<string> {
  const headerId = res.headers.get("X-Correlation-ID") || "";
  let text = "";
  try {
    text = await res.text();
  } catch {
    /* body already consumed or unavailable */
  }

  let msg = text;
  let bodyId = "";
  try {
    const parsed = JSON.parse(text) as { error?: unknown; correlation_id?: unknown };
    if (parsed && typeof parsed === "object") {
      if (typeof parsed.error === "string") msg = parsed.error;
      if (typeof parsed.correlation_id === "string") bodyId = parsed.correlation_id;
    }
  } catch {
    /* plain-text body — use as-is */
  }

  if (!msg) msg = `request failed (HTTP ${res.status})`;
  const ref = bodyId || headerId;
  return ref ? `${msg} (ref: ${ref})` : msg;
}
