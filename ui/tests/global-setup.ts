import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

export default async function globalSetup() {
  let token = "e30.eyJzdWIiOiJ0ZXN0LWFkbWluIiwicm9sZSI6ImFkbWluIiwiZXhwIjo0MTAyNDQ0ODAwfQ.signature";
  let user = "test-admin";

  try {
    const response = await fetch("http://127.0.0.1:8080/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "janus-admin-pass" }),
      signal: AbortSignal.timeout(1500)
    });
    if (response.ok) {
      const body = await response.json() as { token: string };
      token = body.token;
      user = "admin";
    }
  } catch {
    // Offline UI tests use mocked API responses and only require a valid-shaped session.
  }

  const output = path.resolve("test-results/auth-state.json");
  await mkdir(path.dirname(output), { recursive: true });
  await writeFile(output, JSON.stringify({
    cookies: [],
    origins: [{
      origin: "http://localhost:5173",
      localStorage: [
        { name: "janus_token", value: token },
        { name: "janus_user", value: user },
        { name: "janus_role", value: "admin" }
      ]
    }]
  }));
}
