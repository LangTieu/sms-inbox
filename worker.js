// DDL (liaison runs when creating DB):
// CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, from_number TEXT, to_number TEXT, body TEXT, received_at TEXT, created_at INTEGER);
// CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, password_hash TEXT, salt TEXT, failed_attempts INTEGER DEFAULT 0, locked_until INTEGER DEFAULT 0, created_at INTEGER);
// CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, email TEXT, expires_at INTEGER);

// telnyx-sms-relay: forwards inbound Telnyx SMS (message.received) to
// Telegram, Discord and WhatsApp. Stateless; never logs message content.

const MAX_SKEW_SECONDS = 300;
const WHATSAPP_API_VERSION = "v21.0";
const ALLOWED_EMAILS = new Set([
  "tranbinhanbr01@gmail.com",
  "lethanhdongus@gmail.com",
  "admin@aistockvn.com",
]);
const PBKDF2_ITERATIONS = 100000;
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const LOCKOUT_THRESHOLD = 5;
const LOCKOUT_SECONDS = 15 * 60;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const method = request.method.toUpperCase();

    if (method === "GET" && path === "/health") {
      return new Response("ok", { status: 200 });
    }

    if (method === "GET" && (path === "/" || path === "/style.css" || path === "/app.js")) {
      return serveUi(path);
    }

    if (path === "/telnyx" || path === "/") {
      if (path === "/telnyx" || (path === "/" && method === "POST")) {
        if (method !== "POST") {
          return new Response("method not allowed", { status: 405, headers: { allow: "POST" } });
        }
        return handleTelnyx(request, env, ctx);
      }
    }

    if (path.startsWith("/api/") || path === "/api") {
      return handleApi(request, env, path, method);
    }

    if (method === "GET") {
      return new Response("not found", { status: 404 });
    }
    return new Response("not found", { status: 404 });
  },
};

async function handleTelnyx(request, env, ctx) {
  const rawBody = await request.text();

  if (env.TELNYX_PUBLIC_KEY) {
    const ok = await verifyTelnyxSignature(
      env.TELNYX_PUBLIC_KEY,
      request.headers.get("telnyx-signature-ed25519"),
      request.headers.get("telnyx-timestamp"),
      rawBody,
    );
    if (!ok) {
      console.log("relay: rejected request with invalid signature or timestamp");
      return new Response("invalid signature", { status: 401 });
    }
  }

  let event;
  try {
    event = JSON.parse(rawBody);
  } catch {
    return new Response("invalid json", { status: 400 });
  }

  const data = event && event.data;
  if (!data || data.event_type !== "message.received") {
    return new Response("ignored", { status: 200 });
  }

  if (env.DB && data.id) {
    try {
      const payload = data.payload || {};
      const fromNumber = phoneOf(payload.from);
      const toList = Array.isArray(payload.to) ? payload.to : [payload.to];
      const toNumber = toList.map(phoneOf).join(", ");
      const body = typeof payload.text === "string" ? payload.text : "";
      const receivedAt = payload.received_at || payload.sent_at || payload.completed_at || null;
      const createdAt = Math.floor(Date.now() / 1000);
      await env.DB.prepare(
        "INSERT OR IGNORE INTO messages (id, from_number, to_number, body, received_at, created_at) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(String(data.id), fromNumber, toNumber, body, receivedAt, createdAt).run();
    } catch (err) {
      console.log("relay: db insert failed");
    }
  }

  const message = formatMessage((data && data.payload) || {});
  const targets = forwardTargets(env);
  if (targets.length === 0) {
    console.log("relay: message received, no forwarding targets configured");
    return new Response("ok", { status: 200 });
  }

  // Answer Telnyx immediately; forwarding continues in the background.
  ctx.waitUntil(forwardAll(targets, message));
  return new Response("ok", { status: 200 });
}

async function handleApi(request, env, path, method) {
  const jsonHeaders = { "content-type": "application/json; charset=utf-8" };

  if (path === "/api/auth/login") {
    if (method !== "POST") return json({ error: "method not allowed" }, 405, jsonHeaders);
    return handleLogin(request, env);
  }
  if (path === "/api/auth/logout") {
    if (method !== "POST") return json({ error: "method not allowed" }, 405, jsonHeaders);
    return handleLogout(request, env);
  }
  if (path === "/api/auth/register") {
    if (method !== "POST") return json({ error: "method not allowed" }, 405, jsonHeaders);
    return handleRegister(request, env);
  }
  if (path === "/api/auth/me") {
    if (method !== "GET") return json({ error: "method not allowed" }, 405, jsonHeaders);
    const auth = await requireAuth(request, env);
    if (!auth.ok) return json({ error: "unauthorized" }, 401, jsonHeaders);
    return json({ email: auth.email }, 200, jsonHeaders);
  }
  if (path === "/api/messages") {
    if (method !== "GET") return json({ error: "method not allowed" }, 405, jsonHeaders);
    const auth = await requireAuth(request, env);
    if (!auth.ok) return json({ error: "unauthorized" }, 401, jsonHeaders);
    return handleListMessages(request, env);
  }
  if (path.startsWith("/api/messages/")) {
    if (method !== "GET") return json({ error: "method not allowed" }, 405, jsonHeaders);
    const auth = await requireAuth(request, env);
    if (!auth.ok) return json({ error: "unauthorized" }, 401, jsonHeaders);
    const id = decodeURIComponent(path.slice("/api/messages/".length));
    return handleGetMessage(env, id);
  }
  if (path === "/api/stats") {
    if (method !== "GET") return json({ error: "method not allowed" }, 405, jsonHeaders);
    const auth = await requireAuth(request, env);
    if (!auth.ok) return json({ error: "unauthorized" }, 401, jsonHeaders);
    return handleStats(env);
  }

  return json({ error: "not found" }, 404, jsonHeaders);
}

function json(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...extraHeaders },
  });
}

function parseCookies(request) {
  const header = request.headers.get("cookie") || "";
  const out = {};
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(new Uint8Array(hash));
}

function randomHex(bytesLen) {
  const bytes = new Uint8Array(bytesLen);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: hexToBytes(saltHex), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return bytesToHex(new Uint8Array(bits));
}

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const aBytes = new TextEncoder().encode(a);
  const bBytes = new TextEncoder().encode(b);
  if (aBytes.length !== bBytes.length) return false;
  let diff = 0;
  for (let i = 0; i < aBytes.length; i++) diff |= aBytes[i] ^ bBytes[i];
  return diff === 0;
}

async function readJsonBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

async function requireAuth(request, env) {
  if (!env.DB) return { ok: false };
  const cookies = parseCookies(request);
  const token = cookies.session;
  if (!token) return { ok: false };
  const tokenHash = await sha256Hex(token);
  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(
    "SELECT email, expires_at FROM sessions WHERE token_hash = ?"
  ).bind(tokenHash).first();
  if (!row) return { ok: false };
  if (row.expires_at <= now) {
    try {
      await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
    } catch {}
    return { ok: false };
  }
  return { ok: true, email: row.email };
}

function sessionCookie(token, maxAge = SESSION_TTL_SECONDS) {
  return `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

async function handleLogin(request, env) {
  if (!env.DB) return json({ error: "unauthorized" }, 401);
  const body = await readJsonBody(request);
  const email = body && typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = body && typeof body.password === "string" ? body.password : "";
  if (!ALLOWED_EMAILS.has(email) || !password) {
    return json({ error: "invalid credentials" }, 401);
  }
  const user = await env.DB.prepare(
    "SELECT email, password_hash, salt, failed_attempts, locked_until FROM users WHERE email = ?"
  ).bind(email).first();
  const now = Math.floor(Date.now() / 1000);
  if (!user) {
    return json({ error: "invalid credentials" }, 401);
  }
  if (user.locked_until && user.locked_until > now) {
    return json({ error: "invalid credentials" }, 401);
  }
  const computed = await hashPassword(password, user.salt);
  if (!timingSafeEqual(computed, user.password_hash)) {
    const failed = (user.failed_attempts || 0) + 1;
    let lockedUntil = user.locked_until || 0;
    if (failed >= LOCKOUT_THRESHOLD) {
      lockedUntil = now + LOCKOUT_SECONDS;
    }
    await env.DB.prepare(
      "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE email = ?"
    ).bind(failed >= LOCKOUT_THRESHOLD ? 0 : failed, lockedUntil, email).run();
    return json({ error: "invalid credentials" }, 401);
  }

  await env.DB.prepare(
    "UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE email = ?"
  ).bind(email).run();
  const token = randomHex(32);
  const tokenHash = await sha256Hex(token);
  const expiresAt = now + SESSION_TTL_SECONDS;
  await env.DB.prepare(
    "INSERT INTO sessions (token_hash, email, expires_at) VALUES (?, ?, ?)"
  ).bind(tokenHash, email, expiresAt).run();
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "set-cookie": sessionCookie(token),
    },
  });
}

async function handleLogout(request, env) {
  const cookies = parseCookies(request);
  const token = cookies.session;
  if (token && env.DB) {
    try {
      const tokenHash = await sha256Hex(token);
      await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
    } catch {}
  }
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "set-cookie": sessionCookie("", 0),
    },
  });
}

async function handleRegister(request, env) {
  if (!env.DB) return json({ error: "forbidden" }, 403);
  const countRow = await env.DB.prepare("SELECT COUNT(*) AS c FROM users").first();
  const count = countRow ? (countRow.c || countRow["COUNT(*)"] || 0) : 0;
  if (Number(count) !== 0) {
    return json({ error: "forbidden" }, 403);
  }
  const body = await readJsonBody(request);
  const email = body && typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = body && typeof body.password === "string" ? body.password : "";
  if (!ALLOWED_EMAILS.has(email)) {
    return json({ error: "forbidden" }, 403);
  }
  if (password.length < 10) {
    return json({ error: "invalid password" }, 400);
  }
  const salt = randomHex(16);
  const passwordHash = await hashPassword(password, salt);
  const createdAt = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    "INSERT INTO users (email, password_hash, salt, failed_attempts, locked_until, created_at) VALUES (?, ?, ?, 0, 0, ?)"
  ).bind(email, passwordHash, salt, createdAt).run();
  return json({ ok: true }, 201);
}

async function handleListMessages(request, env) {
  if (!env.DB) return json({ messages: [] }, 200);
  const url = new URL(request.url);
  let limit = parseInt(url.searchParams.get("limit") || "50", 10);
  if (!Number.isFinite(limit) || limit <= 0) limit = 50;
  if (limit > 200) limit = 200;
  const before = url.searchParams.get("before");
  const q = (url.searchParams.get("q") || "").trim();

  let beforeRow = null;
  if (before) {
    beforeRow = await env.DB.prepare(
      "SELECT id, received_at, created_at FROM messages WHERE id = ?"
    ).bind(before).first();
  }

  let sql = "SELECT id, from_number, to_number, body, received_at, created_at FROM messages";
  const conds = [];
  const args = [];
  if (q) {
    conds.push("(body LIKE ? OR from_number LIKE ? OR to_number LIKE ?)");
    const like = `%${q}%`;
    args.push(like, like, like);
  }
  if (beforeRow) {
    conds.push("(created_at < ? OR (created_at = ? AND id < ?))");
    args.push(beforeRow.created_at ?? 0, beforeRow.created_at ?? 0, beforeRow.id);
  }
  if (conds.length) sql += " WHERE " + conds.join(" AND ");
  sql += " ORDER BY created_at DESC, id DESC LIMIT ?";
  args.push(limit);

  const result = await env.DB.prepare(sql).bind(...args).all();
  const messages = (result && result.results) ? result.results : [];
  return json({ messages }, 200);
}

async function handleGetMessage(env, id) {
  if (!env.DB) return json({ error: "not found" }, 404);
  const row = await env.DB.prepare(
    "SELECT id, from_number, to_number, body, received_at, created_at FROM messages WHERE id = ?"
  ).bind(id).first();
  if (!row) return json({ error: "not found" }, 404);
  return json(row, 200);
}

async function handleStats(env) {
  if (!env.DB) return json({ total: 0, today: 0 }, 200);
  const totalRow = await env.DB.prepare("SELECT COUNT(*) AS total FROM messages").first();
  const total = totalRow ? Number(totalRow.total || totalRow.c || 0) : 0;
  const startOfToday = new Date();
  startOfToday.setUTCHours(0, 0, 0, 0);
  const startTs = Math.floor(startOfToday.getTime() / 1000);
  const todayRow = await env.DB.prepare(
    "SELECT COUNT(*) AS today FROM messages WHERE created_at >= ?"
  ).bind(startTs).first();
  const today = todayRow ? Number(todayRow.today || todayRow.c || 0) : 0;
  return json({ total, today }, 200);
}


const UI_HTML_B64 = "PCFkb2N0eXBlIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KICA8aGVhZD4KICAgIDxtZXRhIGNoYXJzZXQ9InV0Zi04IiAvPgogICAgPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xIiAvPgogICAgPG1ldGEgbmFtZT0idGhlbWUtY29sb3IiIGNvbnRlbnQ9IiNmZmZmZmYiIC8+CiAgICA8dGl0bGU+QUkgU3RvY2sgVk4gU01TPC90aXRsZT4KICAgIDxtZXRhIG5hbWU9ImRlc2NyaXB0aW9uIiBjb250ZW50PSJSZWFkIHlvdXIgU01TIG1lc3NhZ2VzIGluIEFJIFN0b2NrIFZOIFNNUy4iIC8+CiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9Ii9zdHlsZS5jc3MiIC8+CiAgPC9oZWFkPgogIDxib2R5PgogICAgPCEtLSBMb2dpbiAtLT4KICAgIDxtYWluIGlkPSJsb2dpbi12aWV3IiBjbGFzcz0ibG9naW4iIGhpZGRlbj4KICAgICAgPGZvcm0gaWQ9ImxvZ2luLWZvcm0iIGNsYXNzPSJsb2dpbi1jYXJkIiBub3ZhbGlkYXRlPgogICAgICAgIDxoMSBjbGFzcz0ibG9naW4tdGl0bGUiPkFJIFN0b2NrIFZOIFNNUzwvaDE+CiAgICAgICAgPHAgY2xhc3M9ImxvZ2luLXN1YiI+U2lnbiBpbiB0byByZWFkIHlvdXIgU01TLjwvcD4KCiAgICAgICAgPGxhYmVsIGNsYXNzPSJmaWVsZCI+CiAgICAgICAgICA8c3BhbiBjbGFzcz0iZmllbGQtbGFiZWwiPkVtYWlsPC9zcGFuPgogICAgICAgICAgPGlucHV0IGlkPSJsb2dpbi1lbWFpbCIgbmFtZT0iZW1haWwiIHR5cGU9ImVtYWlsIiBhdXRvY29tcGxldGU9InVzZXJuYW1lIiByZXF1aXJlZCAvPgogICAgICAgIDwvbGFiZWw+CgogICAgICAgIDxsYWJlbCBjbGFzcz0iZmllbGQiPgogICAgICAgICAgPHNwYW4gY2xhc3M9ImZpZWxkLWxhYmVsIj5QYXNzd29yZDwvc3Bhbj4KICAgICAgICAgIDxpbnB1dCBpZD0ibG9naW4tcGFzc3dvcmQiIG5hbWU9InBhc3N3b3JkIiB0eXBlPSJwYXNzd29yZCIgYXV0b2NvbXBsZXRlPSJjdXJyZW50LXBhc3N3b3JkIiByZXF1aXJlZCAvPgogICAgICAgIDwvbGFiZWw+CgogICAgICAgIDxidXR0b24gaWQ9ImxvZ2luLXN1Ym1pdCIgY2xhc3M9ImJ0biBidG4tcHJpbWFyeSBidG4tYmxvY2siIHR5cGU9InN1Ym1pdCI+U2lnbiBpbjwvYnV0dG9uPgogICAgICAgIDxwIGlkPSJsb2dpbi1lcnJvciIgY2xhc3M9ImVycm9yLWxpbmUiIHJvbGU9ImFsZXJ0IiBoaWRkZW4+PC9wPgogICAgICA8L2Zvcm0+CiAgICA8L21haW4+CgogICAgPCEtLSBJbmJveCAtLT4KICAgIDxkaXYgaWQ9ImluYm94LXZpZXciIGNsYXNzPSJhcHAiIGhpZGRlbj4KICAgICAgPGhlYWRlciBjbGFzcz0idG9wYmFyIj4KICAgICAgICA8ZGl2IGNsYXNzPSJicmFuZCI+QUkgU3RvY2sgVk4gU01TPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0ic2VhcmNoIj4KICAgICAgICAgIDxpbnB1dCBpZD0ic2VhcmNoIiB0eXBlPSJzZWFyY2giIHBsYWNlaG9sZGVyPSJTZWFyY2ggc2VuZGVyIG9yIG1lc3NhZ2UiIGFyaWEtbGFiZWw9IlNlYXJjaCBtZXNzYWdlcyIgYXV0b2NvbXBsZXRlPSJvZmYiIC8+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0idG9wYmFyLXJpZ2h0Ij4KICAgICAgICAgIDxzcGFuIGlkPSJjb3VudCIgY2xhc3M9ImNvdW50IiBhcmlhLWxpdmU9InBvbGl0ZSI+PC9zcGFuPgogICAgICAgICAgPGJ1dHRvbiBpZD0icmVmcmVzaCIgY2xhc3M9ImJ0biIgdHlwZT0iYnV0dG9uIj5SZWZyZXNoPC9idXR0b24+CiAgICAgICAgICA8YnV0dG9uIGlkPSJsb2dvdXQiIGNsYXNzPSJidG4iIHR5cGU9ImJ1dHRvbiI+U2lnbiBvdXQ8L2J1dHRvbj4KICAgICAgICA8L2Rpdj4KICAgICAgPC9oZWFkZXI+CiAgICAgIDxwIGlkPSJpbmJveC1lcnJvciIgY2xhc3M9ImVycm9yLWxpbmUgZXJyb3ItYmFyIiByb2xlPSJhbGVydCIgaGlkZGVuPjwvcD4KCiAgICAgIDxkaXYgY2xhc3M9ImxheW91dCIgaWQ9ImxheW91dCI+CiAgICAgICAgPHNlY3Rpb24gY2xhc3M9Imxpc3QtcGFuZSIgYXJpYS1sYWJlbD0iTWVzc2FnZXMiPgogICAgICAgICAgPHVsIGlkPSJsaXN0IiBjbGFzcz0ibGlzdCI+PC91bD4KICAgICAgICAgIDxwIGlkPSJsaXN0LXN0YXR1cyIgY2xhc3M9Imxpc3Qtc3RhdHVzIiByb2xlPSJzdGF0dXMiPjwvcD4KICAgICAgICAgIDxkaXYgY2xhc3M9Imxpc3QtbW9yZSI+CiAgICAgICAgICAgIDxidXR0b24gaWQ9ImxvYWQtbW9yZSIgY2xhc3M9ImJ0biBidG4tYmxvY2siIHR5cGU9ImJ1dHRvbiIgaGlkZGVuPkxvYWQgbW9yZTwvYnV0dG9uPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9zZWN0aW9uPgoKICAgICAgICA8c2VjdGlvbiBjbGFzcz0iZGV0YWlsLXBhbmUiIGFyaWEtbGFiZWw9Ik1lc3NhZ2UiPgogICAgICAgICAgPGJ1dHRvbiBpZD0iYmFjayIgY2xhc3M9ImJ0biBiYWNrLWJ0biIgdHlwZT0iYnV0dG9uIj5CYWNrIHRvIG1lc3NhZ2VzPC9idXR0b24+CiAgICAgICAgICA8ZGl2IGlkPSJkZXRhaWwtZW1wdHkiIGNsYXNzPSJkZXRhaWwtZW1wdHkiPlNlbGVjdCBhIG1lc3NhZ2UgdG8gcmVhZCBpdC48L2Rpdj4KICAgICAgICAgIDxhcnRpY2xlIGlkPSJkZXRhaWwiIGNsYXNzPSJkZXRhaWwiIGhpZGRlbj4KICAgICAgICAgICAgPGRsIGNsYXNzPSJtZXRhIj4KICAgICAgICAgICAgICA8ZHQ+RnJvbTwvZHQ+CiAgICAgICAgICAgICAgPGRkIGlkPSJkLWZyb20iPjwvZGQ+CiAgICAgICAgICAgICAgPGR0PlRvPC9kdD4KICAgICAgICAgICAgICA8ZGQgaWQ9ImQtdG8iPjwvZGQ+CiAgICAgICAgICAgICAgPGR0PlJlY2VpdmVkPC9kdD4KICAgICAgICAgICAgICA8ZGQgaWQ9ImQtdGltZSI+PC9kZD4KICAgICAgICAgICAgPC9kbD4KICAgICAgICAgICAgPGRpdiBpZD0iZC1ib2R5IiBjbGFzcz0iYm9keSI+PC9kaXY+CiAgICAgICAgICA8L2FydGljbGU+CiAgICAgICAgPC9zZWN0aW9uPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgoKICAgIDxzY3JpcHQgc3JjPSIvYXBwLmpzIj48L3NjcmlwdD4KICA8L2JvZHk+CjwvaHRtbD4K";
const UI_CSS_B64 = "OnJvb3QgewogIC0tYmc6ICNmZmZmZmY7CiAgLS1zdXJmYWNlOiAjZjdmOGZhOwogIC0tYm9yZGVyOiAjZTNlNmViOwogIC0tdGV4dDogIzFhMWQyMzsKICAtLW11dGVkOiAjNjY3MDg1OwogIC0tYWNjZW50OiAjMGY3NjZlOwogIC0tYWNjZW50LWhvdmVyOiAjMGI1ZjU4OwogIC0tYWNjZW50LXNvZnQ6ICNlNmY0ZjI7CiAgLS1kYW5nZXI6ICNiNDIzMTg7CiAgLS10b3BiYXItaDogNTZweDsKfQoKKiB7CiAgYm94LXNpemluZzogYm9yZGVyLWJveDsKfQoKaHRtbCwKYm9keSB7CiAgaGVpZ2h0OiAxMDAlOwogIG1hcmdpbjogMDsKfQoKYm9keSB7CiAgZm9udC1mYW1pbHk6IHN5c3RlbS11aSwgLWFwcGxlLXN5c3RlbSwgIlNlZ29lIFVJIiwgUm9ib3RvLCAiSGVsdmV0aWNhIE5ldWUiLCBBcmlhbCwgc2Fucy1zZXJpZjsKICBmb250LXNpemU6IDE1cHg7CiAgbGluZS1oZWlnaHQ6IDEuNTsKICBjb2xvcjogdmFyKC0tdGV4dCk7CiAgYmFja2dyb3VuZDogdmFyKC0tYmcpOwp9CgpbaGlkZGVuXSB7CiAgZGlzcGxheTogbm9uZSAhaW1wb3J0YW50Owp9CgpidXR0b24sCmlucHV0IHsKICBmb250OiBpbmhlcml0OwogIGNvbG9yOiBpbmhlcml0Owp9CgovKiBCdXR0b25zICovCi5idG4gewogIGRpc3BsYXk6IGlubGluZS1mbGV4OwogIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgaGVpZ2h0OiAzNnB4OwogIHBhZGRpbmc6IDAgMTRweDsKICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJvcmRlci1yYWRpdXM6IDhweDsKICBiYWNrZ3JvdW5kOiB2YXIoLS1iZyk7CiAgY3Vyc29yOiBwb2ludGVyOwogIHdoaXRlLXNwYWNlOiBub3dyYXA7Cn0KLmJ0bjpob3ZlciB7CiAgYmFja2dyb3VuZDogdmFyKC0tc3VyZmFjZSk7Cn0KLmJ0bjpmb2N1cy12aXNpYmxlLAppbnB1dDpmb2N1cy12aXNpYmxlLAouaXRlbTpmb2N1cy12aXNpYmxlIHsKICBvdXRsaW5lOiAycHggc29saWQgdmFyKC0tYWNjZW50KTsKICBvdXRsaW5lLW9mZnNldDogMXB4Owp9Ci5idG46ZGlzYWJsZWQgewogIG9wYWNpdHk6IDAuNjsKICBjdXJzb3I6IGRlZmF1bHQ7Cn0KLmJ0bi1wcmltYXJ5IHsKICBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQpOwogIGJvcmRlci1jb2xvcjogdmFyKC0tYWNjZW50KTsKICBjb2xvcjogI2ZmZjsKICBmb250LXdlaWdodDogNjAwOwp9Ci5idG4tcHJpbWFyeTpob3ZlciB7CiAgYmFja2dyb3VuZDogdmFyKC0tYWNjZW50LWhvdmVyKTsKfQouYnRuLWJsb2NrIHsKICB3aWR0aDogMTAwJTsKfQoKLmVycm9yLWxpbmUgewogIG1hcmdpbjogMDsKICBjb2xvcjogdmFyKC0tZGFuZ2VyKTsKICBmb250LXNpemU6IDE0cHg7Cn0KCi8qIExvZ2luICovCi5sb2dpbiB7CiAgbWluLWhlaWdodDogMTAwJTsKICBkaXNwbGF5OiBmbGV4OwogIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7CiAgcGFkZGluZzogMjRweDsKfQoubG9naW4tY2FyZCB7CiAgd2lkdGg6IDEwMCU7CiAgbWF4LXdpZHRoOiAzNjBweDsKICBkaXNwbGF5OiBmbGV4OwogIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47CiAgZ2FwOiAxNnB4Owp9Ci5sb2dpbi10aXRsZSB7CiAgbWFyZ2luOiAwOwogIHRleHQtYWxpZ246IGNlbnRlcjsKICBmb250LXNpemU6IDI4cHg7CiAgZm9udC13ZWlnaHQ6IDYwMDsKICBsZXR0ZXItc3BhY2luZzogLTAuMDFlbTsKfQoubG9naW4tc3ViIHsKICBtYXJnaW46IC04cHggMCA4cHg7CiAgdGV4dC1hbGlnbjogY2VudGVyOwogIGNvbG9yOiB2YXIoLS1tdXRlZCk7Cn0KLmZpZWxkIHsKICBkaXNwbGF5OiBmbGV4OwogIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47CiAgZ2FwOiA2cHg7Cn0KLmZpZWxkLWxhYmVsIHsKICBmb250LXNpemU6IDE0cHg7CiAgZm9udC13ZWlnaHQ6IDUwMDsKfQouZmllbGQgaW5wdXQgewogIGhlaWdodDogNDRweDsKICBwYWRkaW5nOiAwIDE0cHg7CiAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICBib3JkZXItcmFkaXVzOiAxMHB4OwogIGJhY2tncm91bmQ6IHZhcigtLWJnKTsKfQoubG9naW4tY2FyZCAuYnRuLXByaW1hcnkgewogIGhlaWdodDogNDRweDsKICBib3JkZXItcmFkaXVzOiAxMHB4OwogIG1hcmdpbi10b3A6IDRweDsKfQoubG9naW4tY2FyZCAuZXJyb3ItbGluZSB7CiAgdGV4dC1hbGlnbjogY2VudGVyOwp9CgovKiBBcHAgc2hlbGwgKi8KLmFwcCB7CiAgaGVpZ2h0OiAxMDAlOwogIGRpc3BsYXk6IGZsZXg7CiAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsKfQoudG9wYmFyIHsKICBmbGV4OiBub25lOwogIGhlaWdodDogdmFyKC0tdG9wYmFyLWgpOwogIGRpc3BsYXk6IGZsZXg7CiAgYWxpZ24taXRlbXM6IGNlbnRlcjsKICBnYXA6IDE2cHg7CiAgcGFkZGluZzogMCAxNnB4OwogIGJvcmRlci1ib3R0b206IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJhY2tncm91bmQ6IHZhcigtLWJnKTsKfQouYnJhbmQgewogIGZvbnQtd2VpZ2h0OiA2MDA7CiAgd2hpdGUtc3BhY2U6IG5vd3JhcDsKfQouc2VhcmNoIHsKICBmbGV4OiAxOwogIG1heC13aWR0aDogNTIwcHg7Cn0KLnNlYXJjaCBpbnB1dCB7CiAgd2lkdGg6IDEwMCU7CiAgaGVpZ2h0OiAzNnB4OwogIHBhZGRpbmc6IDAgMTJweDsKICBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogIGJvcmRlci1yYWRpdXM6IDhweDsKICBiYWNrZ3JvdW5kOiB2YXIoLS1zdXJmYWNlKTsKfQoudG9wYmFyLXJpZ2h0IHsKICBtYXJnaW4tbGVmdDogYXV0bzsKICBkaXNwbGF5OiBmbGV4OwogIGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgZ2FwOiA4cHg7Cn0KLmNvdW50IHsKICBjb2xvcjogdmFyKC0tbXV0ZWQpOwogIGZvbnQtc2l6ZTogMTNweDsKICBtYXJnaW4tcmlnaHQ6IDRweDsKICB3aGl0ZS1zcGFjZTogbm93cmFwOwp9Ci5lcnJvci1iYXIgewogIGZsZXg6IG5vbmU7CiAgcGFkZGluZzogOHB4IDE2cHg7CiAgYmFja2dyb3VuZDogI2ZlZjNmMjsKICBib3JkZXItYm90dG9tOiAxcHggc29saWQgI2ZlY2RjYTsKfQoKLmxheW91dCB7CiAgZmxleDogMTsKICBtaW4taGVpZ2h0OiAwOwogIGRpc3BsYXk6IGZsZXg7Cn0KCi8qIExpc3QgKi8KLmxpc3QtcGFuZSB7CiAgd2lkdGg6IDM2MHB4OwogIGZsZXg6IG5vbmU7CiAgZGlzcGxheTogZmxleDsKICBmbGV4LWRpcmVjdGlvbjogY29sdW1uOwogIG92ZXJmbG93LXk6IGF1dG87CiAgYm9yZGVyLXJpZ2h0OiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKfQoubGlzdCB7CiAgbGlzdC1zdHlsZTogbm9uZTsKICBtYXJnaW46IDA7CiAgcGFkZGluZzogMDsKfQouaXRlbSB7CiAgZGlzcGxheTogYmxvY2s7CiAgd2lkdGg6IDEwMCU7CiAgcGFkZGluZzogMTJweCAxNnB4OwogIGJvcmRlcjogMDsKICBib3JkZXItYm90dG9tOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKICBiYWNrZ3JvdW5kOiB2YXIoLS1iZyk7CiAgdGV4dC1hbGlnbjogbGVmdDsKICBjdXJzb3I6IHBvaW50ZXI7Cn0KLml0ZW06aG92ZXIgewogIGJhY2tncm91bmQ6IHZhcigtLXN1cmZhY2UpOwp9Ci5pdGVtW2FyaWEtY3VycmVudD0idHJ1ZSJdIHsKICBiYWNrZ3JvdW5kOiB2YXIoLS1hY2NlbnQtc29mdCk7Cn0KLml0ZW0tcm93IHsKICBkaXNwbGF5OiBmbGV4OwogIGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsKICBnYXA6IDEycHg7Cn0KLml0ZW0tZnJvbSB7CiAgZm9udC13ZWlnaHQ6IDYwMDsKICBvdmVyZmxvdzogaGlkZGVuOwogIHRleHQtb3ZlcmZsb3c6IGVsbGlwc2lzOwogIHdoaXRlLXNwYWNlOiBub3dyYXA7Cn0KLml0ZW0tdGltZSB7CiAgZmxleDogbm9uZTsKICBjb2xvcjogdmFyKC0tbXV0ZWQpOwogIGZvbnQtc2l6ZTogMTJweDsKICBsaW5lLWhlaWdodDogMjJweDsKfQouaXRlbS1wcmV2aWV3IHsKICBtYXJnaW4tdG9wOiAycHg7CiAgY29sb3I6IHZhcigtLW11dGVkKTsKICBmb250LXNpemU6IDE0cHg7CiAgb3ZlcmZsb3c6IGhpZGRlbjsKICB0ZXh0LW92ZXJmbG93OiBlbGxpcHNpczsKICB3aGl0ZS1zcGFjZTogbm93cmFwOwp9Ci5saXN0LXN0YXR1cyB7CiAgbWFyZ2luOiAwOwogIHBhZGRpbmc6IDI0cHggMTZweDsKICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgY29sb3I6IHZhcigtLW11dGVkKTsKfQoubGlzdC1zdGF0dXM6ZW1wdHkgewogIGRpc3BsYXk6IG5vbmU7Cn0KLmxpc3QtbW9yZSB7CiAgcGFkZGluZzogMTJweCAxNnB4IDIwcHg7Cn0KLmxpc3QtbW9yZVtoaWRkZW5dIHsKICBkaXNwbGF5OiBub25lOwp9CgovKiBEZXRhaWwgKi8KLmRldGFpbC1wYW5lIHsKICBmbGV4OiAxOwogIG1pbi13aWR0aDogMDsKICBvdmVyZmxvdy15OiBhdXRvOwogIHBhZGRpbmc6IDI0cHggMzJweDsKfQouYmFjay1idG4gewogIGRpc3BsYXk6IG5vbmU7CiAgbWFyZ2luLWJvdHRvbTogMTZweDsKfQouZGV0YWlsLWVtcHR5IHsKICBjb2xvcjogdmFyKC0tbXV0ZWQpOwogIHBhZGRpbmctdG9wOiA0MHB4OwogIHRleHQtYWxpZ246IGNlbnRlcjsKfQoubWV0YSB7CiAgZGlzcGxheTogZ3JpZDsKICBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IDgwcHggMWZyOwogIGdhcDogNnB4IDEycHg7CiAgbWFyZ2luOiAwIDAgMjBweDsKICBwYWRkaW5nLWJvdHRvbTogMjBweDsKICBib3JkZXItYm90dG9tOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsKfQoubWV0YSBkdCB7CiAgY29sb3I6IHZhcigtLW11dGVkKTsKfQoubWV0YSBkZCB7CiAgbWFyZ2luOiAwOwogIG92ZXJmbG93LXdyYXA6IGFueXdoZXJlOwp9Ci5ib2R5IHsKICB3aGl0ZS1zcGFjZTogcHJlLXdyYXA7CiAgb3ZlcmZsb3ctd3JhcDogYW55d2hlcmU7CiAgZm9udC1zaXplOiAxNnB4OwogIGxpbmUtaGVpZ2h0OiAxLjY7Cn0KCi8qIFJlc3BvbnNpdmUgKi8KQG1lZGlhIChtYXgtd2lkdGg6IDgwMHB4KSB7CiAgLmJyYW5kIHsKICAgIGRpc3BsYXk6IG5vbmU7CiAgfQogIC50b3BiYXIgewogICAgZ2FwOiA4cHg7CiAgICBwYWRkaW5nOiAwIDEwcHg7CiAgfQogIC5jb3VudCB7CiAgICBkaXNwbGF5OiBub25lOwogIH0KICAubGlzdC1wYW5lIHsKICAgIHdpZHRoOiAxMDAlOwogICAgYm9yZGVyLXJpZ2h0OiAwOwogIH0KICAuZGV0YWlsLXBhbmUgewogICAgZGlzcGxheTogbm9uZTsKICAgIHBhZGRpbmc6IDE2cHg7CiAgfQogIC5sYXlvdXQuc2hvdy1kZXRhaWwgLmxpc3QtcGFuZSB7CiAgICBkaXNwbGF5OiBub25lOwogIH0KICAubGF5b3V0LnNob3ctZGV0YWlsIC5kZXRhaWwtcGFuZSB7CiAgICBkaXNwbGF5OiBibG9jazsKICB9CiAgLmJhY2stYnRuIHsKICAgIGRpc3BsYXk6IGlubGluZS1mbGV4OwogIH0KfQo=";
const UI_JS_B64 = "KGZ1bmN0aW9uICgpIHsKICAidXNlIHN0cmljdCI7CgogIHZhciBQQUdFX1NJWkUgPSA1MDsKICB2YXIgU0VBUkNIX0RFTEFZID0gMzAwOwoKICB2YXIgJCA9IGZ1bmN0aW9uIChpZCkgewogICAgcmV0dXJuIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKGlkKTsKICB9OwoKICB2YXIgZWwgPSB7CiAgICBsb2dpblZpZXc6ICQoImxvZ2luLXZpZXciKSwKICAgIGxvZ2luRm9ybTogJCgibG9naW4tZm9ybSIpLAogICAgbG9naW5FbWFpbDogJCgibG9naW4tZW1haWwiKSwKICAgIGxvZ2luUGFzc3dvcmQ6ICQoImxvZ2luLXBhc3N3b3JkIiksCiAgICBsb2dpblN1Ym1pdDogJCgibG9naW4tc3VibWl0IiksCiAgICBsb2dpbkVycm9yOiAkKCJsb2dpbi1lcnJvciIpLAogICAgaW5ib3hWaWV3OiAkKCJpbmJveC12aWV3IiksCiAgICBpbmJveEVycm9yOiAkKCJpbmJveC1lcnJvciIpLAogICAgc2VhcmNoOiAkKCJzZWFyY2giKSwKICAgIGNvdW50OiAkKCJjb3VudCIpLAogICAgcmVmcmVzaDogJCgicmVmcmVzaCIpLAogICAgbG9nb3V0OiAkKCJsb2dvdXQiKSwKICAgIGxheW91dDogJCgibGF5b3V0IiksCiAgICBsaXN0OiAkKCJsaXN0IiksCiAgICBsaXN0U3RhdHVzOiAkKCJsaXN0LXN0YXR1cyIpLAogICAgbG9hZE1vcmU6ICQoImxvYWQtbW9yZSIpLAogICAgYmFjazogJCgiYmFjayIpLAogICAgZGV0YWlsOiAkKCJkZXRhaWwiKSwKICAgIGRldGFpbEVtcHR5OiAkKCJkZXRhaWwtZW1wdHkiKSwKICAgIGRGcm9tOiAkKCJkLWZyb20iKSwKICAgIGRUbzogJCgiZC10byIpLAogICAgZFRpbWU6ICQoImQtdGltZSIpLAogICAgZEJvZHk6ICQoImQtYm9keSIpLAogIH07CgogIHZhciBzdGF0ZSA9IHsKICAgIG1lc3NhZ2VzOiBbXSwKICAgIG5leHRCZWZvcmU6IG51bGwsCiAgICBxdWVyeTogIiIsCiAgICBzZWxlY3RlZElkOiBudWxsLAogICAgdG90YWw6IG51bGwsCiAgICBsaXN0VG9rZW46IDAsCiAgICBkZXRhaWxUb2tlbjogMCwKICAgIGxvYWRpbmc6IGZhbHNlLAogIH07CgogIHZhciBzZWFyY2hUaW1lciA9IG51bGw7CgogIGZ1bmN0aW9uIFVuYXV0aG9yaXplZEVycm9yKCkgewogICAgdGhpcy5uYW1lID0gIlVuYXV0aG9yaXplZEVycm9yIjsKICAgIHRoaXMubWVzc2FnZSA9ICJVbmF1dGhvcml6ZWQiOwogIH0KCiAgZnVuY3Rpb24gYXBpKHBhdGgsIG9wdGlvbnMpIHsKICAgIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9OwogICAgdmFyIGluaXQgPSB7CiAgICAgIG1ldGhvZDogb3B0aW9ucy5tZXRob2QgfHwgIkdFVCIsCiAgICAgIGNyZWRlbnRpYWxzOiAic2FtZS1vcmlnaW4iLAogICAgICBoZWFkZXJzOiB7fSwKICAgIH07CiAgICBpZiAob3B0aW9ucy5qc29uICE9PSB1bmRlZmluZWQpIHsKICAgICAgaW5pdC5oZWFkZXJzWyJDb250ZW50LVR5cGUiXSA9ICJhcHBsaWNhdGlvbi9qc29uIjsKICAgICAgaW5pdC5ib2R5ID0gSlNPTi5zdHJpbmdpZnkob3B0aW9ucy5qc29uKTsKICAgIH0KICAgIHJldHVybiBmZXRjaChwYXRoLCBpbml0KS50aGVuKGZ1bmN0aW9uIChyZXMpIHsKICAgICAgcmV0dXJuIHJlcwogICAgICAgIC5qc29uKCkKICAgICAgICAuY2F0Y2goZnVuY3Rpb24gKCkgewogICAgICAgICAgcmV0dXJuIG51bGw7CiAgICAgICAgfSkKICAgICAgICAudGhlbihmdW5jdGlvbiAoZGF0YSkgewogICAgICAgICAgaWYgKHJlcy5zdGF0dXMgPT09IDQwMSAmJiAhb3B0aW9ucy5hbGxvdzQwMSkgewogICAgICAgICAgICBzaG93TG9naW4oKTsKICAgICAgICAgICAgdGhyb3cgbmV3IFVuYXV0aG9yaXplZEVycm9yKCk7CiAgICAgICAgICB9CiAgICAgICAgICBpZiAoIXJlcy5vaykgewogICAgICAgICAgICB2YXIgZXJyID0gbmV3IEVycm9yKChkYXRhICYmIGRhdGEuZXJyb3IpIHx8ICJSZXF1ZXN0IGZhaWxlZCAoIiArIHJlcy5zdGF0dXMgKyAiKS4iKTsKICAgICAgICAgICAgZXJyLnN0YXR1cyA9IHJlcy5zdGF0dXM7CiAgICAgICAgICAgIHRocm93IGVycjsKICAgICAgICAgIH0KICAgICAgICAgIHJldHVybiBkYXRhOwogICAgICAgIH0pOwogICAgfSk7CiAgfQoKICBmdW5jdGlvbiBzaG93RXJyb3Iobm9kZSwgbWVzc2FnZSkgewogICAgaWYgKG1lc3NhZ2UpIHsKICAgICAgbm9kZS50ZXh0Q29udGVudCA9IG1lc3NhZ2U7CiAgICAgIG5vZGUuaGlkZGVuID0gZmFsc2U7CiAgICB9IGVsc2UgewogICAgICBub2RlLnRleHRDb250ZW50ID0gIiI7CiAgICAgIG5vZGUuaGlkZGVuID0gdHJ1ZTsKICAgIH0KICB9CgogIGZ1bmN0aW9uIGVycm9yVGV4dChlcnIpIHsKICAgIGlmIChlcnIgJiYgZXJyLm5hbWUgPT09ICJUeXBlRXJyb3IiKSByZXR1cm4gIk5ldHdvcmsgZXJyb3IuIFBsZWFzZSBjaGVjayB5b3VyIGNvbm5lY3Rpb24gYW5kIHRyeSBhZ2Fpbi4iOwogICAgcmV0dXJuIChlcnIgJiYgZXJyLm1lc3NhZ2UpIHx8ICJTb21ldGhpbmcgd2VudCB3cm9uZy4iOwogIH0KCiAgLyogVmlld3MgKi8KCiAgZnVuY3Rpb24gc2hvd0xvZ2luKCkgewogICAgY2xlYXJUaW1lb3V0KHNlYXJjaFRpbWVyKTsKICAgIHN0YXRlLmxpc3RUb2tlbisrOwogICAgc3RhdGUuZGV0YWlsVG9rZW4rKzsKICAgIHN0YXRlLm1lc3NhZ2VzID0gW107CiAgICBzdGF0ZS5uZXh0QmVmb3JlID0gbnVsbDsKICAgIHN0YXRlLnNlbGVjdGVkSWQgPSBudWxsOwogICAgc3RhdGUucXVlcnkgPSAiIjsKICAgIGVsLnNlYXJjaC52YWx1ZSA9ICIiOwogICAgZWwubGlzdC50ZXh0Q29udGVudCA9ICIiOwogICAgZWwuaW5ib3hWaWV3LmhpZGRlbiA9IHRydWU7CiAgICBlbC5sb2dpblZpZXcuaGlkZGVuID0gZmFsc2U7CiAgICBlbC5sb2dpblBhc3N3b3JkLnZhbHVlID0gIiI7CiAgICBlbC5sb2dpblN1Ym1pdC5kaXNhYmxlZCA9IGZhbHNlOwogICAgc2hvd0Vycm9yKGVsLmluYm94RXJyb3IsICIiKTsKICB9CgogIGZ1bmN0aW9uIHNob3dJbmJveCgpIHsKICAgIGVsLmxvZ2luVmlldy5oaWRkZW4gPSB0cnVlOwogICAgZWwuaW5ib3hWaWV3LmhpZGRlbiA9IGZhbHNlOwogICAgc2hvd0Vycm9yKGVsLmxvZ2luRXJyb3IsICIiKTsKICAgIGNsZWFyRGV0YWlsKCk7CiAgICBsb2FkTGlzdCh0cnVlKTsKICB9CgogIC8qIEZvcm1hdHRpbmcgKi8KCiAgZnVuY3Rpb24gcGFkKG4pIHsKICAgIHJldHVybiBuIDwgMTAgPyAiMCIgKyBuIDogU3RyaW5nKG4pOwogIH0KCiAgZnVuY3Rpb24gZm9ybWF0VGltZShpc28pIHsKICAgIGlmICghaXNvKSByZXR1cm4gIiI7CiAgICB2YXIgcyA9IFN0cmluZyhpc28pOwogICAgaWYgKCEvKFp8WystXVxkezJ9Oj9cZHsyfSkkL2kudGVzdChzKSkgewogICAgICBzID0gcy5yZXBsYWNlKCIgIiwgIlQiKSArICJaIjsKICAgIH0KICAgIHZhciBkID0gbmV3IERhdGUocyk7CiAgICBpZiAoaXNOYU4oZC5nZXRUaW1lKCkpKSByZXR1cm4gU3RyaW5nKGlzbyk7CiAgICByZXR1cm4gKAogICAgICBwYWQoZC5nZXREYXRlKCkpICsgIi8iICsgcGFkKGQuZ2V0TW9udGgoKSArIDEpICsgIi8iICsgZC5nZXRGdWxsWWVhcigpICsgIiAiICsgcGFkKGQuZ2V0SG91cnMoKSkgKyAiOiIgKyBwYWQoZC5nZXRNaW51dGVzKCkpCiAgICApOwogIH0KCiAgZnVuY3Rpb24gZmlyc3RMaW5lKGJvZHkpIHsKICAgIHZhciBsaW5lcyA9IFN0cmluZyhib2R5IHx8ICIiKS5zcGxpdCgvXHI/XG4vKTsKICAgIGZvciAodmFyIGkgPSAwOyBpIDwgbGluZXMubGVuZ3RoOyBpKyspIHsKICAgICAgaWYgKGxpbmVzW2ldLnRyaW0oKSkgcmV0dXJuIGxpbmVzW2ldLnRyaW0oKTsKICAgIH0KICAgIHJldHVybiAiIjsKICB9CgogIC8qIExpc3QgKi8KCiAgZnVuY3Rpb24gcmVuZGVyQ291bnQoKSB7CiAgICBpZiAoc3RhdGUucXVlcnkpIHsKICAgICAgdmFyIG4gPSBzdGF0ZS5tZXNzYWdlcy5sZW5ndGg7CiAgICAgIGVsLmNvdW50LnRleHRDb250ZW50ID0gbiArIChzdGF0ZS5uZXh0QmVmb3JlID8gIisiIDogIiIpICsgKG4gPT09IDEgPyAiIHJlc3VsdCIgOiAiIHJlc3VsdHMiKTsKICAgIH0gZWxzZSBpZiAoc3RhdGUudG90YWwgIT09IG51bGwpIHsKICAgICAgZWwuY291bnQudGV4dENvbnRlbnQgPSBzdGF0ZS50b3RhbCArIChzdGF0ZS50b3RhbCA9PT0gMSA/ICIgbWVzc2FnZSIgOiAiIG1lc3NhZ2VzIik7CiAgICB9IGVsc2UgewogICAgICBlbC5jb3VudC50ZXh0Q29udGVudCA9ICIiOwogICAgfQogIH0KCiAgZnVuY3Rpb24gYnVpbGRJdGVtKG1zZykgewogICAgdmFyIGxpID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgibGkiKTsKICAgIHZhciBidG4gPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJidXR0b24iKTsKICAgIGJ0bi50eXBlID0gImJ1dHRvbiI7CiAgICBidG4uY2xhc3NOYW1lID0gIml0ZW0iOwogICAgYnRuLmRhdGFzZXQuaWQgPSBtc2cuaWQ7CiAgICBpZiAoU3RyaW5nKG1zZy5pZCkgPT09IFN0cmluZyhzdGF0ZS5zZWxlY3RlZElkKSkgYnRuLnNldEF0dHJpYnV0ZSgiYXJpYS1jdXJyZW50IiwgInRydWUiKTsKCiAgICB2YXIgcm93ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7CiAgICByb3cuY2xhc3NOYW1lID0gIml0ZW0tcm93IjsKICAgIHZhciBmcm9tID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic3BhbiIpOwogICAgZnJvbS5jbGFzc05hbWUgPSAiaXRlbS1mcm9tIjsKICAgIGZyb20udGV4dENvbnRlbnQgPSBtc2cuZnJvbV9udW1iZXIgfHwgIlVua25vd24iOwogICAgdmFyIHRpbWUgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJzcGFuIik7CiAgICB0aW1lLmNsYXNzTmFtZSA9ICJpdGVtLXRpbWUiOwogICAgdGltZS50ZXh0Q29udGVudCA9IGZvcm1hdFRpbWUobXNnLnJlY2VpdmVkX2F0KTsKICAgIHJvdy5hcHBlbmRDaGlsZChmcm9tKTsKICAgIHJvdy5hcHBlbmRDaGlsZCh0aW1lKTsKCiAgICB2YXIgcHJldmlldyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoImRpdiIpOwogICAgcHJldmlldy5jbGFzc05hbWUgPSAiaXRlbS1wcmV2aWV3IjsKICAgIHByZXZpZXcudGV4dENvbnRlbnQgPSBmaXJzdExpbmUobXNnLmJvZHkpOwoKICAgIGJ0bi5hcHBlbmRDaGlsZChyb3cpOwogICAgYnRuLmFwcGVuZENoaWxkKHByZXZpZXcpOwogICAgbGkuYXBwZW5kQ2hpbGQoYnRuKTsKICAgIHJldHVybiBsaTsKICB9CgogIGZ1bmN0aW9uIGFwcGVuZEl0ZW1zKG1lc3NhZ2VzKSB7CiAgICB2YXIgZnJhZyA9IGRvY3VtZW50LmNyZWF0ZURvY3VtZW50RnJhZ21lbnQoKTsKICAgIG1lc3NhZ2VzLmZvckVhY2goZnVuY3Rpb24gKG0pIHsKICAgICAgZnJhZy5hcHBlbmRDaGlsZChidWlsZEl0ZW0obSkpOwogICAgfSk7CiAgICBlbC5saXN0LmFwcGVuZENoaWxkKGZyYWcpOwogIH0KCiAgZnVuY3Rpb24gdXBkYXRlTGlzdEZvb3RlcigpIHsKICAgIGVsLmxvYWRNb3JlLmhpZGRlbiA9ICFzdGF0ZS5uZXh0QmVmb3JlOwogICAgZWwubG9hZE1vcmUuZGlzYWJsZWQgPSBzdGF0ZS5sb2FkaW5nOwogICAgaWYgKHN0YXRlLmxvYWRpbmcgJiYgc3RhdGUubWVzc2FnZXMubGVuZ3RoID09PSAwKSB7CiAgICAgIGVsLmxpc3RTdGF0dXMudGV4dENvbnRlbnQgPSAiTG9hZGluZy4uLiI7CiAgICB9IGVsc2UgaWYgKCFzdGF0ZS5sb2FkaW5nICYmIHN0YXRlLm1lc3NhZ2VzLmxlbmd0aCA9PT0gMCkgewogICAgICBlbC5saXN0U3RhdHVzLnRleHRDb250ZW50ID0gc3RhdGUucXVlcnkgPyAiTm8gbWVzc2FnZXMgbWF0Y2ggeW91ciBzZWFyY2guIiA6ICJObyBtZXNzYWdlcyB5ZXQuIjsKICAgIH0gZWxzZSB7CiAgICAgIGVsLmxpc3RTdGF0dXMudGV4dENvbnRlbnQgPSAiIjsKICAgIH0KICB9CgogIGZ1bmN0aW9uIGxvYWRMaXN0KHJlc2V0KSB7CiAgICBpZiAocmVzZXQpIHsKICAgICAgc3RhdGUubGlzdFRva2VuKys7CiAgICAgIHN0YXRlLm1lc3NhZ2VzID0gW107CiAgICAgIHN0YXRlLm5leHRCZWZvcmUgPSBudWxsOwogICAgICBlbC5saXN0LnRleHRDb250ZW50ID0gIiI7CiAgICB9IGVsc2UgaWYgKCFzdGF0ZS5uZXh0QmVmb3JlKSB7CiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTsKICAgIH0KCiAgICB2YXIgdG9rZW4gPSBzdGF0ZS5saXN0VG9rZW47CiAgICB2YXIgYmVmb3JlID0gc3RhdGUubmV4dEJlZm9yZTsKICAgIHN0YXRlLmxvYWRpbmcgPSB0cnVlOwogICAgc2hvd0Vycm9yKGVsLmluYm94RXJyb3IsICIiKTsKICAgIHVwZGF0ZUxpc3RGb290ZXIoKTsKCiAgICB2YXIgcGFyYW1zID0gbmV3IFVSTFNlYXJjaFBhcmFtcygpOwogICAgcGFyYW1zLnNldCgibGltaXQiLCBTdHJpbmcoUEFHRV9TSVpFKSk7CiAgICBpZiAoIXJlc2V0ICYmIGJlZm9yZSkgcGFyYW1zLnNldCgiYmVmb3JlIiwgYmVmb3JlKTsKICAgIGlmIChzdGF0ZS5xdWVyeSkgcGFyYW1zLnNldCgicSIsIHN0YXRlLnF1ZXJ5KTsKCiAgICB2YXIgbGlzdFByb21pc2UgPSBhcGkoIi9hcGkvbWVzc2FnZXM/IiArIHBhcmFtcy50b1N0cmluZygpKQogICAgICAudGhlbihmdW5jdGlvbiAoZGF0YSkgewogICAgICAgIGlmICh0b2tlbiAhPT0gc3RhdGUubGlzdFRva2VuKSByZXR1cm47CiAgICAgICAgdmFyIGJhdGNoID0gKGRhdGEgJiYgZGF0YS5tZXNzYWdlcykgfHwgW107CiAgICAgICAgc3RhdGUubWVzc2FnZXMgPSBzdGF0ZS5tZXNzYWdlcy5jb25jYXQoYmF0Y2gpOwogICAgICAgIHN0YXRlLm5leHRCZWZvcmUgPSAoZGF0YSAmJiBkYXRhLm5leHRfYmVmb3JlKSB8fCBudWxsOwogICAgICAgIGFwcGVuZEl0ZW1zKGJhdGNoKTsKICAgICAgfSkKICAgICAgLmNhdGNoKGZ1bmN0aW9uIChlcnIpIHsKICAgICAgICBpZiAoZXJyIGluc3RhbmNlb2YgVW5hdXRob3JpemVkRXJyb3IgfHwgdG9rZW4gIT09IHN0YXRlLmxpc3RUb2tlbikgcmV0dXJuOwogICAgICAgIHNob3dFcnJvcihlbC5pbmJveEVycm9yLCBlcnJvclRleHQoZXJyKSk7CiAgICAgIH0pCiAgICAgIC50aGVuKGZ1bmN0aW9uICgpIHsKICAgICAgICBpZiAodG9rZW4gIT09IHN0YXRlLmxpc3RUb2tlbikgcmV0dXJuOwogICAgICAgIHN0YXRlLmxvYWRpbmcgPSBmYWxzZTsKICAgICAgICB1cGRhdGVMaXN0Rm9vdGVyKCk7CiAgICAgICAgcmVuZGVyQ291bnQoKTsKICAgICAgfSk7CgogICAgdmFyIHN0YXRzUHJvbWlzZSA9IHJlc2V0CiAgICAgID8gYXBpKCIvYXBpL3N0YXRzIikKICAgICAgICAgIC50aGVuKGZ1bmN0aW9uIChzKSB7CiAgICAgICAgICAgIGlmICh0b2tlbiAhPT0gc3RhdGUubGlzdFRva2VuKSByZXR1cm47CiAgICAgICAgICAgIHN0YXRlLnRvdGFsID0gcyAmJiB0eXBlb2Ygcy50b3RhbCA9PT0gIm51bWJlciIgPyBzLnRvdGFsIDogbnVsbDsKICAgICAgICAgICAgcmVuZGVyQ291bnQoKTsKICAgICAgICAgIH0pCiAgICAgICAgICAuY2F0Y2goZnVuY3Rpb24gKCkgewogICAgICAgICAgICAvKiBjb3VudCBpcyBub24tZXNzZW50aWFsICovCiAgICAgICAgICB9KQogICAgICA6IFByb21pc2UucmVzb2x2ZSgpOwoKICAgIHJldHVybiBQcm9taXNlLmFsbChbbGlzdFByb21pc2UsIHN0YXRzUHJvbWlzZV0pOwogIH0KCiAgLyogRGV0YWlsICovCgogIGZ1bmN0aW9uIGNsZWFyRGV0YWlsKCkgewogICAgc3RhdGUuc2VsZWN0ZWRJZCA9IG51bGw7CiAgICBlbC5kZXRhaWwuaGlkZGVuID0gdHJ1ZTsKICAgIGVsLmRldGFpbEVtcHR5LmhpZGRlbiA9IGZhbHNlOwogICAgZWwubGF5b3V0LmNsYXNzTGlzdC5yZW1vdmUoInNob3ctZGV0YWlsIik7CiAgICBtYXJrU2VsZWN0ZWQoKTsKICB9CgogIGZ1bmN0aW9uIG1hcmtTZWxlY3RlZCgpIHsKICAgIHZhciBpdGVtcyA9IGVsLmxpc3QucXVlcnlTZWxlY3RvckFsbCgiLml0ZW0iKTsKICAgIGZvciAodmFyIGkgPSAwOyBpIDwgaXRlbXMubGVuZ3RoOyBpKyspIHsKICAgICAgaWYgKHN0YXRlLnNlbGVjdGVkSWQgIT09IG51bGwgJiYgaXRlbXNbaV0uZGF0YXNldC5pZCA9PT0gU3RyaW5nKHN0YXRlLnNlbGVjdGVkSWQpKSB7CiAgICAgICAgaXRlbXNbaV0uc2V0QXR0cmlidXRlKCJhcmlhLWN1cnJlbnQiLCAidHJ1ZSIpOwogICAgICB9IGVsc2UgewogICAgICAgIGl0ZW1zW2ldLnJlbW92ZUF0dHJpYnV0ZSgiYXJpYS1jdXJyZW50Iik7CiAgICAgIH0KICAgIH0KICB9CgogIGZ1bmN0aW9uIHJlbmRlckRldGFpbChtc2cpIHsKICAgIGVsLmRGcm9tLnRleHRDb250ZW50ID0gbXNnLmZyb21fbnVtYmVyIHx8ICIiOwogICAgZWwuZFRvLnRleHRDb250ZW50ID0gbXNnLnRvX251bWJlciB8fCAiIjsKICAgIGVsLmRUaW1lLnRleHRDb250ZW50ID0gZm9ybWF0VGltZShtc2cucmVjZWl2ZWRfYXQpOwogICAgZWwuZEJvZHkudGV4dENvbnRlbnQgPSBtc2cuYm9keSB8fCAiIjsKICAgIGVsLmRldGFpbEVtcHR5LmhpZGRlbiA9IHRydWU7CiAgICBlbC5kZXRhaWwuaGlkZGVuID0gZmFsc2U7CiAgfQoKICBmdW5jdGlvbiBzZWxlY3RNZXNzYWdlKGlkKSB7CiAgICBzdGF0ZS5zZWxlY3RlZElkID0gaWQ7CiAgICBtYXJrU2VsZWN0ZWQoKTsKICAgIGVsLmxheW91dC5jbGFzc0xpc3QuYWRkKCJzaG93LWRldGFpbCIpOwogICAgc2hvd0Vycm9yKGVsLmluYm94RXJyb3IsICIiKTsKCiAgICB2YXIgY2FjaGVkID0gbnVsbDsKICAgIGZvciAodmFyIGkgPSAwOyBpIDwgc3RhdGUubWVzc2FnZXMubGVuZ3RoOyBpKyspIHsKICAgICAgaWYgKFN0cmluZyhzdGF0ZS5tZXNzYWdlc1tpXS5pZCkgPT09IFN0cmluZyhpZCkpIHsKICAgICAgICBjYWNoZWQgPSBzdGF0ZS5tZXNzYWdlc1tpXTsKICAgICAgICBicmVhazsKICAgICAgfQogICAgfQogICAgaWYgKGNhY2hlZCkgcmVuZGVyRGV0YWlsKGNhY2hlZCk7CgogICAgdmFyIHRva2VuID0gKytzdGF0ZS5kZXRhaWxUb2tlbjsKICAgIGFwaSgiL2FwaS9tZXNzYWdlcy8iICsgZW5jb2RlVVJJQ29tcG9uZW50KGlkKSkKICAgICAgLnRoZW4oZnVuY3Rpb24gKG1zZykgewogICAgICAgIGlmICh0b2tlbiAhPT0gc3RhdGUuZGV0YWlsVG9rZW4gfHwgIW1zZykgcmV0dXJuOwogICAgICAgIHJlbmRlckRldGFpbChtc2cpOwogICAgICB9KQogICAgICAuY2F0Y2goZnVuY3Rpb24gKGVycikgewogICAgICAgIGlmIChlcnIgaW5zdGFuY2VvZiBVbmF1dGhvcml6ZWRFcnJvciB8fCB0b2tlbiAhPT0gc3RhdGUuZGV0YWlsVG9rZW4pIHJldHVybjsKICAgICAgICBzaG93RXJyb3IoZWwuaW5ib3hFcnJvciwgZXJyb3JUZXh0KGVycikpOwogICAgICB9KTsKICB9CgogIC8qIEV2ZW50cyAqLwoKICBlbC5sb2dpbkZvcm0uYWRkRXZlbnRMaXN0ZW5lcigic3VibWl0IiwgZnVuY3Rpb24gKGUpIHsKICAgIGUucHJldmVudERlZmF1bHQoKTsKICAgIHZhciBlbWFpbCA9IGVsLmxvZ2luRW1haWwudmFsdWUudHJpbSgpOwogICAgdmFyIHBhc3N3b3JkID0gZWwubG9naW5QYXNzd29yZC52YWx1ZTsKICAgIHNob3dFcnJvcihlbC5sb2dpbkVycm9yLCAiIik7CiAgICBlbC5sb2dpblN1Ym1pdC5kaXNhYmxlZCA9IHRydWU7CgogICAgYXBpKCIvYXBpL2F1dGgvbG9naW4iLCB7IG1ldGhvZDogIlBPU1QiLCBqc29uOiB7IGVtYWlsOiBlbWFpbCwgcGFzc3dvcmQ6IHBhc3N3b3JkIH0sIGFsbG93NDAxOiB0cnVlIH0pCiAgICAgIC50aGVuKGZ1bmN0aW9uICgpIHsKICAgICAgICBzaG93SW5ib3goKTsKICAgICAgfSkKICAgICAgLmNhdGNoKGZ1bmN0aW9uIChlcnIpIHsKICAgICAgICBzaG93RXJyb3IoZWwubG9naW5FcnJvciwgZXJyb3JUZXh0KGVycikpOwogICAgICAgIGVsLmxvZ2luU3VibWl0LmRpc2FibGVkID0gZmFsc2U7CiAgICAgIH0pOwogIH0pOwoKICBlbC5saXN0LmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgZnVuY3Rpb24gKGUpIHsKICAgIHZhciBidG4gPSBlLnRhcmdldC5jbG9zZXN0KCIuaXRlbSIpOwogICAgaWYgKGJ0bikgc2VsZWN0TWVzc2FnZShidG4uZGF0YXNldC5pZCk7CiAgfSk7CgogIGVsLmxvYWRNb3JlLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgZnVuY3Rpb24gKCkgewogICAgbG9hZExpc3QoZmFsc2UpOwogIH0pOwoKICBlbC5yZWZyZXNoLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgZnVuY3Rpb24gKCkgewogICAgbG9hZExpc3QodHJ1ZSk7CiAgfSk7CgogIGVsLmJhY2suYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBmdW5jdGlvbiAoKSB7CiAgICBlbC5sYXlvdXQuY2xhc3NMaXN0LnJlbW92ZSgic2hvdy1kZXRhaWwiKTsKICB9KTsKCiAgZWwubG9nb3V0LmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgZnVuY3Rpb24gKCkgewogICAgYXBpKCIvYXBpL2F1dGgvbG9nb3V0IiwgeyBtZXRob2Q6ICJQT1NUIiwgYWxsb3c0MDE6IHRydWUgfSkKICAgICAgLmNhdGNoKGZ1bmN0aW9uICgpIHsKICAgICAgICAvKiBsZWF2ZSB0aGUgc2NyZWVuIHJlZ2FyZGxlc3MgKi8KICAgICAgfSkKICAgICAgLnRoZW4oc2hvd0xvZ2luKTsKICB9KTsKCiAgZWwuc2VhcmNoLmFkZEV2ZW50TGlzdGVuZXIoImlucHV0IiwgZnVuY3Rpb24gKCkgewogICAgY2xlYXJUaW1lb3V0KHNlYXJjaFRpbWVyKTsKICAgIHNlYXJjaFRpbWVyID0gc2V0VGltZW91dChmdW5jdGlvbiAoKSB7CiAgICAgIHZhciBxID0gZWwuc2VhcmNoLnZhbHVlLnRyaW0oKTsKICAgICAgaWYgKHEgPT09IHN0YXRlLnF1ZXJ5KSByZXR1cm47CiAgICAgIHN0YXRlLnF1ZXJ5ID0gcTsKICAgICAgbG9hZExpc3QodHJ1ZSk7CiAgICB9LCBTRUFSQ0hfREVMQVkpOwogIH0pOwoKICAvKiBCb290ICovCgogIGFwaSgiL2FwaS9hdXRoL21lIiwgeyBhbGxvdzQwMTogdHJ1ZSB9KQogICAgLnRoZW4oZnVuY3Rpb24gKCkgewogICAgICBzaG93SW5ib3goKTsKICAgIH0pCiAgICAuY2F0Y2goZnVuY3Rpb24gKGVycikgewogICAgICBzaG93TG9naW4oKTsKICAgICAgaWYgKCEoZXJyICYmIGVyci5zdGF0dXMgPT09IDQwMSkpIHNob3dFcnJvcihlbC5sb2dpbkVycm9yLCBlcnJvclRleHQoZXJyKSk7CiAgICB9KTsKfSkoKTsK";

function b64ToText(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function serveUi(path) {
  if (path === "/") return new Response(b64ToText(UI_HTML_B64), { status: 200, headers: { "content-type": "text/html; charset=utf-8" } });
  if (path === "/style.css") return new Response(b64ToText(UI_CSS_B64), { status: 200, headers: { "content-type": "text/css; charset=utf-8" } });
  return new Response(b64ToText(UI_JS_B64), { status: 200, headers: { "content-type": "text/javascript; charset=utf-8" } });
}

async function verifyTelnyxSignature(publicKeyB64, signatureB64, timestamp, rawBody) {
  if (!signatureB64 || !timestamp || !/^\d+$/.test(timestamp)) return false;

  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - Number(timestamp)) > MAX_SKEW_SECONDS) return false;

  try {
    const key = await crypto.subtle.importKey(
      "raw",
      base64ToBytes(publicKeyB64),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    const signed = new TextEncoder().encode(`${timestamp}|${rawBody}`);
    return await crypto.subtle.verify("Ed25519", key, base64ToBytes(signatureB64), signed);
  } catch (err) {
    console.log(`relay: signature verification error: ${err && err.name}`);
    return false;
  }
}

function base64ToBytes(b64) {
  const bin = atob(b64.trim());
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function phoneOf(value) {
  if (!value) return "unknown";
  if (typeof value === "string") return value;
  return value.phone_number || "unknown";
}

function formatMessage(payload) {
  const from = phoneOf(payload.from);
  const toList = Array.isArray(payload.to) ? payload.to : [payload.to];
  const to = toList.map(phoneOf).join(", ");
  const text = typeof payload.text === "string" ? payload.text : "";
  const media = Array.isArray(payload.media) ? payload.media.length : 0;
  const mediaNote = media > 0 ? `\n[${media} media attachment(s) not forwarded]` : "";
  return `SMS from ${from} to ${to}\n\n${text}${mediaNote}`;
}

function forwardTargets(env) {
  const targets = [];
  if (env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID) {
    targets.push({ name: "telegram", send: (msg) => sendTelegram(env, msg) });
  }
  if (env.DISCORD_WEBHOOK_URL) {
    targets.push({ name: "discord", send: (msg) => sendDiscord(env, msg) });
  }
  if (env.WHATSAPP_PHONE_NUMBER_ID && env.WHATSAPP_TOKEN && env.WHATSAPP_RECIPIENT) {
    targets.push({ name: "whatsapp", send: (msg) => sendWhatsApp(env, msg) });
  }
  return targets;
}

async function forwardAll(targets, message) {
  const results = await Promise.allSettled(targets.map((t) => t.send(message)));
  let ok = 0;
  results.forEach((r, i) => {
    if (r.status === "fulfilled") ok++;
    // Log only the target and a status/error name; never response bodies, which may echo content.
    else console.log(`relay: ${targets[i].name} forward failed: ${r.reason && r.reason.message}`);
  });
  console.log(`relay: forwarded 1 message, ${ok}/${targets.length} targets ok`);
}

async function postJson(url, body, headers = {}) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
}

function truncate(text, max) {
  return text.length <= max ? text : text.slice(0, max - 1) + "…";
}

function sendTelegram(env, message) {
  return postJson(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    chat_id: env.TELEGRAM_CHAT_ID,
    text: truncate(message, 4096),
    disable_web_page_preview: true,
  });
}

function sendDiscord(env, message) {
  return postJson(env.DISCORD_WEBHOOK_URL, {
    content: truncate(message, 2000),
    allowed_mentions: { parse: [] },
  });
}

function sendWhatsApp(env, message) {
  return postJson(
    `https://graph.facebook.com/${WHATSAPP_API_VERSION}/${env.WHATSAPP_PHONE_NUMBER_ID}/messages`,
    {
      messaging_product: "whatsapp",
      to: env.WHATSAPP_RECIPIENT,
      type: "text",
      text: { body: truncate(message, 4096), preview_url: false },
    },
    { authorization: `Bearer ${env.WHATSAPP_TOKEN}` },
  );
}
