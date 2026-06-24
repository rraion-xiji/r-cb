const SESSION_TTL_DAYS = 30;
const DEFAULT_AUTO_DELETE_DAYS = 30;
const MAX_AUTO_DELETE_DAYS = 365;

function json(data, init = {}) {
  return new Response(JSON.stringify(data), {
    ...init,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...(init.headers || {})
    }
  });
}

function errorResponse(status, message) {
  return json({ error: message }, { status });
}

function pad(value) {
  return String(value).padStart(2, "0");
}

function nowIso() {
  return new Date().toISOString();
}

function isoAfterDays(days) {
  return new Date(Date.now() + days * 86400000).toISOString();
}

function remainingTimeString(unlockTime) {
  if (!unlockTime) {
    return "--:--:--";
  }

  const remainingMs = new Date(unlockTime).getTime() - Date.now();
  if (remainingMs <= 0) {
    return "00:00:00";
  }

  const hours = Math.floor(remainingMs / 3600000);
  const minutes = Math.floor((remainingMs % 3600000) / 60000);
  const seconds = Math.floor((remainingMs % 60000) / 1000);
  return `${pad(hours)}:${pad(minutes)}:${pad(seconds)}`;
}

function normalizeAccount(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeProfileField(value) {
  return normalizeAccount(value);
}

function normalizeAutoDeleteDays(value) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) {
    return DEFAULT_AUTO_DELETE_DAYS;
  }
  return Math.min(Math.max(parsed, 1), MAX_AUTO_DELETE_DAYS);
}

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function hashPassword(password, salt) {
  return sha256Hex(`${salt}:${password}`);
}

async function parseJson(request) {
  try {
    return await request.json();
  } catch {
    throw new Error("Request body must be valid JSON");
  }
}

async function getUserByAccount(db, account) {
  return db.prepare(
    `SELECT id, account, password_salt, password_hash, dom, sub, auto_delete_days, delete_at, created_at, updated_at
     FROM users
     WHERE account = ?`
  ).bind(account).first();
}

async function getUserById(db, userId) {
  return db.prepare(
    `SELECT id, account, dom, sub, auto_delete_days, delete_at, created_at, updated_at
     FROM users
     WHERE id = ?`
  ).bind(userId).first();
}

async function ensureRelationshipTargetsExist(db, dom, sub) {
  for (const field of [dom, sub]) {
    if (!field) {
      continue;
    }
    const target = await getUserByAccount(db, field);
    if (!target) {
      throw new Error(`Referenced account "${field}" does not exist`);
    }
  }
}

async function clearReverseBinding(db, account, counterpartColumn, counterpartValue) {
  if (!account) {
    return;
  }
  await db.prepare(
    `UPDATE users
     SET ${counterpartColumn} = '', updated_at = ?
     WHERE account = ? AND ${counterpartColumn} = ?`
  ).bind(nowIso(), account, counterpartValue).run();
}

async function validateOneToOneTargets(db, currentUser, dom, sub) {
  if (dom && dom === currentUser.account) {
    throw new Error("dom cannot reference the current account");
  }
  if (sub && sub === currentUser.account) {
    throw new Error("sub cannot reference the current account");
  }
  if (dom && sub && dom === sub) {
    throw new Error("dom and sub must reference different accounts");
  }

  if (dom) {
    const domUser = await getUserByAccount(db, dom);
    if (!domUser) {
      throw new Error(`Referenced account "${dom}" does not exist`);
    }
    if (domUser.sub && domUser.sub !== currentUser.account) {
      throw new Error(`Account "${dom}" is already paired as sub with another user`);
    }
  }

  if (sub) {
    const subUser = await getUserByAccount(db, sub);
    if (!subUser) {
      throw new Error(`Referenced account "${sub}" does not exist`);
    }
    if (subUser.dom && subUser.dom !== currentUser.account) {
      throw new Error(`Account "${sub}" is already paired as dom with another user`);
    }
  }
}

async function cleanupExpiredRecords(db) {
  const now = nowIso();
  await db.batch([
    db.prepare("DELETE FROM sessions WHERE expires_at <= ?").bind(now),
    db.prepare(
      `UPDATE users
       SET dom = ''
       WHERE dom IN (SELECT account FROM users WHERE delete_at IS NOT NULL AND delete_at <= ?)`
    ).bind(now),
    db.prepare(
      `UPDATE users
       SET sub = ''
       WHERE sub IN (SELECT account FROM users WHERE delete_at IS NOT NULL AND delete_at <= ?)`
    ).bind(now),
    db.prepare("DELETE FROM lock_events WHERE user_id IN (SELECT id FROM users WHERE delete_at IS NOT NULL AND delete_at <= ?)").bind(now),
    db.prepare("DELETE FROM lock_state WHERE user_id IN (SELECT id FROM users WHERE delete_at IS NOT NULL AND delete_at <= ?)").bind(now),
    db.prepare("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE delete_at IS NOT NULL AND delete_at <= ?)").bind(now),
    db.prepare("DELETE FROM users WHERE delete_at IS NOT NULL AND delete_at <= ?").bind(now)
  ]);
}

async function ensureUserState(db, userId) {
  await db.prepare(
    `INSERT OR IGNORE INTO lock_state (user_id, locked, unlock_time, scheduled_at, updated_by, updated_at)
     VALUES (?, 1, NULL, NULL, 'system', datetime('now'))`
  ).bind(userId).run();
}

async function createSession(db, userId) {
  const token = crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
  const createdAt = nowIso();
  const expiresAt = isoAfterDays(SESSION_TTL_DAYS);
  await db.prepare(
    `INSERT INTO sessions (id, user_id, created_at, expires_at)
     VALUES (?, ?, ?, ?)`
  ).bind(token, userId, createdAt, expiresAt).run();
  return { token, expiresAt };
}

async function touchUserRetention(db, user) {
  const refreshedDeleteAt = isoAfterDays(user.auto_delete_days || DEFAULT_AUTO_DELETE_DAYS);
  await db.prepare(
    `UPDATE users
     SET delete_at = ?, updated_at = ?
     WHERE id = ?`
  ).bind(refreshedDeleteAt, nowIso(), user.id).run();

  return {
    ...user,
    delete_at: refreshedDeleteAt
  };
}

function serializeUser(user) {
  return {
    id: user.id,
    account: user.account,
    dom: user.dom,
    sub: user.sub,
    autoDeleteDays: user.auto_delete_days,
    deleteAt: user.delete_at,
    createdAt: user.created_at,
    updatedAt: user.updated_at
  };
}

async function authenticate(request, db) {
  const authHeader = request.headers.get("authorization") || "";
  const prefix = "Bearer ";
  if (!authHeader.startsWith(prefix)) {
    throw new Response(JSON.stringify({ error: "Missing bearer token" }), {
      status: 401,
      headers: { "content-type": "application/json; charset=utf-8" }
    });
  }

  const token = authHeader.slice(prefix.length).trim();
  if (!token) {
    throw new Response(JSON.stringify({ error: "Missing bearer token" }), {
      status: 401,
      headers: { "content-type": "application/json; charset=utf-8" }
    });
  }

  const session = await db.prepare(
    `SELECT
       sessions.id,
       sessions.expires_at,
       users.id AS user_id,
       users.account,
       users.dom,
       users.sub,
       users.auto_delete_days,
       users.delete_at,
       users.created_at,
       users.updated_at
     FROM sessions
     JOIN users ON users.id = sessions.user_id
     WHERE sessions.id = ?`
  ).bind(token).first();

  if (!session) {
    throw new Response(JSON.stringify({ error: "Session not found" }), {
      status: 401,
      headers: { "content-type": "application/json; charset=utf-8" }
    });
  }

  if (new Date(session.expires_at).getTime() <= Date.now()) {
    await db.prepare("DELETE FROM sessions WHERE id = ?").bind(token).run();
    throw new Response(JSON.stringify({ error: "Session expired" }), {
      status: 401,
      headers: { "content-type": "application/json; charset=utf-8" }
    });
  }

  const user = await touchUserRetention(db, {
    id: session.user_id,
    account: session.account,
    dom: session.dom,
    sub: session.sub,
    auto_delete_days: session.auto_delete_days,
    delete_at: session.delete_at,
    created_at: session.created_at,
    updated_at: session.updated_at
  });

  return { token, user };
}

async function loadState(db, user) {
  await ensureUserState(db, user.id);
  const record = await db.prepare(
    `SELECT user_id, locked, unlock_time, scheduled_at, updated_by, updated_at
     FROM lock_state
     WHERE user_id = ?`
  ).bind(user.id).first();

  if (!record) {
    throw new Error("lock_state row missing");
  }

  const unlockTime = record.unlock_time || null;
  const expired = unlockTime && new Date(unlockTime).getTime() <= Date.now();

  if (expired && Number(record.locked) === 1) {
    const currentIso = nowIso();
    await db.batch([
      db.prepare(
        `UPDATE lock_state
         SET locked = 0, unlock_time = NULL, scheduled_at = NULL, updated_by = ?, updated_at = ?
         WHERE user_id = ?`
      ).bind("system-auto-unlock", currentIso, user.id),
      db.prepare(
        `INSERT INTO lock_events (user_id, event_type, locked, unlock_time, remaining_time, source, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).bind(user.id, "auto_unlock", 0, null, "00:00:00", "system", currentIso)
    ]);

    return {
      user: serializeUser(user),
      locked: false,
      unlockTime: null,
      scheduledAt: null,
      remainingTime: "--:--:--",
      updatedAt: currentIso,
      updatedBy: "system-auto-unlock"
    };
  }

  return {
    user: serializeUser(user),
    locked: Number(record.locked) === 1,
    unlockTime,
    scheduledAt: record.scheduled_at || null,
    remainingTime: remainingTimeString(unlockTime),
    updatedAt: record.updated_at,
    updatedBy: record.updated_by
  };
}

async function handleRegister(request, env) {
  const body = await parseJson(request);
  const account = normalizeAccount(body.account);
  const password = String(body.password || "");
  const dom = normalizeProfileField(body.dom);
  const sub = normalizeProfileField(body.sub);
  const autoDeleteDays = normalizeAutoDeleteDays(body.autoDeleteDays);

  if (!account || account.length < 3) {
    return errorResponse(400, "account must be at least 3 characters");
  }
  if (!password || password.length < 6) {
    return errorResponse(400, "password must be at least 6 characters");
  }

  const existingUser = await getUserByAccount(env.DB, account);
  if (existingUser) {
    return errorResponse(409, "account already exists");
  }

  try {
    await validateOneToOneTargets(env.DB, { account }, dom, sub);
  } catch (error) {
    return errorResponse(400, error.message);
  }

  const currentIso = nowIso();
  const deleteAt = isoAfterDays(autoDeleteDays);
  const salt = crypto.randomUUID();
  const passwordHash = await hashPassword(password, salt);
  const insertResult = await env.DB.prepare(
    `INSERT INTO users (account, password_salt, password_hash, dom, sub, auto_delete_days, delete_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(account, salt, passwordHash, dom, sub, autoDeleteDays, deleteAt, currentIso, currentIso).run();

  const userId = insertResult.meta.last_row_id;
  await ensureUserState(env.DB, userId);
  const reciprocalUpdates = [
    ...(dom ? [
      env.DB.prepare(
        `UPDATE users
         SET sub = ?, updated_at = ?
         WHERE account = ?`
      ).bind(account, currentIso, dom)
    ] : []),
    ...(sub ? [
      env.DB.prepare(
        `UPDATE users
         SET dom = ?, updated_at = ?
         WHERE account = ?`
      ).bind(account, currentIso, sub)
    ] : [])
  ];
  if (reciprocalUpdates.length) {
    await env.DB.batch(reciprocalUpdates);
  }
  const session = await createSession(env.DB, userId);
  const user = await getUserById(env.DB, userId);

  return json({
    token: session.token,
    sessionExpiresAt: session.expiresAt,
    user: serializeUser(user)
  }, { status: 201 });
}

async function handleLogin(request, env) {
  const body = await parseJson(request);
  const account = normalizeAccount(body.account);
  const password = String(body.password || "");
  const user = await getUserByAccount(env.DB, account);

  if (!user) {
    return errorResponse(401, "invalid account or password");
  }

  const passwordHash = await hashPassword(password, user.password_salt);
  if (passwordHash !== user.password_hash) {
    return errorResponse(401, "invalid account or password");
  }

  const refreshedUser = await touchUserRetention(env.DB, user);
  const session = await createSession(env.DB, user.id);
  await ensureUserState(env.DB, user.id);

  return json({
    token: session.token,
    sessionExpiresAt: session.expiresAt,
    user: serializeUser(refreshedUser)
  });
}

async function handleLogout(request, env) {
  const { token } = await authenticate(request, env.DB);
  await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(token).run();
  return json({ ok: true });
}

async function handleGetMe(request, env) {
  const { user } = await authenticate(request, env.DB);
  return json({ user: serializeUser(user) });
}

async function handleListUsers(request, env) {
  await authenticate(request, env.DB);
  const results = await env.DB.prepare(
    `SELECT id, account, dom, sub, auto_delete_days, delete_at, created_at, updated_at
     FROM users
     ORDER BY created_at DESC`
  ).all();
  return json({ users: (results.results || []).map(serializeUser) });
}

async function handleUpdateProfile(request, env) {
  const { user } = await authenticate(request, env.DB);
  const body = await parseJson(request);
  const dom = normalizeProfileField(body.dom);
  const sub = normalizeProfileField(body.sub);

  try {
    await validateOneToOneTargets(env.DB, user, dom, sub);
  } catch (error) {
    return errorResponse(400, error.message);
  }

  const currentIso = nowIso();
  await clearReverseBinding(env.DB, user.dom, "sub", user.account);
  await clearReverseBinding(env.DB, user.sub, "dom", user.account);

  await env.DB.batch([
    env.DB.prepare(
      `UPDATE users
       SET dom = ?, sub = ?, updated_at = ?
       WHERE id = ?`
    ).bind(dom, sub, currentIso, user.id),
    ...(dom ? [
      env.DB.prepare(
        `UPDATE users
         SET sub = ?, updated_at = ?
         WHERE account = ?`
      ).bind(user.account, currentIso, dom)
    ] : []),
    ...(sub ? [
      env.DB.prepare(
        `UPDATE users
         SET dom = ?, updated_at = ?
         WHERE account = ?`
      ).bind(user.account, currentIso, sub)
    ] : [])
  ]);

  const updatedUser = await getUserById(env.DB, user.id);
  return json({ user: serializeUser(updatedUser) });
}

async function handlePlanet(request, env) {
  await authenticate(request, env.DB);
  const results = await env.DB.prepare(
    `SELECT id, account, dom, sub, created_at
     FROM users
     ORDER BY created_at ASC`
  ).all();
  const users = results.results || [];
  const knownAccounts = new Set(users.map((user) => user.account));
  const nodes = users.map((user) => ({
    id: user.account,
    label: user.account,
    dom: user.dom,
    sub: user.sub
  }));
  const links = [];

  for (const user of users) {
    if (user.sub && knownAccounts.has(user.sub)) {
      links.push({
        source: user.account,
        target: user.sub,
        type: "dom_to_sub"
      });
    }
  }

  return json({ nodes, links });
}

async function handleDeleteAccount(request, env) {
  const { user, token } = await authenticate(request, env.DB);
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET dom = '' WHERE dom = ?").bind(user.account),
    env.DB.prepare("UPDATE users SET sub = '' WHERE sub = ?").bind(user.account),
    env.DB.prepare("DELETE FROM lock_events WHERE user_id = ?").bind(user.id),
    env.DB.prepare("DELETE FROM lock_state WHERE user_id = ?").bind(user.id),
    env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(user.id),
    env.DB.prepare("DELETE FROM users WHERE id = ?").bind(user.id)
  ]);
  return json({ ok: true, deletedToken: token });
}

async function handleGetState(request, env) {
  const { user } = await authenticate(request, env.DB);
  const state = await loadState(env.DB, user);
  return json(state);
}

async function handlePostState(request, env) {
  const { user } = await authenticate(request, env.DB);
  const body = await parseJson(request);
  const locked = body.locked ? 1 : 0;
  const unlockTime = body.unlockTime || null;
  const source = typeof body.source === "string" && body.source ? body.source : "unknown";

  if (unlockTime) {
    const parsed = new Date(unlockTime);
    if (Number.isNaN(parsed.getTime())) {
      return errorResponse(400, "unlockTime must be a valid ISO datetime");
    }
  }

  const currentIso = nowIso();
  const scheduledAt = unlockTime ? currentIso : null;
  await ensureUserState(env.DB, user.id);
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE lock_state
       SET locked = ?, unlock_time = ?, scheduled_at = ?, updated_by = ?, updated_at = ?
       WHERE user_id = ?`
    ).bind(locked, unlockTime, scheduledAt, source, currentIso, user.id),
    env.DB.prepare(
      `INSERT INTO lock_events (user_id, event_type, locked, unlock_time, remaining_time, source, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(user.id, "state_update", locked, unlockTime, remainingTimeString(unlockTime), source, currentIso)
  ]);

  const state = await loadState(env.DB, user);
  return json(state);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      await cleanupExpiredRecords(env.DB);

      if (url.pathname === "/api/register" && request.method === "POST") {
        return handleRegister(request, env);
      }
      if (url.pathname === "/api/login" && request.method === "POST") {
        return handleLogin(request, env);
      }
      if (url.pathname === "/api/logout" && request.method === "POST") {
        return handleLogout(request, env);
      }
      if (url.pathname === "/api/me" && request.method === "GET") {
        return handleGetMe(request, env);
      }
      if (url.pathname === "/api/users" && request.method === "GET") {
        return handleListUsers(request, env);
      }
      if (url.pathname === "/api/planet" && request.method === "GET") {
        return handlePlanet(request, env);
      }
      if (url.pathname === "/api/account/profile" && request.method === "PATCH") {
        return handleUpdateProfile(request, env);
      }
      if (url.pathname === "/api/account" && request.method === "DELETE") {
        return handleDeleteAccount(request, env);
      }
      if (url.pathname === "/api/state") {
        if (request.method === "GET") {
          return handleGetState(request, env);
        }
        if (request.method === "POST") {
          return handlePostState(request, env);
        }
        return new Response("Method Not Allowed", {
          status: 405,
          headers: { allow: "GET, POST" }
        });
      }
      if (url.pathname === "/") {
        return env.ASSETS.fetch(new Request(new URL("/index.html", request.url), request));
      }

      return env.ASSETS.fetch(request);
    } catch (error) {
      if (error instanceof Response) {
        return error;
      }
      return json({ error: error.message || "Internal error" }, { status: 500 });
    }
  }
};
