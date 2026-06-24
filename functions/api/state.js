function json(data, init = {}) {
  return new Response(JSON.stringify(data), {
    ...init,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...(init.headers || {})
    }
  });
}

function pad(value) {
  return String(value).padStart(2, "0");
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

async function ensureSeed(db) {
  await db.prepare(
    `INSERT OR IGNORE INTO lock_state (id, locked, unlock_time, scheduled_at, updated_by, updated_at)
     VALUES (1, 1, NULL, NULL, 'system', datetime('now'))`
  ).run();
}

async function loadState(db) {
  await ensureSeed(db);

  const record = await db.prepare(
    `SELECT id, locked, unlock_time, scheduled_at, updated_by, updated_at
     FROM lock_state
     WHERE id = 1`
  ).first();

  if (!record) {
    throw new Error("lock_state row missing");
  }

  const unlockTime = record.unlock_time || null;
  const expired = unlockTime && new Date(unlockTime).getTime() <= Date.now();

  if (expired && Number(record.locked) === 1) {
    const nowIso = new Date().toISOString();
    await db.batch([
      db.prepare(
        `UPDATE lock_state
         SET locked = 0, unlock_time = NULL, scheduled_at = NULL, updated_by = ?, updated_at = ?
         WHERE id = 1`
      ).bind("system-auto-unlock", nowIso),
      db.prepare(
        `INSERT INTO lock_events (event_type, locked, unlock_time, remaining_time, source, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      ).bind("auto_unlock", 0, null, "00:00:00", "system", nowIso)
    ]);

    return {
      locked: false,
      unlockTime: null,
      scheduledAt: null,
      remainingTime: "--:--:--",
      updatedAt: nowIso,
      updatedBy: "system-auto-unlock"
    };
  }

  return {
    locked: Number(record.locked) === 1,
    unlockTime,
    scheduledAt: record.scheduled_at || null,
    remainingTime: remainingTimeString(unlockTime),
    updatedAt: record.updated_at,
    updatedBy: record.updated_by
  };
}

export async function onRequestGet(context) {
  try {
    const state = await loadState(context.env.DB);
    return json(state);
  } catch (error) {
    return json({ error: error.message }, { status: 500 });
  }
}

export async function onRequestPost(context) {
  try {
    const body = await context.request.json();
    const locked = body.locked ? 1 : 0;
    const unlockTime = body.unlockTime || null;
    const source = typeof body.source === "string" && body.source ? body.source : "unknown";

    if (unlockTime) {
      const parsed = new Date(unlockTime);
      if (Number.isNaN(parsed.getTime())) {
        return json({ error: "unlockTime must be a valid ISO datetime" }, { status: 400 });
      }
    }

    const nowIso = new Date().toISOString();
    const scheduledAt = unlockTime ? nowIso : null;
    await ensureSeed(context.env.DB);
    await context.env.DB.batch([
      context.env.DB.prepare(
        `UPDATE lock_state
         SET locked = ?, unlock_time = ?, scheduled_at = ?, updated_by = ?, updated_at = ?
         WHERE id = 1`
      ).bind(locked, unlockTime, scheduledAt, source, nowIso),
      context.env.DB.prepare(
        `INSERT INTO lock_events (event_type, locked, unlock_time, remaining_time, source, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      ).bind("state_update", locked, unlockTime, remainingTimeString(unlockTime), source, nowIso)
    ]);

    const state = await loadState(context.env.DB);
    return json(state);
  } catch (error) {
    return json({ error: error.message }, { status: 500 });
  }
}
