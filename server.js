const express = require("express");
const cors = require("cors");
const fs = require("fs/promises");
const path = require("path");
const crypto = require("crypto");
const { randomUUID } = crypto;

const app = express();
const PORT = process.env.PORT || 3000;

const dataDir = path.join(__dirname, "data");
const usersFile = path.join(dataDir, "users.json");
const messagesFile = path.join(dataDir, "messages.json");
const secretFile = path.join(dataDir, "secret.key");

const TTL_MS = 3 * 24 * 60 * 60 * 1000; // 3 days

app.use(cors());
app.use(express.json({ limit: "16kb" }));
app.use(express.static(path.join(__dirname, "public")));

function sanitizeUsername(input) {
  return String(input || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.-]/g, "")
    .slice(0, 28);
}

function sanitizeMessage(input) {
  return String(input || "").trim().slice(0, 300);
}

function sanitizeOwnerKey(input) {
  const k = String(input || "").trim();
  if (!k) return "";
  // allow base64url-ish and uuid-ish strings
  return k.replace(/[^a-zA-Z0-9._~-]/g, "").slice(0, 120);
}

async function ensureDataFiles() {
  await fs.mkdir(dataDir, { recursive: true });

  for (const [file, fallback] of [
    [usersFile, "[]"],
    [messagesFile, "[]"],
  ]) {
    try {
      await fs.access(file);
    } catch {
      await fs.writeFile(file, fallback, "utf8");
    }
  }
}

async function readJSON(file, fallback) {
  try {
    const raw = await fs.readFile(file, "utf8");
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

async function writeJSON(file, data) {
  await fs.writeFile(file, JSON.stringify(data, null, 2), "utf8");
}

async function getOrCreateSecretKey() {
  try {
    const raw = await fs.readFile(secretFile, "utf8");
    const buf = Buffer.from(raw.trim(), "base64");
    if (buf.length === 32) return buf;
  } catch {
    // ignore
  }
  const key = crypto.randomBytes(32);
  await fs.writeFile(secretFile, key.toString("base64"), "utf8");
  return key;
}

let SECRET_KEY = null;

function encryptText(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", SECRET_KEY, iv);
  const ct = Buffer.concat([cipher.update(String(plain), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("base64"),
    ct: ct.toString("base64"),
    tag: tag.toString("base64"),
  };
}

function decryptText(payload) {
  // Backward compatibility if older messages stored plaintext
  if (payload && typeof payload.text === "string") return payload.text;
  if (!payload || !payload.iv || !payload.ct || !payload.tag) return "";
  const iv = Buffer.from(payload.iv, "base64");
  const ct = Buffer.from(payload.ct, "base64");
  const tag = Buffer.from(payload.tag, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", SECRET_KEY, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt.toString("utf8");
}

async function cleanupExpired() {
  const now = Date.now();

  const users = await readJSON(usersFile, []);
  const activeUsers = users.filter((u) => !u.expiresAt || u.expiresAt > now);
  const activeSet = new Set(activeUsers.map((u) => u.username));
  if (activeUsers.length !== users.length) await writeJSON(usersFile, activeUsers);

  const messages = await readJSON(messagesFile, []);
  const cleanedMessages = messages.filter((m) => {
    const freshEnough = !m.ts || m.ts > now - TTL_MS;
    const userActive = !m.to || activeSet.has(m.to);
    return freshEnough && userActive;
  });
  if (cleanedMessages.length !== messages.length) await writeJSON(messagesFile, cleanedMessages);
}

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, mode: "production-ready" });
});

app.post("/api/users", async (req, res) => {
  const username = sanitizeUsername(req.body?.username);
  const ownerKey = sanitizeOwnerKey(req.body?.ownerKey);
  if (!username) {
    return res.status(400).json({ error: "Invalid username" });
  }
  if (!ownerKey) {
    return res.status(400).json({ error: "Missing ownerKey" });
  }

  await cleanupExpired();

  const users = await readJSON(usersFile, []);
  const existing = users.find((u) => u.username === username);
  const now = Date.now();
  if (existing) {
    if (existing.ownerKey && existing.ownerKey !== ownerKey) {
      return res.status(409).json({ error: "Username taken" });
    }
    existing.ownerKey = ownerKey;
    existing.expiresAt = now + TTL_MS;
    await writeJSON(usersFile, users);
  } else {
    users.push({
      username,
      ownerKey,
      createdAt: now,
      expiresAt: now + TTL_MS,
    });
    await writeJSON(usersFile, users);
  }

  return res.json({ username, link: `/Whisp.html?to=${encodeURIComponent(username)}` });
});

app.get("/api/users/:username", async (req, res) => {
  const username = sanitizeUsername(req.params.username);
  if (!username) {
    return res.status(400).json({ error: "Invalid username" });
  }

  await cleanupExpired();
  const users = await readJSON(usersFile, []);
  const user = users.find((u) => u.username === username);
  return res.json({ exists: Boolean(user), username, expiresAt: user?.expiresAt || null });
});

app.post("/api/messages", async (req, res) => {
  const to = sanitizeUsername(req.body?.to);
  const text = sanitizeMessage(req.body?.text);

  if (!to || !text) {
    return res.status(400).json({ error: "Missing recipient or message" });
  }

  await cleanupExpired();

  const users = await readJSON(usersFile, []);
  const hasUser = users.some((u) => u.username === to);
  if (!hasUser) {
    const now = Date.now();
    users.push({ username: to, ownerKey: "", createdAt: now, expiresAt: now + TTL_MS });
    await writeJSON(usersFile, users);
  }

  const messages = await readJSON(messagesFile, []);
  const enc = encryptText(text);
  messages.unshift({
    id: randomUUID(),
    to,
    iv: enc.iv,
    ct: enc.ct,
    tag: enc.tag,
    ts: Date.now(),
  });
  await writeJSON(messagesFile, messages);
  return res.status(201).json({ ok: true });
});

app.get("/api/messages/:username", async (req, res) => {
  const username = sanitizeUsername(req.params.username);
  if (!username) {
    return res.status(400).json({ error: "Invalid username" });
  }

  await cleanupExpired();
  const messages = await readJSON(messagesFile, []);
  const userMessages = messages
    .filter((m) => m.to === username)
    .map((m) => ({
      id: m.id,
      to: m.to,
      text: decryptText(m),
      ts: m.ts,
    }));
  return res.json({ messages: userMessages });
});

app.delete("/api/messages/:id", async (req, res) => {
  const id = String(req.params.id || "").trim();
  const to = sanitizeUsername(req.body?.to);
  const ownerKey = sanitizeOwnerKey(req.body?.ownerKey);
  if (!id || !to || !ownerKey) {
    return res.status(400).json({ error: "Missing id/to/ownerKey" });
  }

  await cleanupExpired();

  const users = await readJSON(usersFile, []);
  const user = users.find((u) => u.username === to);
  if (!user || !user.ownerKey || user.ownerKey !== ownerKey) {
    return res.status(403).json({ error: "Not allowed" });
  }

  const messages = await readJSON(messagesFile, []);
  const before = messages.length;
  const after = messages.filter((m) => !(m.id === id && m.to === to));
  if (after.length === before) return res.status(404).json({ error: "Not found" });
  await writeJSON(messagesFile, after);
  return res.json({ ok: true });
});

app.use((_req, res) => {
  res.sendFile(path.join(__dirname, "public", "Whisp.html"));
});

ensureDataFiles()
  .then(async () => {
    SECRET_KEY = await getOrCreateSecretKey();
    await cleanupExpired();
    setInterval(() => cleanupExpired().catch(() => {}), 60 * 60 * 1000);
    app.listen(PORT, () => {
      console.log(`Whisp running on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error("Failed to initialize data files", err);
    process.exit(1);
  });
