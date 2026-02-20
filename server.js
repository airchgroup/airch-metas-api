require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const mysql = require("mysql2/promise");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";

const pool = mysql.createPool({
  host: process.env.DB_HOST || "127.0.0.1",
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASS || "",
  database: process.env.DB_NAME || "Airch Metas",
  waitForConnections: true,
  connectionLimit: 10,
});

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (!token) return res.status(401).json({ error: "NO_TOKEN" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "BAD_TOKEN" });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== "ADMIN") return res.status(403).json({ error: "FORBIDDEN" });
  next();
}

app.get("/", (req, res) => res.send("API OK"));

// LOGIN
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "MISSING_FIELDS" });

  const [rows] = await pool.query(
    "SELECT id, username, name, role, password_hash, active FROM users WHERE username=? LIMIT 1",
    [String(username)]
  );
  const u = rows?.[0];
  if (!u || !u.active) return res.status(401).json({ error: "INVALID" });

  const ok = await bcrypt.compare(String(password), u.password_hash);
  if (!ok) return res.status(401).json({ error: "INVALID" });

  const token = signToken({ id: u.id, role: u.role, name: u.name });
  res.json({ token, user: { id: u.id, role: u.role, name: u.name } });
});

// ME
app.get("/api/me", auth, async (req, res) => {
  const [rows] = await pool.query(
    "SELECT id, username, name, role, active FROM users WHERE id=? LIMIT 1",
    [req.user.id]
  );
  const u = rows?.[0];
  if (!u) return res.status(404).json({ error: "NOT_FOUND" });
  res.json({ id: u.id, role: u.role, name: u.name });
});

/* ---------------- ADMIN ---------------- */

app.get("/api/admin/users", auth, adminOnly, async (req, res) => {
  const [rows] = await pool.query(
    "SELECT id, name, username, role, active FROM users WHERE role='USER' AND active=1 ORDER BY name"
  );
  res.json({ rows });
});

app.post("/api/admin/goals", auth, adminOnly, async (req, res) => {
  const { userId, weekStart, weekEnd, name, goalType, priority, targetUnits, activeDays, bonus } = req.body || {};
  if (!userId || !weekStart || !weekEnd || !name || !goalType) {
    return res.status(400).json({ error: "MISSING_FIELDS" });
  }

  const gType = String(goalType);
  const pr = priority ? String(priority) : "PRIMARY";
  const b = Number(bonus || 0);

  let tu = 0, td = 0, adJson = null;

  if (gType === "COUNT") {
    tu = Math.max(0, Math.floor(Number(targetUnits || 0)));
    if (tu <= 0) return res.status(400).json({ error: "BAD_TARGET_UNITS" });
  } else if (gType === "DAYS") {
    const ad = Array.isArray(activeDays) ? activeDays : [0, 1, 2, 3, 4];
    const cleaned = ad.map(Number).filter((x) => x >= 0 && x <= 4);
    if (!cleaned.length) return res.status(400).json({ error: "BAD_ACTIVE_DAYS" });
    td = cleaned.length;
    adJson = JSON.stringify(cleaned);
  } else {
    return res.status(400).json({ error: "BAD_GOAL_TYPE" });
  }

  const [r] = await pool.query(
    `INSERT INTO goals
      (user_id, week_start, week_end, name, goal_type, priority, target_units, target_days, active_days_json, bonus, status)
     VALUES (?,?,?,?,?,?,?,?,?,?, 'ACTIVE')`,
    [userId, weekStart, weekEnd, String(name).trim(), gType, pr, tu, td, adJson, b]
  );

  res.json({ id: r.insertId });
});

app.patch("/api/admin/goals/:id", auth, adminOnly, async (req, res) => {
  const goalId = Number(req.params.id);
  const patch = req.body || {};

  const [rows] = await pool.query("SELECT * FROM goals WHERE id=? LIMIT 1", [goalId]);
  const g = rows?.[0];
  if (!g) return res.status(404).json({ error: "NOT_FOUND" });

  const name = patch.name != null ? String(patch.name).trim() : g.name;
  const bonus = patch.bonus != null ? Number(patch.bonus) : Number(g.bonus);

  let target_units = Number(g.target_units);
  let target_days = Number(g.target_days);
  let active_days_json = g.active_days_json;

  if (g.goal_type === "COUNT" && patch.targetUnits != null) {
    const tu = Math.max(0, Math.floor(Number(patch.targetUnits)));
    if (tu <= 0) return res.status(400).json({ error: "BAD_TARGET_UNITS" });
    target_units = tu;
  }

  if (g.goal_type === "DAYS" && patch.activeDays != null) {
    const ad = Array.isArray(patch.activeDays) ? patch.activeDays : [0, 1, 2, 3, 4];
    const cleaned = ad.map(Number).filter((x) => x >= 0 && x <= 4);
    if (!cleaned.length) return res.status(400).json({ error: "BAD_ACTIVE_DAYS" });
    target_days = cleaned.length;
    active_days_json = JSON.stringify(cleaned);
  }

  await pool.query(
    `UPDATE goals SET name=?, bonus=?, target_units=?, target_days=?, active_days_json=? WHERE id=?`,
    [name, bonus, target_units, target_days, active_days_json, goalId]
  );

  res.json({ ok: true });
});

app.post("/api/admin/goals/:id/disable", auth, adminOnly, async (req, res) => {
  const goalId = Number(req.params.id);
  await pool.query("UPDATE goals SET status='INACTIVE' WHERE id=?", [goalId]);
  res.json({ ok: true });
});

app.get("/api/admin/goals", auth, adminOnly, async (req, res) => {
  const { userId, weekStart, weekEnd } = req.query;
  if (!userId || !weekStart || !weekEnd) return res.status(400).json({ error: "MISSING_QUERY" });

  const [rows] = await pool.query(
    `SELECT id, user_id as userId, week_start as weekStart, week_end as weekEnd, name,
            goal_type as goalType, priority,
            target_units as targetUnits, target_days as targetDays,
            active_days_json as activeDaysJson,
            bonus, status, UNIX_TIMESTAMP(created_at)*1000 as createdAt
     FROM goals
     WHERE user_id=? AND week_start=? AND week_end=? AND status='ACTIVE'
     ORDER BY FIELD(priority,'PRIMARY','EXTRA'), created_at DESC`,
    [userId, weekStart, weekEnd]
  );

  res.json({
    rows: rows.map((g) => ({
      ...g,
      activeDays: g.activeDaysJson ? JSON.parse(g.activeDaysJson) : [],
    })),
  });
});

/* ---------------- USER ---------------- */

// ✅ ESTA É A ROTA QUE ESTAVA FALTANDO
app.get("/api/my/goals", auth, async (req, res) => {
  const { weekStart, weekEnd } = req.query;
  if (!weekStart || !weekEnd) return res.status(400).json({ error: "MISSING_QUERY" });

  const [rows] = await pool.query(
    `SELECT id, user_id as userId, week_start as weekStart, week_end as weekEnd, name,
            goal_type as goalType, priority,
            target_units as targetUnits, target_days as targetDays,
            active_days_json as activeDaysJson,
            bonus, status, UNIX_TIMESTAMP(created_at)*1000 as createdAt
     FROM goals
     WHERE user_id=? AND week_start=? AND week_end=? AND status='ACTIVE'
     ORDER BY FIELD(priority,'PRIMARY','EXTRA'), created_at DESC`,
    [req.user.id, weekStart, weekEnd]
  );

  res.json({
    rows: rows.map((g) => ({
      ...g,
      activeDays: g.activeDaysJson ? JSON.parse(g.activeDaysJson) : [],
    })),
  });
});

app.get("/api/my/tasks", auth, async (req, res) => {
  const goalId = Number(req.query.goalId || 0);
  if (!goalId) return res.status(400).json({ error: "MISSING_GOAL" });

  const [rows] = await pool.query(
    `SELECT id, goal_id as goalId, qty, day_date as dayDate, note,
            UNIX_TIMESTAMP(created_at)*1000 as createdAt
     FROM tasks
     WHERE user_id=? AND goal_id=?
     ORDER BY created_at DESC
     LIMIT 200`,
    [req.user.id, goalId]
  );
  res.json({ rows });
});

app.post("/api/my/tasks/count", auth, async (req, res) => {
  const { goalId, qty, note } = req.body || {};
  const gId = Number(goalId);
  const q = Math.floor(Number(qty));
  if (!gId || !q || q <= 0) return res.status(400).json({ error: "BAD_FIELDS" });

  const [gRows] = await pool.query(
    "SELECT id, goal_type as goalType FROM goals WHERE id=? AND user_id=? AND status='ACTIVE' LIMIT 1",
    [gId, req.user.id]
  );
  const g = gRows?.[0];
  if (!g || g.goalType !== "COUNT") return res.status(400).json({ error: "NOT_COUNT_GOAL" });

  await pool.query(
    `INSERT INTO tasks (user_id, goal_id, qty, day_date, note) VALUES (?,?,?,?,?)`,
    [req.user.id, gId, q, null, note ? String(note) : ""]
  );
  res.json({ ok: true });
});

app.post("/api/my/tasks/day", auth, async (req, res) => {
  const { goalId, dayDate, note } = req.body || {};
  const gId = Number(goalId);
  const d = String(dayDate || "");
  if (!gId || !d) return res.status(400).json({ error: "BAD_FIELDS" });

  const [gRows] = await pool.query(
    "SELECT id, goal_type as goalType FROM goals WHERE id=? AND user_id=? AND status='ACTIVE' LIMIT 1",
    [gId, req.user.id]
  );
  const g = gRows?.[0];
  if (!g || g.goalType !== "DAYS") return res.status(400).json({ error: "NOT_DAYS_GOAL" });

  try {
    await pool.query(
      `INSERT INTO tasks (user_id, goal_id, qty, day_date, note) VALUES (?,?,?,?,?)`,
      [req.user.id, gId, 1, d, note ? String(note) : ""]
    );
    res.json({ ok: true });
  } catch {
    // UNIQUE (goal_id, day_date) evita duplicar o mesmo dia
    res.json({ ok: true, already: true });
  }
});

app.listen(PORT, async () => {
  console.log(`✅ API rodando em http://127.0.0.1:${PORT}`);
  try {
    await pool.query("SELECT 1");
    console.log(`✅ MySQL conectado: ${process.env.DB_NAME || "Airch Metas"}`);
  } catch (e) {
    console.log("❌ Falha ao conectar no MySQL:", e.message);
  }
});
