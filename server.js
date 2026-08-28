const express = require("express");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "32kb" }));
app.use(express.urlencoded({ extended: false, limit: "32kb" }));

const PORT = process.env.PORT || 10000;
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "CHANGE_THIS_PASSWORD";
const LICENSE_SECRET = process.env.LICENSE_SECRET || "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET";
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("DATABASE_URL is required. Connect a Render Postgres database.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5
});

function sha256(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function hmac(value) {
  return crypto.createHmac("sha256", LICENSE_SECRET).update(String(value)).digest("hex");
}

function makeKey() {
  const bytes = crypto.randomBytes(12).toString("hex").toUpperCase();
  return `MPEB-${bytes.slice(0,4)}-${bytes.slice(4,8)}-${bytes.slice(8,12)}-${bytes.slice(12,16)}-${bytes.slice(16,20)}-${bytes.slice(20,24)}`;
}

function adminAuthorized(req) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Basic ")) return false;
  try {
    const decoded = Buffer.from(auth.slice(6), "base64").toString("utf8");
    const split = decoded.indexOf(":");
    if (split < 0) return false;
    const user = decoded.slice(0, split);
    const pass = decoded.slice(split + 1);
    return crypto.timingSafeEqual(Buffer.from(user), Buffer.from(ADMIN_USER)) &&
           crypto.timingSafeEqual(Buffer.from(pass), Buffer.from(ADMIN_PASSWORD));
  } catch {
    return false;
  }
}

function requireAdmin(req, res, next) {
  if (!adminAuthorized(req)) {
    res.set("WWW-Authenticate", 'Basic realm="MPEB License Admin"');
    return res.status(401).send("Admin authentication required");
  }
  next();
}

function normalizeKey(key) {
  return String(key || "").trim().toUpperCase();
}

function validDeviceId(deviceId) {
  return /^[A-Za-z0-9._:-]{16,200}$/.test(String(deviceId || ""));
}

function signLicense(licenseId, deviceId, keyHash) {
  return hmac(`${licenseId}:${deviceId}:${keyHash}`);
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS licenses (
      id BIGSERIAL PRIMARY KEY,
      key_hash TEXT UNIQUE NOT NULL,
      key_hint TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      expires_at TIMESTAMPTZ NULL,
      device_hash TEXT NULL,
      device_hint TEXT NULL,
      activated_at TIMESTAMPTZ NULL,
      last_seen_at TIMESTAMPTZ NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS licenses_status_idx ON licenses(status);
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS licenses_device_hash_idx ON licenses(device_hash);
  `);
}

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, service: "mpeb-license-api", time: new Date().toISOString() });
  } catch (e) {
    res.status(503).json({ ok: false, error: "database_unavailable" });
  }
});

app.post("/api/activate", async (req, res) => {
  const key = normalizeKey(req.body.key);
  const deviceId = String(req.body.device_id || "").trim();

  if (!/^MPEB-[A-Z0-9-]{20,80}$/.test(key)) {
    return res.status(400).json({ success: false, error: "Invalid license key format." });
  }
  if (!validDeviceId(deviceId)) {
    return res.status(400).json({ success: false, error: "Invalid device ID." });
  }

  const keyHash = sha256(key);
  const deviceHash = sha256(deviceId);

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const result = await client.query(
      "SELECT * FROM licenses WHERE key_hash=$1 FOR UPDATE",
      [keyHash]
    );

    if (!result.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ success: false, error: "Invalid license key." });
    }

    const lic = result.rows[0];

    if (lic.status !== "active") {
      await client.query("ROLLBACK");
      return res.status(403).json({ success: false, error: "This license is disabled." });
    }

    if (lic.expires_at && new Date(lic.expires_at) <= new Date()) {
      await client.query("ROLLBACK");
      return res.status(403).json({ success: false, error: "This license has expired." });
    }

    if (lic.device_hash && lic.device_hash !== deviceHash) {
      await client.query("ROLLBACK");
      return res.status(409).json({
        success: false,
        error: "This license is already activated on another system."
      });
    }

    if (!lic.device_hash) {
      await client.query(
        `UPDATE licenses
         SET device_hash=$1, device_hint=$2, activated_at=NOW(), last_seen_at=NOW()
         WHERE id=$3`,
        [deviceHash, deviceId.slice(0, 32), lic.id]
      );
    } else {
      await client.query(
        "UPDATE licenses SET last_seen_at=NOW() WHERE id=$1",
        [lic.id]
      );
    }

    await client.query("COMMIT");

    const token = signLicense(lic.id, deviceHash, keyHash);

    return res.json({
      success: true,
      token,
      license: {
        id: lic.id,
        expires_at: lic.expires_at,
        activated: true
      }
    });
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    console.error(e);
    return res.status(500).json({ success: false, error: "Activation failed." });
  } finally {
    client.release();
  }
});

app.post("/api/validate", async (req, res) => {
  const token = String(req.body.token || "");
  const deviceId = String(req.body.device_id || "").trim();

  if (!token || !validDeviceId(deviceId)) {
    return res.status(400).json({ success: false, error: "Missing license information." });
  }

  const deviceHash = sha256(deviceId);

  const result = await pool.query(
    "SELECT * FROM licenses WHERE device_hash=$1 LIMIT 1",
    [deviceHash]
  );

  if (!result.rows.length) {
    return res.status(401).json({ success: false, error: "License not activated." });
  }

  const lic = result.rows[0];

  if (lic.status !== "active") {
    return res.status(403).json({ success: false, error: "License disabled." });
  }

  if (lic.expires_at && new Date(lic.expires_at) <= new Date()) {
    return res.status(403).json({ success: false, error: "License expired." });
  }

  const expected = signLicense(lic.id, deviceHash, lic.key_hash);

  if (token.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))) {
    return res.status(401).json({ success: false, error: "Invalid license token." });
  }

  await pool.query(
    "UPDATE licenses SET last_seen_at=NOW() WHERE id=$1",
    [lic.id]
  );

  res.json({
    success: true,
    license: {
      id: lic.id,
      expires_at: lic.expires_at
    }
  });
});

app.get("/api/admin/licenses", requireAdmin, async (req, res) => {
  const result = await pool.query(`
    SELECT id, key_hint, status, expires_at, device_hint,
           activated_at, last_seen_at, created_at
    FROM licenses
    ORDER BY id DESC
    LIMIT 500
  `);
  res.json({ success: true, licenses: result.rows });
});

app.post("/api/admin/licenses", requireAdmin, async (req, res) => {
  const expiresAt = req.body.expires_at ? new Date(req.body.expires_at) : null;

  if (expiresAt && Number.isNaN(expiresAt.getTime())) {
    return res.status(400).json({ success: false, error: "Invalid expiry date." });
  }

  const key = makeKey();
  const keyHash = sha256(key);
  const keyHint = key.slice(-8);

  try {
    const result = await pool.query(
      `INSERT INTO licenses (key_hash, key_hint, expires_at)
       VALUES ($1,$2,$3)
       RETURNING id, expires_at, created_at`,
      [keyHash, keyHint, expiresAt]
    );

    res.json({
      success: true,
      key,
      license: result.rows[0]
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: "Could not create license." });
  }
});

app.post("/api/admin/licenses/:id/reset", requireAdmin, async (req, res) => {
  const result = await pool.query(
    `UPDATE licenses
     SET device_hash=NULL,
         device_hint=NULL,
         activated_at=NULL,
         last_seen_at=NULL
     WHERE id=$1
     RETURNING id`,
    [req.params.id]
  );

  if (!result.rows.length) {
    return res.status(404).json({ success: false, error: "License not found." });
  }

  res.json({ success: true });
});

app.post("/api/admin/licenses/:id/status", requireAdmin, async (req, res) => {
  const status = req.body.status === "disabled" ? "disabled" : "active";

  const result = await pool.query(
    `UPDATE licenses SET status=$1 WHERE id=$2 RETURNING id,status`,
    [status, req.params.id]
  );

  if (!result.rows.length) {
    return res.status(404).json({ success: false, error: "License not found." });
  }

  res.json({ success: true, license: result.rows[0] });
});

app.get("/api/admin/export", requireAdmin, async (req, res) => {
  const result = await pool.query(`
    SELECT id, key_hint, status, expires_at, device_hint,
           activated_at, last_seen_at, created_at
    FROM licenses
    ORDER BY id DESC
  `);
  res.json({ success: true, licenses: result.rows });
});

app.use(express.static(path.join(__dirname, "public"), {
  extensions: ["html"]
}));

app.get("/admin", requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("/api/config", (req, res) => {
  res.json({ api: "/api" });
});

initDb()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`MPEB License API listening on ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("Database initialization failed:", err);
    process.exit(1);
  });
