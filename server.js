const express = require("express");
const path = require("path");
const crypto = require("crypto");
const session = require("express-session");
const { Pool } = require("pg");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.ADMIN_SESSION_SECRET || "CHANGE_THIS_SECRET",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 1000 * 60 * 60 * 8
    }
}));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL
        ? { rejectUnauthorized: false }
        : false
});

const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

function adminAuth(req, res, next) {
    if (req.session && req.session.admin === true) {
        return next();
    }

    return res.status(401).json({
        success: false,
        error: "Admin login required."
    });
}

/* =========================
   ADMIN LOGIN
========================= */

app.post("/api/admin/login", (req, res) => {
    const { username, password } = req.body;

    if (
        username === ADMIN_USER &&
        password === ADMIN_PASSWORD
    ) {
        req.session.admin = true;
        req.session.adminUser = username;

        return res.json({
            success: true
        });
    }

    return res.status(401).json({
        success: false,
        error: "Invalid admin ID or password."
    });
});

app.post("/api/admin/logout", (req, res) => {
    req.session.destroy(() => {
        res.json({
            success: true
        });
    });
});

app.get("/api/admin/session", (req, res) => {
    res.json({
        loggedIn: req.session?.admin === true
    });
});

/* =========================
   GENERATE KEY
========================= */

function generateKey() {
    const r = crypto.randomBytes(12)
        .toString("hex")
        .toUpperCase();

    return `MPEB-${r.slice(0,4)}-${r.slice(4,8)}-${r.slice(8,12)}-${r.slice(12,16)}-${r.slice(16,20)}-${r.slice(20,24)}`;
}

app.post("/api/admin/licenses", adminAuth, async (req, res) => {
    try {
        const {
            type = "annual",
            payment_mode = "cash",
            expires_at
        } = req.body;

        if (!["annual", "lifetime", "trial"].includes(type)) {
            return res.status(400).json({
                success: false,
                error: "Invalid license type."
            });
        }

        if (!["cash", "online"].includes(payment_mode)) {
            return res.status(400).json({
                success: false,
                error: "Invalid payment mode."
            });
        }

        let expiry = null;

        if (type === "trial") {
            expiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
        }

        if (type === "annual") {
            expiry = expires_at
                ? new Date(expires_at)
                : new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
        }

        const key = generateKey();

        const result = await pool.query(
            `
            INSERT INTO licenses
            (
                key_hash,
                key_hint,
                type,
                status,
                expires_at,
                payment_mode,
                created_at
            )
            VALUES
            (
                encode(digest($1, 'sha256'), 'hex'),
                $2,
                $3,
                'active',
                $4,
                $5,
                NOW()
            )
            RETURNING
                id,
                key_hint,
                type,
                status,
                expires_at,
                payment_mode,
                created_at
            `,
            [
                key,
                key.slice(-8),
                type,
                expiry,
                payment_mode
            ]
        );

        return res.json({
            success: true,
            key,
            license: result.rows[0]
        });

    } catch (err) {
        console.error("GENERATE KEY ERROR:", err);

        return res.status(500).json({
            success: false,
            error: "Key generation failed.",
            detail: process.env.NODE_ENV === "production"
                ? undefined
                : err.message
        });
    }
});

/* =========================
   LICENSE LIST
========================= */

app.get("/api/admin/licenses", adminAuth, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                id,
                key_hint,
                type,
                status,
                expires_at,
                device_hint,
                payment_mode,
                razorpay_payment_id,
                customer_name,
                customer_phone,
                created_at
            FROM licenses
            ORDER BY id DESC
        `);

        res.json({
            success: true,
            licenses: result.rows
        });

    } catch (err) {
        console.error("LICENSE LIST ERROR:", err);

        res.status(500).json({
            success: false,
            error: "Could not load licenses."
        });
    }
});

/* =========================
   PAYMENT HISTORY
========================= */

app.get("/api/admin/payments", adminAuth, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                id,
                razorpay_payment_id,
                razorpay_order_id,
                amount,
                currency,
                status,
                license_id,
                created_at
            FROM payments
            ORDER BY id DESC
        `);

        res.json({
            success: true,
            payments: result.rows
        });

    } catch (err) {
        console.error("PAYMENT LIST ERROR:", err);

        res.status(500).json({
            success: false,
            error: "Could not load payment history."
        });
    }
});

/* =========================
   RESET DEVICE
========================= */

app.post(
    "/api/admin/licenses/:id/reset",
    adminAuth,
    async (req, res) => {
        try {
            const result = await pool.query(
                `
                UPDATE licenses
                SET
                    device_hash = NULL,
                    device_hint = NULL,
                    activated_at = NULL,
                    last_seen_at = NULL
                WHERE id = $1
                RETURNING id
                `,
                [req.params.id]
            );

            if (!result.rows.length) {
                return res.status(404).json({
                    success: false,
                    error: "License not found."
                });
            }

            res.json({
                success: true
            });

        } catch (err) {
            console.error(err);

            res.status(500).json({
                success: false,
                error: "Device reset failed."
            });
        }
    }
);

/* =========================
   ENABLE / DISABLE
========================= */

app.post(
    "/api/admin/licenses/:id/status",
    adminAuth,
    async (req, res) => {
        try {
            const status =
                req.body.status === "disabled"
                    ? "disabled"
                    : "active";

            const result = await pool.query(
                `
                UPDATE licenses
                SET status = $1
                WHERE id = $2
                RETURNING id, status
                `,
                [status, req.params.id]
            );

            if (!result.rows.length) {
                return res.status(404).json({
                    success: false,
                    error: "License not found."
                });
            }

            res.json({
                success: true,
                license: result.rows[0]
            });

        } catch (err) {
            res.status(500).json({
                success: false,
                error: "Status update failed."
            });
        }
    }
);

/* =========================
   DELETE
========================= */

app.delete(
    "/api/admin/licenses/:id",
    adminAuth,
    async (req, res) => {
        try {
            const result = await pool.query(
                "DELETE FROM licenses WHERE id=$1 RETURNING id",
                [req.params.id]
            );

            if (!result.rows.length) {
                return res.status(404).json({
                    success: false,
                    error: "License not found."
                });
            }

            res.json({
                success: true
            });

        } catch (err) {
            res.status(500).json({
                success: false,
                error: "Delete failed."
            });
        }
    }
);

/* =========================
   STATIC FILES
   MUST COME AFTER API
========================= */

app.use(express.static(
    path.join(__dirname, "public")
));

/* =========================
   ADMIN PAGE
========================= */

app.get("/admin", (req, res) => {
    res.sendFile(
        path.join(__dirname, "public", "admin.html")
    );
});

app.get("/admin.html", (req, res) => {
    res.sendFile(
        path.join(__dirname, "public", "admin.html")
    );
});

/* =========================
   HEALTH
========================= */

app.get("/health", async (req, res) => {
    try {
        await pool.query("SELECT 1");

        res.json({
            ok: true,
            service: "mpeb-license-api",
            time: new Date().toISOString()
        });

    } catch (err) {
        res.status(503).json({
            ok: false,
            error: "database_unavailable"
        });
    }
});

const PORT = process.env.PORT || 10000;

app.listen(PORT, "0.0.0.0", () => {
    console.log(`MPEB License API running on ${PORT}`);
});
