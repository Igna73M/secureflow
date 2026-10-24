const crypto = require("node:crypto");
const argon2 = require("argon2");
const session = require("express-session");
const SqliteSessionStore = require("./sqlite-session-store");

const IDLE_TTL_MS = 30 * 60 * 1000;
const ABSOLUTE_TTL_MS = 12 * 60 * 60 * 1000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const REGISTER_WINDOW_MS = 60 * 60 * 1000;

function readConfig() {
    const secret = process.env.SECUREFLOW_SESSION_SECRET;
    const production = process.env.NODE_ENV === "production";
    const secureSetting = process.env.SECUREFLOW_COOKIE_SECURE;
    const publicOrigin = process.env.SECUREFLOW_PUBLIC_ORIGIN;
    const proxyHops = process.env.SECUREFLOW_TRUST_PROXY_HOPS || "0";

    if (typeof secret !== "string" || Buffer.byteLength(secret) < 32) {
        throw new Error("SECUREFLOW_SESSION_SECRET must contain at least 32 bytes.");
    }
    if (secureSetting !== "true" && secureSetting !== "false") {
        throw new Error("SECUREFLOW_COOKIE_SECURE must be explicitly set to true or false.");
    }
    if (production && secureSetting !== "true") {
        throw new Error("SECUREFLOW_COOKIE_SECURE must be true in production.");
    }
    if (production && !publicOrigin) {
        throw new Error("SECUREFLOW_PUBLIC_ORIGIN is required in production.");
    }
    if (!/^[0-5]$/.test(proxyHops)) {
        throw new Error("SECUREFLOW_TRUST_PROXY_HOPS must be an integer from 0 to 5.");
    }

    let origin = null;
    if (publicOrigin) {
        const parsed = new URL(publicOrigin);
        if (parsed.origin !== publicOrigin || (production && parsed.protocol !== "https:")) {
            throw new Error("SECUREFLOW_PUBLIC_ORIGIN must be an origin, and HTTPS in production.");
        }
        origin = parsed.origin;
    }

    return { secret, secure: secureSetting === "true", origin, proxyHops: Number(proxyHops) };
}

const config = readConfig();
const dummyHashPromise = argon2.hash("secureflow-invalid-account-password", {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1,
});

function normalizeEmail(value) {
    if (typeof value !== "string") return null;
    const email = value.trim().toLowerCase();
    if (
        email.length > 254 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        email.split("@")[0].length > 64
    ) return null;
    return email;
}

function validPassword(value) {
    return typeof value === "string" &&
        Buffer.byteLength(value, "utf8") >= 12 &&
        Buffer.byteLength(value, "utf8") <= 128;
}

function publicUser(user) {
    return { id: user.id, email: user.email_normalized };
}

function csrfToken(req) {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString("base64url");
    }
    return req.session.csrfToken;
}

function safeCompare(left, right) {
    if (typeof left !== "string" || typeof right !== "string") return false;
    const leftBuffer = Buffer.from(left);
    const rightBuffer = Buffer.from(right);
    return leftBuffer.length === rightBuffer.length &&
        crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function clearCookie(res) {
    res.clearCookie("secureflow.sid", {
        httpOnly: true,
        secure: config.secure,
        sameSite: "lax",
        path: "/",
    });
}

function originIsAllowed(req) {
    const origin = req.get("origin");
    if (!origin) return true;
    const expected = config.origin || `${req.protocol}://${req.get("host")}`;
    try {
        return new URL(origin).origin === expected;
    } catch {
        return false;
    }
}

function registerAuthRoutes(app, db) {
    app.set("trust proxy", config.proxyHops);
    app.use(session({
        name: "secureflow.sid",
        secret: config.secret,
        store: new SqliteSessionStore(db),
        resave: false,
        saveUninitialized: false,
        rolling: true,
        cookie: {
            httpOnly: true,
            secure: config.secure,
            sameSite: "lax",
            path: "/",
            maxAge: IDLE_TTL_MS,
        },
    }));

    const rateTransaction = db.transaction((key, now, windowMs, maximum) => {
        db.prepare("DELETE FROM auth_rate_limits WHERE window_started <= ?").run(now - 60 * 60 * 1000);
        const row = db.prepare(`
            SELECT window_started, attempts FROM auth_rate_limits WHERE bucket_key = ?
        `).get(key);
        if (!row || now - row.window_started >= windowMs) {
            db.prepare(`
                INSERT INTO auth_rate_limits (bucket_key, window_started, attempts)
                VALUES (?, ?, 1)
                ON CONFLICT(bucket_key) DO UPDATE SET window_started = excluded.window_started, attempts = 1
            `).run(key, now);
            return true;
        }
        if (row.attempts >= maximum) return false;
        db.prepare("UPDATE auth_rate_limits SET attempts = attempts + 1 WHERE bucket_key = ?").run(key);
        return true;
    });

    function allowAttempt(key, windowMs, maximum) {
        const digest = crypto.createHmac("sha256", config.secret).update(key).digest("hex");
        return rateTransaction(digest, Date.now(), windowMs, maximum);
    }

    function requireAuth(req, res, next) {
        const userId = req.session?.userId;
        const authenticatedAt = req.session?.authenticatedAt;
        if (!Number.isSafeInteger(userId) || !Number.isSafeInteger(authenticatedAt)) {
            if (req.path === "/console.html" && req.accepts("html")) {
                return res.redirect(302, "/login");
            }
            return res.status(401).json({ error: "Authentication required." });
        }
        if (Date.now() - authenticatedAt >= ABSOLUTE_TTL_MS) {
            return req.session.destroy(() => {
                clearCookie(res);
                res.status(401).json({ error: "Authentication required." });
            });
        }
        const user = db.prepare("SELECT id, email_normalized FROM users WHERE id = ?").get(userId);
        if (!user) return res.status(401).json({ error: "Authentication required." });
        req.authUser = user;
        return next();
    }

    function getSessionUserId(req) {
        const userId = req.session?.userId;
        const authenticatedAt = req.session?.authenticatedAt;
        if (!Number.isSafeInteger(userId) || !Number.isSafeInteger(authenticatedAt) ||
            Date.now() - authenticatedAt >= ABSOLUTE_TTL_MS) return null;
        return db.prepare("SELECT id FROM users WHERE id = ?").get(userId)?.id ?? null;
    }

    function csrfProtection(req, res, next) {
        if (!req.is("application/json")) {
            return res.status(415).json({ error: "Content-Type must be application/json." });
        }
        if (!originIsAllowed(req) || !safeCompare(req.get("x-csrf-token"), req.session?.csrfToken)) {
            return res.status(403).json({ error: "Request could not be verified." });
        }
        return next();
    }

    function saveSession(req, res, user, status) {
        req.session.regenerate((error) => {
            if (error) return res.status(500).json({ error: "Authentication could not be completed." });
            req.session.userId = user.id;
            req.session.authenticatedAt = Date.now();
            req.session.csrfToken = crypto.randomBytes(32).toString("base64url");
            req.session.save((saveError) => {
                if (saveError) return res.status(500).json({ error: "Authentication could not be completed." });
                return res.status(status).json({ user: publicUser(user), csrfToken: req.session.csrfToken });
            });
        });
    }

    app.get("/api/auth/me", (req, res) => {
        if (!Number.isSafeInteger(req.session?.userId)) {
            return res.json({ authenticated: false, user: null, csrfToken: csrfToken(req) });
        }
        const user = db.prepare("SELECT id, email_normalized FROM users WHERE id = ?").get(req.session.userId);
        if (!user || !Number.isSafeInteger(req.session.authenticatedAt) ||
            Date.now() - req.session.authenticatedAt >= ABSOLUTE_TTL_MS) {
            const regenerateSession = req.session.regenerate.bind(req.session);
            return req.session.destroy((destroyError) => {
                if (destroyError) return res.status(500).json({ error: "Session could not be refreshed." });
                clearCookie(res);
                regenerateSession((regenerateError) => {
                    if (regenerateError) return res.status(500).json({ error: "Session could not be refreshed." });
                    const token = csrfToken(req);
                    req.session.save((saveError) => {
                        if (saveError) return res.status(500).json({ error: "Session could not be refreshed." });
                        return res.json({ authenticated: false, user: null, csrfToken: token });
                    });
                });
            });
        }
        return res.json({ authenticated: true, user: publicUser(user), csrfToken: csrfToken(req) });
    });

    app.post("/api/auth/register", csrfProtection, async (req, res) => {
        if (!allowAttempt(`register:${req.ip}`, REGISTER_WINDOW_MS, 5)) {
            return res.status(429).json({ error: "Too many registration attempts. Try again later." });
        }
        const email = normalizeEmail(req.body?.email);
        const password = req.body?.password;
        if (!email) return res.status(400).json({ error: "Enter a valid email address." });
        if (!validPassword(password)) {
            return res.status(400).json({ error: "Password must be 12 to 128 UTF-8 bytes." });
        }

        try {
            const passwordHash = await argon2.hash(password, {
                type: argon2.argon2id,
                memoryCost: 19456,
                timeCost: 2,
                parallelism: 1,
            });
            const result = db.prepare("INSERT INTO users (email_normalized, password_hash) VALUES (?, ?)")
                .run(email, passwordHash);
            const user = { id: Number(result.lastInsertRowid), email_normalized: email };
            return saveSession(req, res, user, 201);
        } catch (error) {
            if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
                return res.status(409).json({ error: "An account with that email already exists." });
            }
            return res.status(500).json({ error: "Registration could not be completed." });
        }
    });

    app.post("/api/auth/login", csrfProtection, async (req, res) => {
        const email = normalizeEmail(req.body?.email);
        const rawEmail = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
        const accountKey = `login-account:${email || rawEmail.slice(0, 254)}`;
        if (!allowAttempt(`login-ip:${req.ip}`, LOGIN_WINDOW_MS, 50) ||
            !allowAttempt(accountKey, LOGIN_WINDOW_MS, 5)) {
            return res.status(429).json({ error: "Too many login attempts. Try again later." });
        }
        const password = req.body?.password;
        if (!email || typeof password !== "string" || Buffer.byteLength(password, "utf8") > 128) {
            return res.status(401).json({ error: "Email or password is incorrect." });
        }

        const user = db.prepare("SELECT id, email_normalized, password_hash FROM users WHERE email_normalized = ?")
            .get(email);
        const passwordHash = user?.password_hash || await dummyHashPromise;
        let valid = false;
        try {
            valid = await argon2.verify(passwordHash, password);
        } catch {
            valid = false;
        }
        if (!user || !valid) {
            return res.status(401).json({ error: "Email or password is incorrect." });
        }
        return saveSession(req, res, user, 200);
    });

    app.post("/api/auth/logout", requireAuth, csrfProtection, (req, res) => {
        req.session.destroy((error) => {
            if (error) return res.status(500).json({ error: "Logout could not be completed." });
            clearCookie(res);
            return res.status(204).end();
        });
    });

    return { requireAuth, csrfProtection, getSessionUserId };
}

module.exports = { registerAuthRoutes };
