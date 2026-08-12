/**
 * sso_router.js  —  Levyni SSO + OAuth2 Provider
 *
 * Supports:
 *   - Internal unified login  (your own apps/sites)
 *   - Authorization Code + PKCE  (external apps, user-facing)
 *   - Client Credentials  (server-to-server, no user)
 *   - Token Introspection  (RFC 7662)
 *
 * Mount in server.js:
 *   const { createSSORouter, makeAuthMiddleware } = require('./sso_router');
 *   const sso = createSSORouter(pool, transporter);
 *   app.use('/auth',  sso.auth);
 *   app.use('/oauth', sso.oauth);
 *   const authenticateToken = makeAuthMiddleware(pool);  // replaces old one
 *
 * ─── Route map ────────────────────────────────────────────────
 *  Internal (your apps):
 *    POST  /auth/unified          login → JWT + refresh token
 *                                 sets HttpOnly lv_device cookie on first login
 *                                 reads lv_device cookie → one-click login (no body needed)
 *    POST  /auth/refresh          rotate tokens
 *    POST  /auth/logout           revoke session/token; clears device cookie optionally
 *    GET   /auth/me               profile from any valid token
 *
 *  Device management (trusted-device / one-click login):
 *    GET   /auth/devices          list all registered devices (auth required)
 *    DELETE /auth/devices/:id     revoke a device (auth required)
 *    POST  /auth/devices/forget   revoke THIS device cookie + DB row
 *
 *  OAuth2 provider (external devs):
 *    GET   /oauth/authorize       consent page
 *    POST  /oauth/authorize/approve  form submission from consent page
 *    POST  /oauth/token           code→tokens, refresh, client_credentials
 *    POST  /oauth/introspect      validate any token (RFC 7662)
 *    GET   /oauth/userinfo        OIDC profile endpoint
 *    POST  /oauth/revoke          revoke token (RFC 7009)
 *
 *  Client management:
 *    POST   /oauth/clients        register app
 *    GET    /oauth/clients        list my apps
 *    PATCH  /oauth/clients/:id    update (name, redirect_uris, logo)
 *    DELETE /oauth/clients/:id    deactivate
 * ────────────────────────────────────────────────────────────
 */

'use strict';

const express = require('express');
const crypto  = require('node:crypto');
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');

// ── Constants ─────────────────────────────────────────────────
const SALT_ROUNDS       = 10;
const ACCESS_TTL        = 3_600;              // 1 h
const REFRESH_TTL       = 60 * 60 * 24 * 30; // 30 d
const CC_ACCESS_TTL     = 3_600;              // client_credentials token lifetime
const CODE_TTL          = 600;                // 10 min
const SESSION_TTL       = 60 * 60 * 24 * 14; // 14 d

const ALLOWED_GRANTS  = ['authorization_code', 'refresh_token', 'client_credentials'];
const DEVICE_TTL      = 60 * 60 * 24 * 365; // 1 year — device token lifetime

const SCOPE_LABELS = {
    openid:  'Confirm your identity',
    profile: 'Read your username and avatar',
    email:   'Read your email address',
};

// ── Helpers ───────────────────────────────────────────────────
const rand   = (bytes = 32)  => crypto.randomBytes(bytes).toString('hex');
const nowSec = ()             => Math.floor(Date.now() / 1000);
const sha256b64url = (str)   =>
    crypto.createHash('sha256').update(str).digest('base64url');

function sanitizeEmail(email) {
    if (!email || typeof email !== 'string') throw new Error('Invalid email');
    return email.trim().toLowerCase();
}

// ── JWT ───────────────────────────────────────────────────────
function signJWT(payload, ttl = ACCESS_TTL) {
    return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: ttl });
}
function verifyJWT(token) {
    return jwt.verify(token, process.env.JWT_SECRET);
}

// ── DB helpers ────────────────────────────────────────────────
async function dbUser(pool, email) {
    const [r] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    return r[0] ?? null;
}

async function dbClient(pool, id) {
    const [r] = await pool.query(
        'SELECT * FROM oauth_clients WHERE id = ? AND is_active = 1', [id]
    );
    return r[0] ?? null;
}

async function dbSaveToken(pool, { accessToken, refreshToken = null, clientId,
    userEmail = null, grantType, scopes }) {
    await pool.query(
        `INSERT INTO oauth_tokens
         (access_token, refresh_token, client_id, user_email, grant_type, scopes,
          access_expires, refresh_expires)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [
            accessToken, refreshToken, clientId, userEmail, grantType, scopes,
            nowSec() + ACCESS_TTL,
            refreshToken ? nowSec() + REFRESH_TTL : null,
        ]
    );
}

async function dbFindToken(pool, accessToken) {
    const [r] = await pool.query(
        'SELECT * FROM oauth_tokens WHERE access_token = ? AND revoked = 0', [accessToken]
    );
    return r[0] ?? null;
}

async function dbRevokeToken(pool, token) {
    await pool.query(
        'UPDATE oauth_tokens SET revoked = 1 WHERE access_token = ? OR refresh_token = ?',
        [token, token]
    );
}

// ── Device helpers ────────────────────────────────────────────
async function dbFindDevice(pool, deviceToken) {
    const [r] = await pool.query(
        `SELECT * FROM sso_devices
         WHERE device_token = ? AND revoked = 0 AND expires_at > ?`,
        [deviceToken, nowSec()]
    );
    return r[0] ?? null;
}

async function dbRegisterDevice(pool, { userEmail, deviceToken, label, userAgent, ip }) {
    // Upsert on (user_email, user_agent prefix) so same browser reuses its row.
    // fingerprint column stores a hash of user_agent for quick lookup.
    const fingerprint = crypto.createHash('sha256').update(userAgent).digest('hex').slice(0, 16);
    await pool.query(
        `INSERT INTO sso_devices
         (device_token, user_email, fingerprint, label, user_agent, ip, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
           device_token = VALUES(device_token),
           label        = VALUES(label),
           ip           = VALUES(ip),
           expires_at   = VALUES(expires_at),
           revoked      = 0`,
        [deviceToken, userEmail, fingerprint, label, userAgent, ip, nowSec() + DEVICE_TTL]
    );
    return { deviceToken, fingerprint };
}

// ── Auth middleware (accepts JWT or opaque token) ─────────────
function makeAuthMiddleware(pool) {
    return async (req, res, next) => {
        const header = req.headers['authorization'] ?? '';
        const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
        if (!token) return res.status(401).json({ error: 'Bearer token required' });

        // JWT first (internal tokens are JWTs)
        try {
            req.user = verifyJWT(token);
            return next();
        } catch (_) { /* not a JWT — try opaque */ }

        // Opaque OAuth2 token
        const row = await dbFindToken(pool, token);
        if (!row || row.access_expires < nowSec()) {
            return res.status(401).json({ error: 'Invalid or expired token' });
        }
        req.user = {
            email:    row.user_email,
            clientId: row.client_id,
            scopes:   row.scopes,
            grantType: row.grant_type,
        };
        next();
    };
}

// ── Verify client credentials (Basic auth or body params) ─────
async function authenticateClient(pool, req) {
    let clientId, clientSecret;

    const basic = req.headers['authorization'] ?? '';
    if (basic.startsWith('Basic ')) {
        const decoded = Buffer.from(basic.slice(6), 'base64').toString();
        [clientId, clientSecret] = decoded.split(':');
    } else {
        clientId     = req.body.client_id;
        clientSecret = req.body.client_secret;
    }

    if (!clientId || !clientSecret) return null;

    const client = await dbClient(pool, clientId);
    if (!client) return null;

    const ok = await bcrypt.compare(clientSecret, client.secret_hash);
    return ok ? client : null;
}

// ── Cookie helpers ────────────────────────────────────────────
const DEVICE_COOKIE     = 'lv_device';
const COOKIE_MAX_AGE    = DEVICE_TTL; // seconds

function setDeviceCookie(res, token) {
    res.cookie(DEVICE_COOKIE, token, {
        httpOnly:  true,
        sameSite:  'Lax',
        secure:    process.env.NODE_ENV === 'production',
        maxAge:    COOKIE_MAX_AGE * 1000, // ms
        path:      '/',
    });
}

function clearDeviceCookie(res) {
    res.clearCookie(DEVICE_COOKIE, { httpOnly: true, sameSite: 'Lax', path: '/' });
}

function deviceCookieToken(req) {
    // Works with cookie-parser OR manual header parse
    if (req.cookies?.[DEVICE_COOKIE]) return req.cookies[DEVICE_COOKIE];
    const raw = req.headers.cookie || '';
    const m   = raw.match(/(?:^|;\s*)lv_device=([^;]+)/);
    return m ? decodeURIComponent(m[1]) : null;
}

function makeDeviceLabel(req) {
    const ua  = req.headers['user-agent'] || '';
    const day = new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
    // Extract rough browser/OS hint
    let hint = 'Browser';
    if (/iPhone|iPad/i.test(ua))        hint = 'iPhone/iPad';
    else if (/Android/i.test(ua))       hint = 'Android';
    else if (/Chrome/i.test(ua))        hint = 'Chrome';
    else if (/Firefox/i.test(ua))       hint = 'Firefox';
    else if (/Safari/i.test(ua))        hint = 'Safari';
    return `${hint} — ${day}`;
}

// ── Router factory ────────────────────────────────────────────
function createSSORouter(pool, transporter) {
    const auth  = express.Router();
    const oauth = express.Router();
    const requireAuth = makeAuthMiddleware(pool);

    // Accept both JSON bodies (API calls) and URL-encoded bodies (HTML form submissions)
    auth.use(express.json());
    auth.use(express.urlencoded({ extended: false }));
    oauth.use(express.json());
    oauth.use(express.urlencoded({ extended: false }));

    // ══════════════════════════════════════════════════════════
    //  INTERNAL AUTH  (/auth/*)
    // ══════════════════════════════════════════════════════════

    /**
     * POST /auth/unified
     * Your own apps call this instead of the old /api/auth/login.
     * Body: { email, password, client_id? }
     * Returns: { token, refresh_token, expires_in, session_id, user }
     */
    auth.post('/unified', async (req, res) => {
        try {
            const { email, password, client_id } = req.body;
            const cookieToken = deviceCookieToken(req);

            // ── Path A: device cookie present, no password → one-click ─
            if (cookieToken && !password && !email) {
                const device = await dbFindDevice(pool, cookieToken);
                if (!device) {
                    clearDeviceCookie(res);
                    return res.status(401).json({ error: 'Device not recognized. Please log in with your password.' });
                }

                const user = await dbUser(pool, device.user_email);
                if (!user) {
                    clearDeviceCookie(res);
                    return res.status(401).json({ error: 'Account not found' });
                }

                await pool.query(
                    'UPDATE sso_devices SET last_used_at = NOW() WHERE device_token = ?',
                    [cookieToken]
                );

                const token        = signJWT({ email: device.user_email, userId: user.userId, type: 'access' });
                const refreshToken = rand(40);
                await dbSaveToken(pool, {
                    accessToken: token, refreshToken,
                    clientId:    client_id ?? 'levyni-internal',
                    userEmail:   device.user_email,
                    grantType:   'authorization_code',
                    scopes:      'openid profile email',
                });

                const sessionId = rand(32);
                await pool.query(
                    `INSERT INTO sso_sessions (session_id, user_email, user_agent, ip, expires_at)
                     VALUES (?, ?, ?, ?, ?)`,
                    [sessionId, device.user_email, req.headers['user-agent'] ?? '', req.ip, nowSec() + SESSION_TTL]
                );

                // Refresh cookie TTL
                setDeviceCookie(res, cookieToken);

                const { hashedPassword, ...safeUser } = user;
                return res.json({
                    success: true, token, refresh_token: refreshToken,
                    expires_in: ACCESS_TTL, session_id: sessionId,
                    trusted_device: true, user: safeUser,
                });
            }

            // ── Path B: email + password ──────────────────────────────
            if (!email || !password)
                return res.status(400).json({ error: 'email and password required' });

            const sanitized = sanitizeEmail(email);
            const user = await dbUser(pool, sanitized);
            if (!user?.hashedPassword)
                return res.status(401).json({ error: 'Invalid credentials' });

            const match = await bcrypt.compare(password, user.hashedPassword);
            if (!match) return res.status(401).json({ error: 'Invalid credentials' });

            if (client_id) {
                const c = await dbClient(pool, client_id);
                if (!c) return res.status(403).json({ error: 'Unknown client_id' });
            }

            const token        = signJWT({ email: sanitized, userId: user.userId, type: 'access' });
            const refreshToken = rand(40);
            await dbSaveToken(pool, {
                accessToken: token, refreshToken,
                clientId:    client_id ?? 'levyni-internal',
                userEmail:   sanitized,
                grantType:   'authorization_code',
                scopes:      'openid profile email',
            });

            const sessionId = rand(32);
            await pool.query(
                `INSERT INTO sso_sessions (session_id, user_email, user_agent, ip, expires_at)
                 VALUES (?, ?, ?, ?, ?)`,
                [sessionId, sanitized, req.headers['user-agent'] ?? '', req.ip, nowSec() + SESSION_TTL]
            );

            // ── Register / refresh device cookie ──────────────────────
            // Reuse existing cookie token if still valid, otherwise mint new one
            let newDeviceToken = cookieToken;
            const existingDevice = cookieToken ? await dbFindDevice(pool, cookieToken) : null;
            if (!existingDevice || existingDevice.user_email !== sanitized) {
                newDeviceToken = rand(40);
            }
            await dbRegisterDevice(pool, {
                userEmail:   sanitized,
                deviceToken: newDeviceToken,
                label:       makeDeviceLabel(req),
                userAgent:   req.headers['user-agent'] ?? '',
                ip:          req.ip,
            });
            setDeviceCookie(res, newDeviceToken);

            const { hashedPassword, ...safeUser } = user;
            res.json({
                success: true, token, refresh_token: refreshToken,
                expires_in: ACCESS_TTL, session_id: sessionId,
                trusted_device: false, user: safeUser,
            });
        } catch (err) {
            console.error('[SSO] unified:', err.message);
            res.status(500).json({ error: 'Login failed' });
        }
    });

    /**
     * POST /auth/refresh
     * Body: { refresh_token }
     */
    auth.post('/refresh', async (req, res) => {
        try {
            const { refresh_token } = req.body;
            if (!refresh_token)
                return res.status(400).json({ error: 'refresh_token required' });

            const [rows] = await pool.query(
                `SELECT * FROM oauth_tokens
                 WHERE refresh_token = ? AND revoked = 0 AND refresh_expires > ?`,
                [refresh_token, nowSec()]
            );
            const row = rows[0];
            if (!row) return res.status(401).json({ error: 'Invalid or expired refresh token' });

            const user = await dbUser(pool, row.user_email);
            if (!user) return res.status(401).json({ error: 'User no longer exists' });

            await dbRevokeToken(pool, row.access_token);

            const newToken   = signJWT({ email: row.user_email, userId: user.userId, type: 'access' });
            const newRefresh = rand(40);

            await dbSaveToken(pool, {
                accessToken:  newToken,
                refreshToken: newRefresh,
                clientId:     row.client_id,
                userEmail:    row.user_email,
                grantType:    row.grant_type,
                scopes:       row.scopes,
            });

            const { hashedPassword, ...safeUser } = user;
            res.json({ token: newToken, refresh_token: newRefresh, expires_in: ACCESS_TTL, user: safeUser });
        } catch (err) {
            console.error('[SSO] refresh:', err.message);
            res.status(500).json({ error: 'Token refresh failed' });
        }
    });

    /**
     * POST /auth/logout
     * Body: { token?, session_id? }
     */
    auth.post('/logout', async (req, res) => {
        try {
            const { token, session_id } = req.body;
            if (token)      await dbRevokeToken(pool, token);
            if (session_id) await pool.query(
                'UPDATE sso_sessions SET revoked = 1 WHERE session_id = ?', [session_id]
            );
            // Intentionally keep lv_device cookie so next visit is one-click
            res.json({ success: true });
        } catch (err) {
            console.error('[SSO] logout:', err.message);
            res.status(500).json({ error: 'Logout failed' });
        }
    });

    /**
     * POST /auth/devices/forget
     * Revokes the device cookie AND the DB row for this browser.
     * Called when user explicitly clicks "Remove this device".
     */
    auth.post('/devices/forget', async (req, res) => {
        try {
            const cookieToken = deviceCookieToken(req);
            if (cookieToken) {
                await pool.query(
                    'UPDATE sso_devices SET revoked = 1 WHERE device_token = ?',
                    [cookieToken]
                );
                clearDeviceCookie(res);
            }
            res.json({ success: true });
        } catch (err) {
            console.error('[SSO] devices/forget:', err.message);
            res.status(500).json({ error: 'Failed to forget device' });
        }
    });

    /**
     * GET /auth/me
     * Returns profile from any valid token (JWT or opaque).
     */
    auth.get('/me', requireAuth, async (req, res) => {
        try {
            // client_credentials tokens have no user
            if (!req.user.email)
                return res.status(403).json({ error: 'No user associated with this token' });

            const user = await dbUser(pool, req.user.email);
            if (!user) return res.status(404).json({ error: 'User not found' });

            const { hashedPassword, ...safeUser } = user;
            res.json({ success: true, user: safeUser });
        } catch (err) {
            res.status(500).json({ error: 'Failed to fetch profile' });
        }
    });

    /**
     * GET /auth/devices
     * List all registered devices for the current user.
     */
    auth.get('/devices', requireAuth, async (req, res) => {
        try {
            if (!req.user.email) return res.status(403).json({ error: 'No user' });
            const [rows] = await pool.query(
                `SELECT id, label, fingerprint, user_agent, ip,
                        created_at, expires_at, last_used_at
                 FROM sso_devices
                 WHERE user_email = ? AND revoked = 0 AND expires_at > ?
                 ORDER BY created_at DESC`,
                [req.user.email, nowSec()]
            );
            res.json({ success: true, devices: rows });
        } catch (err) {
            console.error('[SSO] devices list:', err.message);
            res.status(500).json({ error: 'Failed to list devices' });
        }
    });

    /**
     * DELETE /auth/devices/:id
     * Revoke a specific registered device.
     */
    auth.delete('/devices/:id', requireAuth, async (req, res) => {
        try {
            if (!req.user.email) return res.status(403).json({ error: 'No user' });
            await pool.query(
                'UPDATE sso_devices SET revoked = 1 WHERE id = ? AND user_email = ?',
                [req.params.id, req.user.email]
            );
            res.json({ success: true });
        } catch (err) {
            console.error('[SSO] device revoke:', err.message);
            res.status(500).json({ error: 'Failed to revoke device' });
        }
    });

    // ══════════════════════════════════════════════════════════
    //  OAUTH2 PROVIDER  (/oauth/*)
    // ══════════════════════════════════════════════════════════

    /**
     * GET /oauth/authorize
     * External app redirects user here to start auth code flow.
     * Query params: client_id, redirect_uri, response_type=code,
     *               scope, state, code_challenge, code_challenge_method=S256
     */
    oauth.get('/authorize', async (req, res) => {
        try {
            const {
                client_id,
                redirect_uri,
                response_type,
                scope = 'openid profile email',
                state = '',
                code_challenge = '',
                code_challenge_method = 'S256',
            } = req.query;

            if (response_type !== 'code')
                return res.status(400).json({ error: 'Only response_type=code supported' });
            if (!client_id || !redirect_uri)
                return res.status(400).json({ error: 'client_id and redirect_uri required' });

            const client = await dbClient(pool, client_id);
            if (!client) return res.status(400).json({ error: 'Unknown client_id' });

            const allowedUris = JSON.parse(client.redirect_uris);
            if (!allowedUris.includes(redirect_uri))
                return res.status(400).json({ error: 'redirect_uri not registered for this client' });

            // ── Check device cookie server-side ───────────────────────
            let trustedUser = null;
            const cookieToken = deviceCookieToken(req);
            if (cookieToken) {
                const device = await dbFindDevice(pool, cookieToken);
                if (device) {
                    const u = await dbUser(pool, device.user_email);
                    if (u) {
                        const { hashedPassword, ...safe } = u;
                        trustedUser = safe;
                    }
                }
            }

            res.send(buildConsentPage({
                clientName:    client.name,
                clientLogo:    client.logo_url,
                scopes:        scope.split(' ').filter(Boolean),
                clientId:      client_id,
                redirectUri:   redirect_uri,
                state,
                codeChallenge: code_challenge,
                trustedUser,   // null = show password form; object = show one-click panel
            }));
        } catch (err) {
            console.error('[SSO] authorize:', err.message);
            res.status(500).json({ error: 'Authorization failed' });
        }
    });

    /**
     * POST /oauth/authorize/approve
     * Consent form submits here. Verifies credentials, issues code, redirects.
     * Path A: cookie device token → one-click, no password.
     * Path B: email+password → verify, register device cookie, issue code.
     */
    oauth.post('/authorize/approve', async (req, res) => {
        try {
            const { email, password, client_id, redirect_uri, state, scopes, code_challenge } = req.body;

            if (!client_id || !redirect_uri) {
                console.error('[SSO] approve: missing client_id/redirect_uri');
                return res.status(400).send(errorPage('Missing required fields. Please try again.'));
            }

            const client = await dbClient(pool, client_id);
            if (!client) return res.status(400).send(errorPage('Unknown application.'));

            const allowedUris = JSON.parse(client.redirect_uris);
            if (!allowedUris.includes(redirect_uri))
                return res.status(400).send(errorPage('Redirect URI mismatch.'));

            const cookieToken = deviceCookieToken(req);
            let sanitized;

            // ── Path A: trusted device cookie, no password needed ─────
            if (cookieToken && !email && !password) {
                const device = await dbFindDevice(pool, cookieToken);
                if (!device) {
                    clearDeviceCookie(res);
                    return res.status(401).send(errorPage('Device no longer recognized. Please log in with your password.'));
                }
                sanitized = device.user_email;
                await pool.query('UPDATE sso_devices SET last_used_at = NOW() WHERE device_token = ?', [cookieToken]);
                setDeviceCookie(res, cookieToken); // refresh TTL
            }
            // ── Path B: email + password (first login / switch account) ─
            else {
                if (!email || !password) {
                    console.error('[SSO] approve: missing email/password');
                    return res.status(400).send(errorPage('Missing required fields. Please try again.'));
                }
                try { sanitized = sanitizeEmail(email); }
                catch { return res.status(400).send(errorPage('Invalid email address.')); }

                const user = await dbUser(pool, sanitized);
                if (!user?.hashedPassword) return res.status(401).send(errorPage('Invalid email or password.'));

                const match = await bcrypt.compare(password, user.hashedPassword);
                if (!match) return res.status(401).send(errorPage('Invalid email or password.'));

                // Register / refresh device cookie for this browser
                let newToken = cookieToken;
                const existingDevice = cookieToken ? await dbFindDevice(pool, cookieToken) : null;
                if (!existingDevice || existingDevice.user_email !== sanitized) newToken = rand(40);
                await dbRegisterDevice(pool, {
                    userEmail: sanitized, deviceToken: newToken,
                    label: makeDeviceLabel(req), userAgent: req.headers['user-agent'] ?? '', ip: req.ip,
                });
                setDeviceCookie(res, newToken);
            }

            // Issue authorization code
            const code = rand(32);
            await pool.query(
                `INSERT INTO oauth_codes (code, client_id, user_email, redirect_uri, scopes, code_challenge, expires_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [code, client_id, sanitized, redirect_uri, scopes ?? 'openid profile email', code_challenge || null, nowSec() + CODE_TTL]
            );

            const url = new URL(redirect_uri);
            url.searchParams.set('code', code);
            if (state) url.searchParams.set('state', state);

            const isXHR = req.headers['x-requested-with'] === 'XMLHttpRequest' ||
                          (req.headers['accept'] || '').includes('application/json');
            if (isXHR) return res.json({ redirect_to: url.toString() });
            res.redirect(url.toString());
        } catch (err) {
            console.error('[SSO] approve:', err.message);
            res.status(500).send(errorPage('An error occurred. Please try again.'));
        }
    });

    /**
     * POST /oauth/token
     * Handles three grant types:
     *   - authorization_code  (+ PKCE)
     *   - refresh_token
     *   - client_credentials
     */
    oauth.post('/token', async (req, res) => {
        // Force JSON response regardless of Accept header
        res.set('Content-Type', 'application/json');

        try {
            const { grant_type } = req.body;
            if (!ALLOWED_GRANTS.includes(grant_type))
                return res.status(400).json({ error: 'unsupported_grant_type' });

            // ── client_credentials ────────────────────────────
            if (grant_type === 'client_credentials') {
                const client = await authenticateClient(pool, req);
                if (!client)
                    return res.status(401).json({ error: 'invalid_client' });

                const allowed = client.allowed_grants.split(',').map(g => g.trim());
                if (!allowed.includes('client_credentials'))
                    return res.status(403).json({ error: 'Grant type not permitted for this client' });

                const requestedScope = (req.body.scope ?? client.scopes)
                    .split(' ')
                    .filter(s => client.scopes.includes(s))
                    .join(' ');

                const accessToken = rand(40);
                await pool.query(
                    `INSERT INTO oauth_tokens
                     (access_token, client_id, user_email, grant_type, scopes, access_expires)
                     VALUES (?, ?, NULL, 'client_credentials', ?, ?)`,
                    [accessToken, client.id, requestedScope, nowSec() + CC_ACCESS_TTL]
                );

                return res.json({
                    access_token: accessToken,
                    token_type:   'Bearer',
                    expires_in:   CC_ACCESS_TTL,
                    scope:        requestedScope,
                });
            }

            // ── authorization_code ────────────────────────────
            if (grant_type === 'authorization_code') {
                const { code, redirect_uri, code_verifier } = req.body;
                if (!code || !redirect_uri)
                    return res.status(400).json({ error: 'code and redirect_uri required' });

                // Client auth (confidential clients supply a secret; public clients use PKCE only)
                let clientId = req.body.client_id;
                const basic  = req.headers['authorization'] ?? '';
                if (basic.startsWith('Basic ')) {
                    const decoded = Buffer.from(basic.slice(6), 'base64').toString();
                    clientId = decoded.split(':')[0];
                }
                if (!clientId) return res.status(400).json({ error: 'client_id required' });

                const client = await dbClient(pool, clientId);
                if (!client) return res.status(401).json({ error: 'invalid_client' });

                const [codeRows] = await pool.query(
                    `SELECT * FROM oauth_codes WHERE code = ? AND used = 0 AND expires_at > ?`,
                    [code, nowSec()]
                );
                const cr = codeRows[0];
                if (!cr)                         return res.status(400).json({ error: 'invalid_grant' });
                if (cr.client_id !== clientId)   return res.status(400).json({ error: 'invalid_grant' });
                if (cr.redirect_uri !== redirect_uri) return res.status(400).json({ error: 'redirect_uri_mismatch' });

                // PKCE
                if (cr.code_challenge) {
                    if (!code_verifier)
                        return res.status(400).json({ error: 'code_verifier required' });
                    if (sha256b64url(code_verifier) !== cr.code_challenge)
                        return res.status(400).json({ error: 'invalid_grant: PKCE failed' });
                }

                await pool.query('UPDATE oauth_codes SET used = 1 WHERE code = ?', [code]);

                const accessToken  = rand(40);
                const refreshToken = rand(40);
                await dbSaveToken(pool, {
                    accessToken, refreshToken,
                    clientId, userEmail: cr.user_email,
                    grantType: 'authorization_code',
                    scopes: cr.scopes,
                });

                return res.json({
                    access_token:  accessToken,
                    refresh_token: refreshToken,
                    token_type:    'Bearer',
                    expires_in:    ACCESS_TTL,
                    scope:         cr.scopes,
                });
            }

            // ── refresh_token ─────────────────────────────────
            if (grant_type === 'refresh_token') {
                const { refresh_token } = req.body;
                if (!refresh_token)
                    return res.status(400).json({ error: 'refresh_token required' });

                const client = await authenticateClient(pool, req);
                // confidential clients must authenticate; public clients just provide client_id
                const clientId = client?.id ?? req.body.client_id;
                if (!clientId) return res.status(400).json({ error: 'client_id required' });

                const [rows] = await pool.query(
                    `SELECT * FROM oauth_tokens
                     WHERE refresh_token = ? AND client_id = ? AND revoked = 0 AND refresh_expires > ?`,
                    [refresh_token, clientId, nowSec()]
                );
                const row = rows[0];
                if (!row) return res.status(401).json({ error: 'invalid_grant' });

                await dbRevokeToken(pool, row.access_token);

                const newAccess  = rand(40);
                const newRefresh = rand(40);
                await dbSaveToken(pool, {
                    accessToken:  newAccess,
                    refreshToken: newRefresh,
                    clientId, userEmail: row.user_email,
                    grantType:    'authorization_code',
                    scopes:       row.scopes,
                });

                return res.json({
                    access_token:  newAccess,
                    refresh_token: newRefresh,
                    token_type:    'Bearer',
                    expires_in:    ACCESS_TTL,
                    scope:         row.scopes,
                });
            }
        } catch (err) {
            console.error('[SSO] token:', err.message);
            res.status(500).json({ error: 'server_error' });
        }
    });

    /**
     * POST /oauth/introspect  (RFC 7662)
     * Validate any token — JWT, opaque access, or opaque refresh.
     * Body: { token, client_id?, client_secret? }
     * Used for server-to-server validation without calling /userinfo.
     */
    oauth.post('/introspect', async (req, res) => {
        try {
            const { token } = req.body;
            if (!token) return res.json({ active: false });

            // Requesting client may optionally authenticate (log who introspects)
            const requestingClient = await authenticateClient(pool, req);
            // No hard requirement — some setups allow bearer-authenticated introspection

            // Try JWT (internal tokens)
            try {
                const decoded = verifyJWT(token);
                const user    = decoded.email ? await dbUser(pool, decoded.email) : null;
                return res.json({
                    active:      true,
                    token_type:  'Bearer',
                    sub:         decoded.email ?? null,
                    email:       decoded.email ?? null,
                    username:    user?.username ?? null,
                    userId:      decoded.userId ?? null,
                    exp:         decoded.exp,
                    iat:         decoded.iat,
                    scope:       'openid profile email',
                    client_id:   'levyni-internal',
                });
            } catch (_) { /* not a JWT */ }

            // Try opaque token
            const row = await dbFindToken(pool, token);
            if (!row || row.access_expires < nowSec())
                return res.json({ active: false });

            const user = row.user_email ? await dbUser(pool, row.user_email) : null;
            return res.json({
                active:      true,
                token_type:  'Bearer',
                sub:         row.user_email ?? null,
                email:       row.user_email ?? null,
                username:    user?.username ?? null,
                client_id:   row.client_id,
                grant_type:  row.grant_type,
                scope:       row.scopes,
                exp:         row.access_expires,
                iat:         Math.floor(new Date(row.created_at).getTime() / 1000),
            });
        } catch (err) {
            console.error('[SSO] introspect:', err.message);
            res.status(500).json({ error: 'server_error' });
        }
    });

    /**
     * GET /oauth/userinfo  (OIDC)
     * Returns profile claims based on token scopes.
     */
    oauth.get('/userinfo', requireAuth, async (req, res) => {
        try {
            if (!req.user.email)
                return res.status(403).json({ error: 'No user associated with this token' });

            const user   = await dbUser(pool, req.user.email);
            if (!user) return res.status(404).json({ error: 'User not found' });

            const scopes  = (req.user.scopes ?? '').split(' ');
            const payload = { sub: user.email };

            if (scopes.includes('profile')) {
                payload.username      = user.username;
                payload.profile_image = user.profileImage ?? null;
                payload.badge_type    = user.badgeType ?? null;
                payload.role          = user.role ?? null;
            }
            if (scopes.includes('email')) {
                payload.email = user.email;
            }

            res.json(payload);
        } catch (err) {
            res.status(500).json({ error: 'server_error' });
        }
    });

    /**
     * POST /oauth/revoke  (RFC 7009)
     * Body: { token }  — works for both access and refresh tokens.
     */
    oauth.post('/revoke', async (req, res) => {
        try {
            const { token } = req.body;
            if (!token) return res.status(400).json({ error: 'token required' });
            await dbRevokeToken(pool, token);
            res.json({ success: true });
        } catch (err) {
            res.status(500).json({ error: 'server_error' });
        }
    });


    // ── Client management ─────────────────────────────────────

    /**
     * POST /oauth/clients
     * Register a new OAuth2 client. Must be an authenticated Levyni user.
     * Body: { name, description?, redirect_uris[], allowed_grants[], scopes?, logo_url? }
     */
    oauth.post('/clients', requireAuth, async (req, res) => {
        try {
            if (!req.user.email)
                return res.status(403).json({ error: 'Client registration requires a user account' });

            const {
                name,
                description = '',
                redirect_uris = [],
                allowed_grants = ['authorization_code'],
                scopes = 'openid profile email',
                logo_url = null,
            } = req.body;

            if (!name || !Array.isArray(redirect_uris) || redirect_uris.length === 0)
                return res.status(400).json({ error: 'name and redirect_uris[] required' });

            // Validate grant types
            const invalidGrants = allowed_grants.filter(g => !ALLOWED_GRANTS.includes(g));
            if (invalidGrants.length)
                return res.status(400).json({ error: `Unknown grant types: ${invalidGrants.join(', ')}` });

            // Client credentials apps don't need redirect URIs; auth code apps do
            if (allowed_grants.includes('authorization_code')) {
                for (const uri of redirect_uris) {
                    try { new URL(uri); }
                    catch { return res.status(400).json({ error: `Invalid redirect URI: ${uri}` }); }
                }
            }

            const slug         = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 40);
            const clientId     = `${slug}-${rand(4)}`;
            const clientSecret = rand(24);
            const secretHash   = await bcrypt.hash(clientSecret, SALT_ROUNDS);

            await pool.query(
                `INSERT INTO oauth_clients
                 (id, secret_hash, name, description, owner_email, redirect_uris, allowed_grants, scopes, logo_url)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    clientId, secretHash, name, description, req.user.email,
                    JSON.stringify(redirect_uris),
                    allowed_grants.join(','),
                    scopes,
                    logo_url,
                ]
            );

            res.status(201).json({
                success:       true,
                client_id:     clientId,
                client_secret: clientSecret,   // shown exactly once
                name,
                allowed_grants,
                redirect_uris,
                scopes,
                warning: 'Save your client_secret now — it cannot be retrieved again.',
            });
        } catch (err) {
            console.error('[SSO] client register:', err.message);
            res.status(500).json({ error: 'Client registration failed' });
        }
    });

    /** GET /oauth/clients — list clients owned by authenticated user */
    oauth.get('/clients', requireAuth, async (req, res) => {
        try {
            if (!req.user.email)
                return res.status(403).json({ error: 'Requires user account' });

            const [clients] = await pool.query(
                `SELECT id, name, description, redirect_uris, allowed_grants,
                        scopes, logo_url, is_active, created_at
                 FROM oauth_clients WHERE owner_email = ? ORDER BY created_at DESC`,
                [req.user.email]
            );
            res.json({ success: true, clients });
        } catch (err) {
            res.status(500).json({ error: 'Failed to list clients' });
        }
    });

    /** PATCH /oauth/clients/:id — update name, redirect_uris, logo */
    oauth.patch('/clients/:id', requireAuth, async (req, res) => {
        try {
            const { id } = req.params;
            const [rows] = await pool.query(
                'SELECT * FROM oauth_clients WHERE id = ? AND owner_email = ?',
                [id, req.user.email]
            );
            if (!rows[0]) return res.status(404).json({ error: 'Client not found' });

            const { name, description, redirect_uris, logo_url, is_active } = req.body;
            const updates = []; const vals = [];

            if (name !== undefined)          { updates.push('name = ?');          vals.push(name); }
            if (description !== undefined)   { updates.push('description = ?');   vals.push(description); }
            if (logo_url !== undefined)      { updates.push('logo_url = ?');       vals.push(logo_url); }
            if (is_active !== undefined)     { updates.push('is_active = ?');      vals.push(is_active ? 1 : 0); }
            if (redirect_uris !== undefined) {
                for (const u of redirect_uris) {
                    try { new URL(u); }
                    catch { return res.status(400).json({ error: `Invalid URI: ${u}` }); }
                }
                updates.push('redirect_uris = ?');
                vals.push(JSON.stringify(redirect_uris));
            }

            if (!updates.length) return res.status(400).json({ error: 'No fields to update' });

            vals.push(id);
            await pool.query(`UPDATE oauth_clients SET ${updates.join(', ')} WHERE id = ?`, vals);
            res.json({ success: true });
        } catch (err) {
            res.status(500).json({ error: 'Update failed' });
        }
    });

    /** DELETE /oauth/clients/:id — deactivate (soft delete) */
    oauth.delete('/clients/:id', requireAuth, async (req, res) => {
        try {
            const { id } = req.params;
            const [rows] = await pool.query(
                'SELECT id FROM oauth_clients WHERE id = ? AND owner_email = ?',
                [id, req.user.email]
            );
            if (!rows[0]) return res.status(404).json({ error: 'Client not found' });

            await pool.query('UPDATE oauth_clients SET is_active = 0 WHERE id = ?', [id]);
            // Revoke all active tokens for this client
            await pool.query(
                'UPDATE oauth_tokens SET revoked = 1 WHERE client_id = ?', [id]
            );
            res.json({ success: true, message: 'Client deactivated and all tokens revoked' });
        } catch (err) {
            res.status(500).json({ error: 'Delete failed' });
        }
    });

    return { auth, oauth };
}

// ── Consent page HTML ─────────────────────────────────────────
function buildConsentPage({ clientName, clientLogo, scopes, clientId, redirectUri, state, codeChallenge, trustedUser }) {
    const scopeItems = scopes
        .map(s => `
          <li>
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true">
              <path d="M2.5 7L5.5 10L11.5 4" stroke="#0f6e56" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            <span>${SCOPE_LABELS[s] ?? s}</span>
          </li>`)
        .join('');

    const logo = clientLogo
        ? `<img src="${clientLogo}" alt="${clientName}" class="logo-img">`
        : `<div class="logo-letter">${clientName.trim()[0].toUpperCase()}</div>`;

    // ── Server-rendered trusted panel (cookie was valid) ─────────
    const trustedName    = trustedUser ? (trustedUser.username || trustedUser.email.split('@')[0]) : '';
    const trustedInitial = trustedName ? trustedName[0].toUpperCase() : '';
    const trustedAvatar  = trustedUser?.profileImage
        ? `<img src="${trustedUser.profileImage}" style="width:100%;height:100%;object-fit:cover" alt="">`
        : trustedInitial;

    const trustedPanel = trustedUser ? `
  <!-- ── ONE-CLICK panel ── -->
  <div id="panel-trusted">
    <div class="trusted-chip">
      <div class="trusted-avatar">${trustedAvatar}</div>
      <div class="trusted-info">
        <div class="trusted-name">${trustedName}</div>
        <div class="trusted-email">${trustedUser.email}</div>
      </div>
      <div class="trusted-badge">&#10003; Trusted</div>
    </div>

    <div class="error" id="err-trusted" role="alert"></div>

    <div class="actions">
      <button type="button" class="btn btn-cancel" onclick="history.back()">Cancel</button>
      <button type="button" class="btn btn-approve" id="btn-trusted" onclick="doTrustedAuthorize()">
        Authorize as ${trustedName.split(' ')[0]}
      </button>
    </div>
    <div class="switch-link">
      <a onclick="showPasswordForm()">Not you? Use a different account</a>
    </div>
  </div>

  <!-- ── PASSWORD form (hidden when trusted) ── -->
  <div id="panel-password" style="display:none">` : `
  <!-- ── PASSWORD form ── -->
  <div id="panel-password">`;

    const closingDiv = `</div>`; // closes panel-password

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize ${clientName}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg:      #f7f6f3;
    --surface: #ffffff;
    --border:  #e2e1db;
    --text:    #1a1a18;
    --muted:   #73726c;
    --accent:  #3d35a8;
    --accent-h:#2e2880;
    --green:   #0f6e56;
    --danger:  #c0392b;
    --radius:  12px;
    --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #141412; --surface: #1f1f1c; --border: #2e2e2a;
      --text: #ececea; --muted: #888780; --accent: #7b6ff5; --accent-h: #9183f7; --green: #1db892;
    }
  }
  body {
    font-family: var(--font); background: var(--bg); color: var(--text);
    min-height: 100dvh; display: flex; align-items: center; justify-content: center; padding: 20px;
  }
  .card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 36px 32px; width: 100%; max-width: 400px;
  }
  .header {
    display: flex; flex-direction: column; align-items: center;
    gap: 10px; margin-bottom: 28px; text-align: center;
  }
  .logo-img { width: 52px; height: 52px; border-radius: 10px; object-fit: contain; }
  .logo-letter {
    width: 52px; height: 52px; border-radius: 10px; background: var(--accent);
    color: #fff; font-size: 24px; font-weight: 600;
    display: flex; align-items: center; justify-content: center;
  }
  .header h1 { font-size: 17px; font-weight: 600; line-height: 1.3; }
  .header p  { font-size: 13px; color: var(--muted); }

  .permissions {
    background: var(--bg); border: 1px solid var(--border);
    border-radius: 8px; padding: 14px 16px; margin-bottom: 24px;
  }
  .permissions-label {
    font-size: 11px; font-weight: 600; letter-spacing: .06em;
    text-transform: uppercase; color: var(--muted); margin-bottom: 10px;
  }
  .permissions ul { list-style: none; display: flex; flex-direction: column; gap: 7px; }
  .permissions li { display: flex; align-items: center; gap: 8px; font-size: 13px; }
  .permissions li svg { flex-shrink: 0; }

  /* Trusted chip */
  .trusted-chip {
    display: flex; align-items: center; gap: 10px;
    background: var(--bg); border: 1px solid var(--border);
    border-radius: 10px; padding: 12px 14px; margin-bottom: 20px;
  }
  .trusted-avatar {
    width: 40px; height: 40px; border-radius: 50%;
    background: var(--accent); color: #fff;
    display: flex; align-items: center; justify-content: center;
    font-size: 18px; font-weight: 600; flex-shrink: 0; overflow: hidden;
  }
  .trusted-info { min-width: 0; flex: 1; }
  .trusted-name  { font-size: 14px; font-weight: 600; color: var(--text); }
  .trusted-email { font-size: 12px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .trusted-badge { font-size: 11px; color: var(--green); font-weight: 600; white-space: nowrap; margin-left: auto; }
  .switch-link   { margin-top: 14px; text-align: center; }
  .switch-link a { font-size: 12px; color: var(--muted); cursor: pointer; text-decoration: underline; text-underline-offset: 2px; }

  .field { margin-bottom: 14px; }
  .field label { display: block; font-size: 12px; font-weight: 500; color: var(--muted); margin-bottom: 5px; }
  .field input {
    width: 100%; padding: 10px 13px; font-size: 14px; font-family: var(--font);
    color: var(--text); background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; outline: none; transition: border-color .15s, box-shadow .15s;
    -webkit-appearance: none;
  }
  .field input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 15%, transparent);
  }
  .field input::placeholder { color: var(--muted); opacity: .7; }

  .error {
    display: none; background: #fef0ef; border: 1px solid #f5c6c3;
    border-radius: 7px; padding: 10px 13px; font-size: 13px;
    color: var(--danger); margin-bottom: 14px;
  }
  @media (prefers-color-scheme: dark) {
    .error { background: #2a1414; border-color: #5a2020; color: #e88; }
  }
  .error.show { display: block; }

  .actions { display: flex; gap: 10px; margin-top: 20px; }
  .btn {
    flex: 1; padding: 11px 16px; font-size: 14px; font-family: var(--font);
    font-weight: 500; border-radius: 8px; border: none; cursor: pointer;
    transition: opacity .15s, background .15s; line-height: 1;
  }
  .btn:active { opacity: .8; }
  .btn-cancel { background: var(--bg); color: var(--text); border: 1px solid var(--border); }
  .btn-approve { background: var(--accent); color: #fff; }
  .btn-approve:hover { background: var(--accent-h); }
  .btn-approve:disabled { opacity: .55; cursor: not-allowed; }

  .spinner {
    display: inline-block; width: 14px; height: 14px;
    border: 2px solid rgba(255,255,255,.4); border-top-color: #fff;
    border-radius: 50%; animation: spin .6s linear infinite;
    vertical-align: middle; margin-right: 6px;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  .footer { margin-top: 20px; text-align: center; font-size: 11px; color: var(--muted); line-height: 1.5; }
  .footer a { color: var(--muted); text-decoration: underline; text-underline-offset: 2px; }
</style>
</head>
<body>
<div class="card">
  <div class="header">
    ${logo}
    <h1>${clientName} wants access<br>to your Levyni account</h1>
    <p>Sign in to authorize this request</p>
  </div>

  <div class="permissions">
    <p class="permissions-label">This will allow ${clientName} to</p>
    <ul>${scopeItems}</ul>
  </div>

  ${trustedPanel}

    <!-- Password form fields -->
    <form id="form" novalidate>
      <div class="field">
        <label for="email">Email</label>
        <input type="email" id="email" name="email" placeholder="you@example.com"
               autocomplete="email" required>
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input type="password" id="password" name="password"
               placeholder="Your Levyni password" autocomplete="current-password" required>
      </div>
      <div class="error" id="err" role="alert"></div>
      <div class="actions">
        <button type="button" class="btn btn-cancel" onclick="history.back()">Cancel</button>
        <button type="submit" class="btn btn-approve" id="submit-btn">Authorize</button>
      </div>
    </form>

  ${closingDiv}

  <p class="footer">
    Your password is never shared with ${clientName}.<br>
    Powered by <a href="https://levyni.com">Levyni</a>
  </p>
</div>

<script>
  const CLIENT_ID      = ${JSON.stringify(clientId)};
  const REDIRECT_URI   = ${JSON.stringify(redirectUri)};
  const STATE          = ${JSON.stringify(state)};
  const SCOPES         = ${JSON.stringify(scopes.join(' '))};
  const CODE_CHALLENGE = ${JSON.stringify(codeChallenge)};
  const IS_TRUSTED     = ${trustedUser ? 'true' : 'false'};

  function showPasswordForm() {
    document.getElementById('panel-trusted').style.display  = 'none';
    document.getElementById('panel-password').style.display = 'block';
  }

  // ── One-click authorize (cookie sent automatically by browser) ─
  async function doTrustedAuthorize() {
    const btn = document.getElementById('btn-trusted');
    const err = document.getElementById('err-trusted');
    err.classList.remove('show');
    btn.disabled  = true;
    btn.innerHTML = '<span class="spinner"></span>Authorizing\u2026';

    try {
      // Send NO email/password — server reads lv_device cookie automatically
      const res = await fetch('/oauth/authorize/approve', {
        method:      'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type':     'application/x-www-form-urlencoded',
          'X-Requested-With': 'XMLHttpRequest',
        },
        body: new URLSearchParams({
          client_id:      CLIENT_ID,
          redirect_uri:   REDIRECT_URI,
          state:          STATE,
          scopes:         SCOPES,
          code_challenge: CODE_CHALLENGE,
        }),
      });

      if (res.ok) {
        const data = await res.json().catch(() => ({}));
        if (data.redirect_to) { window.location.href = data.redirect_to; return; }
      }

      if (res.status === 401) {
        // Cookie invalid — fall back to password form
        showPasswordForm();
        return;
      }

      const ct   = res.headers.get('content-type') || '';
      const data = ct.includes('application/json') ? await res.json().catch(() => ({})) : {};
      showTrustedError(data.error ?? 'Authorization failed. Please try again.');
    } catch (_) {
      showTrustedError('Network error. Please try again.');
    } finally {
      btn.disabled    = false;
      btn.textContent = 'Authorize as ${trustedName.split(' ')[0]}';
    }
  }

  function showTrustedError(msg) {
    const err = document.getElementById('err-trusted');
    err.textContent = msg;
    err.classList.add('show');
  }

  // ── Password form ─────────────────────────────────────────────
  const form = document.getElementById('form');
  const err  = document.getElementById('err');
  const btn  = document.getElementById('submit-btn');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    err.classList.remove('show');

    const email    = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    if (!email || !password) { showError('Please fill in both fields.'); return; }

    btn.disabled  = true;
    btn.innerHTML = '<span class="spinner"></span>Authorizing\u2026';

    try {
      const res = await fetch('/oauth/authorize/approve', {
        method:      'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type':     'application/x-www-form-urlencoded',
          'X-Requested-With': 'XMLHttpRequest',
        },
        body: new URLSearchParams({
          email, password,
          client_id:      CLIENT_ID,
          redirect_uri:   REDIRECT_URI,
          state:          STATE,
          scopes:         SCOPES,
          code_challenge: CODE_CHALLENGE,
        }),
      });

      if (res.ok) {
        const data = await res.json().catch(() => ({}));
        if (data.redirect_to) { window.location.href = data.redirect_to; return; }
      }
      if (res.status === 401) { showError('Incorrect email or password. Please try again.'); return; }

      const ct   = res.headers.get('content-type') || '';
      const data = ct.includes('application/json') ? await res.json().catch(() => ({})) : {};
      showError(data.error ?? 'Authorization failed (' + res.status + '). Please try again.');
    } catch (_) {
      form.submit(); // network failure — native fallback
    }
  });

  function showError(msg) {
    err.textContent = msg;
    err.classList.add('show');
    btn.disabled    = false;
    btn.textContent = 'Authorize';
    document.getElementById('password').value = '';
    document.getElementById('password').focus();
  }
</script>
</body>
</html>`;
}

// ── Error page (minimal) ──────────────────────────────────────
function errorPage(message) {
    return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Error</title>
<style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f7f6f3}
.box{background:#fff;border:1px solid #e2e1db;border-radius:12px;padding:36px;max-width:360px;text-align:center}
h1{font-size:16px;font-weight:600;color:#1a1a18;margin-bottom:8px}p{font-size:13px;color:#73726c}</style>
</head><body><div class="box"><h1>Authorization Error</h1><p>${message}</p>
<a href="javascript:history.back()" style="display:inline-block;margin-top:16px;font-size:13px;color:#3d35a8">Go back</a>
</div></body></html>`;
}

module.exports = { createSSORouter, makeAuthMiddleware };