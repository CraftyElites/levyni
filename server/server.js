const express = require('express');
const multer = require('multer');
const cors = require('cors');
const { google } = require('googleapis');
const path = require('path');
const axios = require('axios');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const mysql = require('mysql2/promise');
const { initRobotUsersManager } = require('./src/utils/robot_users_manager');
const { initNotifications, sendToUser } = require('./src/utils/notifications');
const { createCommunityGigRouter } = require('./src/routes/community_gig_router');
const { createSSORouter, makeAuthMiddleware } = require('./src/routes/sso_router');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const app = express();
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/'); // Folder to save files
    },
    filename: function (req, file, cb) {
        // Generate a unique filename: timestamp + random suffix + original extension
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname); // Gets .jpg, .png, etc.
        cb(null, file.fieldname + '-' + uniqueSuffix + ext);
        // Example result: image-1704567890123-123456789.jpg
    }
});
/*
import { generateAllThumbnails } from "./thumbnail_generator.js";

generateAllThumbnails();*/
const { generateAllThumbnails } = require("./src/utils/thumbnail_generator");

generateAllThumbnails();
const upload = multer({ storage: storage });

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(o => o.trim())
    .filter(Boolean);
 
// Always allow localhost:3001 (Forge) in development
if (process.env.NODE_ENV !== 'production') {
    ALLOWED_ORIGINS.push('http://localhost:3001');
    ALLOWED_ORIGINS.push('http://192.168.0.100:3001'); // LAN access
}
 
app.use(require('cors')({
    origin: (origin, cb) => {
        // Allow server-to-server calls (no Origin header)
        if (!origin) return cb(null, true);
        if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
        // Allow any localhost in dev
        if (/^https?:\/\/localhost(:\d+)?$/.test(origin)) return cb(null, true);
        cb(null, false); // silently reject rather than error
    },
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
}));
app.use(cookieParser());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const saltRounds = 10;
const nodemailer = require('nodemailer');

// Create SMTP transporter (global, so it can be reused)
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

const DATA_FILE = path.join(__dirname, 'db', 'json', 'data.json');
const USERS_FILE = path.join(__dirname, 'db', 'json', 'users.json');
const SERVICES_FILE = path.join(__dirname, 'db', 'json', 'services.json');
const EVENTS_FILE = path.join(__dirname, 'db', 'json', 'events.json');
const TASKS_FILE = path.join(__dirname, 'db', 'json', 'tasks.json');
const ADMINS_FILE = path.join(__dirname, 'db', 'json', 'admins.json');
const ANSWERS_FILE = path.join(__dirname, 'db', 'json', 'answers.json');
const REQUESTS_FILE = path.join(__dirname, 'db', 'json', 'requests.json');
const TOKEN_PATH = path.join(__dirname, 'google-token.json');
const LOG_FILE = path.join(__dirname, 'db', 'json', 'admin-actions.log');
const OTPS_FILE = path.join(__dirname, 'db', 'json', 'otps.json');
const AUTH_FILE = path.join(__dirname, 'db', 'json', 'auth.html');
const SCOPES = ['https://www.googleapis.com/auth/drive'];
const crypto = require('node:crypto');

const generateUserId = () => {
    const year = new Date().getFullYear();
    const randomBytes = crypto.randomBytes(5); // 5 bytes = 10 hex chars
    const randomPart = randomBytes.toString('hex').toUpperCase(); // e.g., "A3F9B2C1D4"

    return `USR-${year}-${randomPart}`;
};

let auth;
let drive;

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    port: process.env.DB_PORT || 3306,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

(async () => {
    try {
        auth = await getOAuth2Client();
        drive = google.drive({ version: 'v3', auth });
    } catch (e) {
        console.error('OAuth2 setup failed:', e.message);
        // Continue without crashing; uploads will fail gracefully
    }

    // Ensure default settings and admin if not exist
    async function ensureDefaults() {
        try {
            // Check and set default admin key
            const [keyRows] = await pool.query('SELECT * FROM settings WHERE name = "admin_key"');
            if (keyRows.length === 0) {
                await pool.query('INSERT INTO settings (name, value) VALUES ("admin_key", "Nets")');
            }

            // Check and set default admin
            const [adminRows] = await pool.query('SELECT * FROM admins WHERE email = "enochatenaga@gmail.com"');
            if (adminRows.length === 0) {
                await pool.query(
                    'INSERT INTO admins (email, id, rank, userId, hashedPassword) VALUES (?, 1, "custom", ?, "")',
                    ["enochatenaga@gmail.com", generateUserId()]
                );
            }
        } catch (error) {
            console.error('Error initializing defaults:', error.message);
        }
    }
    await ensureDefaults();
    await initNotifications();

// Initialize Robot Users Manager
    await initRobotUsersManager(pool);

    // Function to log admin actions (keep file-based)
    function logAdminAction(action, ip, data) {
        const date = new Date().toISOString();
        const logLine = JSON.stringify({ action, date, ip, data }) + '\n';
        require('fs').appendFile(LOG_FILE, logLine, (err) => {
            if (err) console.error('Log write error:', err.message);
        });
    }

    function sanitizeEmail(email) {
        if (!email || typeof email !== 'string') {
            throw new Error('Invalid email');
        }
        return email.trim().toLowerCase();
    }

    /*const authenticateToken = (req, res, next) => {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1]; // Assumes Bearer <token>

        if (!token) {
            return res.status(401).json({ error: 'Access token required' });
        }

        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) {
                return res.status(403).json({ error: 'Invalid or expired token' });
            }
            req.user = user; // Attaches decoded user (email, userId, optional rank) to req
            next();
        });
    };*/
    const authenticateToken = makeAuthMiddleware(pool);
    app.use(express.static(path.join(__dirname, '../public')))
    const qaSignupRouter = require('./src/routes/qa-tester-router')(transporter);
    app.use('/qa-signup', qaSignupRouter);
    //--- ADMIN ROUTES ---
    const admin = express.Router()
    app.use('/admin', admin);

    const communityRouter = createCommunityGigRouter(pool, authenticateToken, sendToUser);
    app.use('/community', communityRouter);

    admin.get('/validate/:token', async (req, res) => {
        const { token } = req.params;
        const action = `${req.method} ${req.path}`;
        const ip = req.ip;
        const data = { token };
        logAdminAction(action, ip, data);

        if (!token) {
            res.status(401).send('Not Found');
        }
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            console.log('Token is valid:', decoded);
            const currentTime = Math.floor(Date.now() / 1000);
            if (decoded.exp < currentTime) {
                res.status(401).json({ message: 'Token has Expired' });
            } else {
                res.status(209).json({ message: 'Token is valid' });
            }
        } catch (error) {
            res.status(500).json({ message: 'Token is Invalid' });
            console.log(error.name)
        }
    });

    admin.post('/create', async (req, res) => {
        const { id, userId, password, email, rank, adminKey } = req.body;
        const action = `${req.method} ${req.path}`;
        const ip = req.ip;
        const data = { id, userId, email, rank, adminKey }; // Exclude password for security
        logAdminAction(action, ip, data);

        try {
            if (!id || !userId || !password || !email || !rank || !adminKey) {
                return res.status(400).json({ error: 'Invalid data: all fields are required' });
            }

            const sanitizedEmail = sanitizeEmail(email);

            const [keyRows] = await pool.query('SELECT value FROM settings WHERE name = "admin_key"');
            if (keyRows.length === 0 || keyRows[0].value !== adminKey) {
                return res.status(403).json({ message: 'Unauthorized' });
            }

            const hashedPassword = await bcrypt.hash(password, saltRounds);

            const [existing] = await pool.query('SELECT * FROM admins WHERE email = ?', [sanitizedEmail]);
            if (existing.length > 0) {
                return res.status(409).json({ error: 'Email already exists' });
            }

            await pool.query(
                'INSERT INTO admins (email, id, rank, userId, hashedPassword) VALUES (?, ?, ?, ?, ?)',
                [sanitizedEmail, id, rank, userId, hashedPassword]
            );

            res.json({ message: 'Created!', data: { id, userId, email: sanitizedEmail } });
        } catch (error) {
            console.error('Admin create error:', error.message);
            res.status(500).json({ error: 'Failed to create admin' });
        }
    });

    admin.get('/all', async (req, res) => {
        const action = `${req.method} ${req.path}`;
        const ip = req.ip;
        const data = {};
        logAdminAction(action, ip, data);

        try {
            const [admins] = await pool.query('SELECT email, id, rank, userId FROM admins');
            res.json(admins);
        } catch (error) {
            console.error('Get all admins error:', error.message);
            res.status(500).json({ error: 'Failed to retrieve admins' });
        }
    });

    admin.get('/:email', async (req, res) => {
        const { email } = req.params;
        const action = `${req.method} ${req.path}`;
        const ip = req.ip;
        const data = { email };
        logAdminAction(action, ip, data);

        try {
            const sanitizedEmail = sanitizeEmail(decodeURIComponent(email));
            const [adminRows] = await pool.query('SELECT email, id, rank, userId FROM admins WHERE email = ?', [sanitizedEmail]);
            if (adminRows.length === 0) {
                return res.status(404).json({ error: 'Admin not found' });
            }
            res.json(adminRows[0]);
        } catch (error) {
            console.error('Get single admin error:', error.message);
            res.status(500).json({ error: 'Failed to retrieve admin' });
        }
    });

    admin.post('/login', async (req, res) => {
        const { email, password, adminKey } = req.body;

        try {
            if (!email || !password || !adminKey) {
                return res.status(400).json({ error: 'Email, password and admin key are required' });
            }

            const sanitizedEmail = sanitizeEmail(email);

            const [keyRows] = await pool.query('SELECT value FROM settings WHERE name = "admin_key"');
            if (keyRows.length === 0 || keyRows[0].value !== adminKey) {
                return res.status(403).json({ error: 'Invalid admin key' });
            }

            const [adminRows] = await pool.query('SELECT * FROM admins WHERE email = ?', [sanitizedEmail]);
            if (adminRows.length === 0) {
                return res.status(403).json({ error: 'Not an admin account' });
            }
            const adminRecord = adminRows[0];

            const [userRows] = await pool.query('SELECT * FROM users WHERE email = ?', [sanitizedEmail]);
            if (userRows.length === 0 || !userRows[0].hashedPassword) {
                return res.status(401).json({ error: 'User account not found' });
            }
            const userRecord = userRows[0];

            const match = await bcrypt.compare(password, userRecord.hashedPassword);
            if (!match) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const token = jwt.sign(
                {
                    email: sanitizedEmail,
                    userId: userRecord.userId,
                    rank: adminRecord.rank
                },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );

            res.status(200).json({
                success: true,
                token,
                signedDate: Math.floor(Date.now() / 1000),
                duration: 3600,
                message: 'Admin login successful'
            });

        } catch (err) {
            console.error('Admin login error:', err.message);
            res.status(500).json({ error: 'Admin login failed' });
        }
    });


    // --- ADMIN-ONLY MIDDLEWARE (rank check) ---
    const requireAdmin = (req, res, next) => {
        if (!req.user || !req.user.rank) {
            return res.status(403).json({ error: 'Admin access required' });
        }
        // You can customize ranks: "super", "custom", etc.
        const allowedRanks = ['super', 'custom']; // adjust as needed
        if (!allowedRanks.includes(req.user.rank)) {
            return res.status(403).json({ error: 'Insufficient admin privileges' });
        }
        next();
    };

    // GET route for admin logs with time filter (keep file-based)
    admin.get('/config/logs', async (req, res) => {
        const action = `${req.method} ${req.path}`;
        const ip = req.ip;
        const data = req.query;
        logAdminAction(action, ip, data);

        const { from } = req.query;
        try {
            const fs = require('fs');
            const logContent = await fs.promises.readFile(LOG_FILE, 'utf8');
            const logs = logContent.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));

            let fromDate = null;
            if (from) {
                const match = from.match(/(\d+) (\w+) ago/);
                if (match) {
                    let ms = parseInt(match[1]);
                    const unit = match[2].toLowerCase();
                    if (unit.startsWith('day')) ms *= 24 * 60 * 60 * 1000;
                    else if (unit.startsWith('month')) ms *= 30 * 24 * 60 * 60 * 1000;
                    else if (unit.startsWith('week')) ms *= 7 * 24 * 60 * 60 * 1000;
                    else if (unit.startsWith('year')) ms *= 365 * 24 * 60 * 60 * 1000;
                    fromDate = new Date(Date.now() - ms);
                }
            }

            const filteredLogs = fromDate ? logs.filter(log => new Date(log.date) >= fromDate) : logs;
            res.json(filteredLogs);
        } catch (error) {
            console.error('Get logs error:', error.message);
            res.status(500).json({ error: 'Failed to retrieve logs' });
        }
    });

    // Apply authentication + admin check to all following routes
    //admin.use(authenticateToken, requireAdmin);

    // 1. DELETE USER BY EMAIL
    admin.delete('/users/:email', async (req, res) => {
        const { email } = req.params;
        const action = `DELETE_USER ${email}`;
        const ip = req.ip;
        logAdminAction(action, ip, { deletedBy: '' });

        try {
            const sanitizedEmail = sanitizeEmail(decodeURIComponent(email));
            const [userRows] = await pool.query('SELECT * FROM users WHERE email = ?', [sanitizedEmail]);

            if (userRows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            await pool.query('DELETE FROM users WHERE email = ?', [sanitizedEmail]);

            res.json({ success: true, message: 'User deleted successfully' });
        } catch (error) {
            console.error('Delete user error:', error.message);
            res.status(500).json({ error: 'Failed to delete user' });
        }
    });

    admin.delete('/tasks/:id', async (req, res) => {
        const { id } = req.params;
        const action = `DELETE_TASK ${id}`;
        const ip = req.ip;
        logAdminAction(action, ip, { deletedBy: '' });

        try {
            const [taskRows] = await pool.query('SELECT * FROM tasks WHERE id = ?', [id]);

            if (taskRows.length === 0) {
                return res.status(404).json({ error: 'Task not found' });
            }

            await pool.query('DELETE FROM tasks WHERE id = ?', [id]);

            res.json({ success: true, message: 'Task deleted successfully' });
        } catch (error) {
            console.error('Delete task error:', error.message);
            res.status(500).json({ error: 'Failed to delete task' });
        }
    });

    admin.delete('/services/:id', async (req, res) => {
        const { id } = req.params;
        const action = `DELETE_SERVICE ${id}`;
        const ip = req.ip;
        logAdminAction(action, ip, { deletedBy: '' });

        try {
            const [serviceRows] = await pool.query('SELECT * FROM services WHERE id = ?', [id]);

            if (serviceRows.length === 0) {
                return res.status(404).json({ error: 'Service not found' });
            }

            await pool.query('DELETE FROM services WHERE id = ?', [id]);

            res.json({ success: true, message: 'Service deleted successfully' });
        } catch (error) {
            console.error('Delete service error:', error.message);
            res.status(500).json({ error: 'Failed to delete service' });
        }
    });

    // DELETE /admin/events/:id - Delete/reject an event with notification
    admin.delete('/events/:id', async (req, res) => {
        const action = `${req.method} ${req.path}`;
        const ip = req.ip;

        try {
            const { id } = req.params;
            const { userEmail } = req.body;

            if (!id) {
                return res.status(400).json({ error: 'Event ID is required' });
            }

            const eventId = parseInt(id, 10);
            if (isNaN(eventId)) {
                return res.status(400).json({ error: 'Invalid event ID' });
            }

            const [eventRows] = await pool.query('SELECT * FROM events WHERE id = ?', [eventId]);

            if (eventRows.length === 0) {
                return res.status(404).json({ error: 'Event not found' });
            }

            const targetEvent = eventRows[0];

            // Log admin action with details
            logAdminAction(action, ip, {
                requestedBy: '',
                eventId,
                eventName: targetEvent.name,
                submittedBy: targetEvent.submittedBy
            });

            await pool.query('DELETE FROM events WHERE id = ?', [eventId]);

            // TODO: Send rejection notification to user

            res.status(200).json({
                success: true,
                message: 'Event rejected successfully',
                event: targetEvent
            });

        } catch (error) {
            console.error('Event deletion error:', error.message);
            res.status(500).json({ error: 'Failed to reject event' });
        }
    });

    // PATCH /admin/requests/validate - Validate a service request
    admin.patch('/requests/validate', async (req, res) => {
        const { email, requestId } = req.body;
        const action = 'VALIDATE_SERVICE_REQUEST';
        const ip = req.ip;
        logAdminAction(action, ip, { email, requestId, validatedBy: req.user.email });

        try {
            if (!email || !requestId) {
                return res.status(400).json({ error: 'Email and requestId are required' });
            }

            const sanitizedEmail = sanitizeEmail(email);

            const [requestRows] = await pool.query('SELECT * FROM service_requests WHERE email = ? AND id = ?', [sanitizedEmail, requestId]);
            if (requestRows.length === 0) {
                return res.status(404).json({ error: 'Request not found' });
            }
            const request = requestRows[0];

            if (request.status !== 'pending') {
                return res.status(400).json({ error: 'Request is not pending' });
            }

            const [userRows] = await pool.query('SELECT * FROM users WHERE email = ?', [sanitizedEmail]);
            if (userRows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            const user = userRows[0];

            const marketPoints = parseInt(user.marketPoints) || 0;
            const requestPrice = parseFloat(request.price) || 0;

            await pool.query(
                'UPDATE service_requests SET status = "validated", validatedAt = NOW(), validatedBy = ? WHERE id = ?',
                [req.user.email, requestId]
            );

            await pool.query(
                'UPDATE users SET marketPoints = ?, pending = ? WHERE email = ?',
                [Math.max(0, marketPoints - requestPrice), Math.max(0, (parseInt(user.pending) || 0) - 1), sanitizedEmail]
            );

            const [updatedRequest] = await pool.query('SELECT * FROM service_requests WHERE id = ?', [requestId]);
            const [updatedUser] = await pool.query('SELECT marketPoints, pending FROM users WHERE email = ?', [sanitizedEmail]);

            res.json({
                success: true,
                message: 'Service request validated successfully',
                request: updatedRequest[0],
                updatedUser: updatedUser[0]
            });

        } catch (error) {
            console.error('Validate service request error:', error.message);
            res.status(500).json({ error: 'Failed to validate service request' });
        }
    });

    app.post('/api/request/service', async (req, res) => {
        const { email, serviceId } = req.body;

        try {
            if (!email || !serviceId) {
                return res.status(400).json({ error: 'Email and serviceId are required' });
            }

            const sanitizedEmail = sanitizeEmail(email);

            const [userRows] = await pool.query('SELECT * FROM users WHERE email = ?', [sanitizedEmail]);
            if (userRows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            const user = userRows[0];

            const [serviceRows] = await pool.query('SELECT * FROM services WHERE id = ?', [serviceId]);
            if (serviceRows.length === 0) {
                return res.status(404).json({ error: 'Service not found' });
            }
            const service = serviceRows[0];

            const verifiedPoints = parseInt(user.verifiedPoints) || 0;
            const servicePrice = parseFloat(service.price) || 0;

            if (verifiedPoints < servicePrice) {
                return res.status(400).json({
                    error: 'Insufficient verified points',
                    required: servicePrice,
                    available: verifiedPoints
                });
            }

            await pool.query(
                'INSERT INTO service_requests (email, serviceId, serviceName, price, status, createdAt) VALUES (?, ?, ?, ?, "pending", NOW())',
                [sanitizedEmail, service.id, service.name, servicePrice]
            );

            const [newRequestRows] = await pool.query(
                'SELECT * FROM service_requests WHERE email = ? ORDER BY id DESC LIMIT 1',
                [sanitizedEmail]
            );
            const newRequest = newRequestRows[0];

            await pool.query(
                'UPDATE users SET verifiedPoints = ?, marketPoints = ?, pending = ? WHERE email = ?',
                [
                    verifiedPoints - servicePrice,
                    (parseInt(user.marketPoints) || 0) + servicePrice,
                    (parseInt(user.pending) || 0) + 1,
                    sanitizedEmail
                ]
            );

            const [updatedUser] = await pool.query('SELECT verifiedPoints, pending FROM users WHERE email = ?', [sanitizedEmail]);

            res.status(201).json({
                success: true,
                message: 'Service request created successfully',
                request: newRequest,
                remainingPoints: updatedUser[0].verifiedPoints,
                pendingRequests: updatedUser[0].pending
            });

        } catch (error) {
            console.error('Service request error:', error.message);
            res.status(500).json({ error: 'Failed to create service request' });
        }
    });

    // 2. CHANGE MASTER ADMIN KEY (very sensitive!)
    admin.patch('/key', async (req, res) => {
        const { newKey, email } = req.body;
        const action = 'CHANGE_ADMIN_KEY';
        const ip = req.ip;
        logAdminAction(action, ip, { changedBy: email });

        if (!newKey || typeof newKey !== 'string' || newKey.trim().length < 6) {
            return res.status(400).json({ error: 'New key must be at least 6 characters' });
        }

        try {
            const [existing] = await pool.query('SELECT * FROM settings WHERE name = "admin_key"');
            if (existing.length > 0) {
                await pool.query('UPDATE settings SET value = ? WHERE name = "admin_key"', [newKey.trim()]);
            } else {
                await pool.query('INSERT INTO settings (name, value) VALUES ("admin_key", ?)', [newKey.trim()]);
            }

            process.env.ADMIN_KEY = newKey.trim();

            res.json({ success: true, message: 'Admin master key updated successfully' });
        } catch (error) {
            console.error('Change admin key error:', error.message);
            res.status(500).json({ error: 'Failed to update admin key' });
        }
    });

    // PATCH /api/admin/config - Update app configuration (admin only)
    admin.patch('/config', async (req, res) => {
        const { appUpdateUrl, appAvailable, version, updateNote } = req.body;

        // At least one field must be provided
        if (
            appUpdateUrl === undefined &&
            appAvailable === undefined &&
            version === undefined &&
            updateNote === undefined
        ) {
            return res.status(400).json({ error: 'No configuration fields provided' });
        }

        // Type validation
        if (appUpdateUrl !== undefined && typeof appUpdateUrl !== 'string') {
            return res.status(400).json({ error: 'appUpdateUrl must be a string' });
        }
        if (appAvailable !== undefined && typeof appAvailable !== 'boolean') {
            return res.status(400).json({ error: 'appAvailable must be a boolean' });
        }
        if (version !== undefined && typeof version !== 'string') {
            return res.status(400).json({ error: 'version must be a string' });
        }
        if (updateNote !== undefined && typeof updateNote !== 'string') {
            return res.status(400).json({ error: 'updateNote must be a string' });
        }

        try {
            const updates = [];
            if (appUpdateUrl !== undefined) {
                updates.push({ name: 'app_update_url', value: appUpdateUrl.trim() || null });
            }
            if (appAvailable !== undefined) {
                updates.push({ name: 'app_available', value: appAvailable ? 'true' : 'false' });
            }
            if (version !== undefined) {
                updates.push({ name: 'app_version', value: version.trim() || null });
            }
            if (updateNote !== undefined) {
                updates.push({ name: 'app_update_note', value: updateNote.trim() || null });
            }

            for (const update of updates) {
                const [exist] = await pool.query('SELECT * FROM settings WHERE name = ?', [update.name]);
                if (exist.length > 0) {
                    await pool.query('UPDATE settings SET value = ? WHERE name = ?', [update.value, update.name]);
                } else if (update.value !== null) {
                    await pool.query('INSERT INTO settings (name, value) VALUES (?, ?)', [update.name, update.value]);
                }
            }

            const [configRows] = await pool.query('SELECT name, value FROM settings WHERE name LIKE "app_%"');
            const appConfig = configRows.reduce((acc, row) => {
                let key = row.name.replace('app_', '');
                let value = row.value;
                if (key === 'available') value = value === 'true';
                acc[key] = value;
                return acc;
            }, {});

            res.json({
                success: true,
                message: 'App configuration updated successfully',
                appConfig
            });
        } catch (error) {
            console.error('Error updating app config:', error.message);
            res.status(500).json({ error: 'Failed to update app configuration.' });
        }
    });

    // GET /api/config - Public route to fetch current app configuration
    app.get('/api/config', async (req, res) => {
        try {
            const [configRows] = await pool.query('SELECT name, value FROM settings WHERE name LIKE "app_%"');
            const appConfig = configRows.reduce((acc, row) => {
                let key = row.name.replace('app_', '');
                let value = row.value;
                if (key === 'available') value = value === 'true';
                acc[key] = value;
                return acc;
            }, {
                update_url: null,
                available: true,
                version: null,
                update_note: null
            });

            res.json({
                success: true,
                appConfig
            });
        } catch (error) {
            console.error('Error fetching app config:', error.message);
            res.status(500).json({ error: 'Failed to fetch app configuration.' });
        }
    });

    admin.patch('/answers', async (req, res) => {
        const { status, email, taskId } = req.body;

        if (!['validated', 'demoted'].includes(status) || !email || !taskId) {
            return res.status(400).json({ error: 'Invalid or missing fields: status, email, taskId' });
        }

        const sanitizedEmail = sanitizeEmail(email);

        try {
            const [answerRows] = await pool.query('SELECT * FROM answers WHERE email = ? AND taskId = ?', [sanitizedEmail, taskId]);
            if (answerRows.length === 0) {
                return res.status(404).json({ error: 'Answer not found' });
            }
            const answer = answerRows[0];
            const reward = parseInt(answer.reward) || 0;

            const [userRows] = await pool.query('SELECT * FROM users WHERE email = ?', [sanitizedEmail]);
            if (userRows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            const user = userRows[0];

            const unVerified = parseInt(user.unVerifiedPoints) || 0;
            const verified = parseInt(user.verifiedPoints) || 0;

            let newUnVerified = unVerified;
            let newVerified = verified;

            if (status === 'validated') {
                newUnVerified = Math.max(0, unVerified - reward);
                newVerified = verified + reward;
            } else if (status === 'demoted') {
                newUnVerified = Math.max(0, unVerified - reward);
            }

            await pool.query(
                'UPDATE answers SET reviewed = true, status = ? WHERE email = ? AND taskId = ?',
                [status, sanitizedEmail, taskId]
            );

            await pool.query(
                'UPDATE users SET unVerifiedPoints = ?, verifiedPoints = ? WHERE email = ?',
                [newUnVerified, newVerified, sanitizedEmail]
            );

            res.json({
                success: true,
                message: `Answer ${status} successfully`,
                pointsUpdated: true
            });
        } catch (error) {
            console.error('Error updating answer:', error.message);
            res.status(500).json({ error: 'Failed to update answer.' });
        }
    });




    //--- OTHER ROUTES  ---

    // Also update the upload endpoint to handle token errors gracefully:
    app.post('/api/upload', upload.single('file'), async (req, res) => {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        if (!drive) {
            return res.status(503).json({ error: 'Google Drive service unavailable' });
        }

        try {
            const fs = require('fs');
            const fileMetadata = {
                name: req.file.originalname,
                parents: [process.env.DRIVE_FOLDER_ID],
            };
            const media = {
                mimeType: req.file.mimetype,
                body: fs.createReadStream(req.file.path),
            };

            const response = await drive.files.create({
                requestBody: fileMetadata,
                media: media,
                fields: 'id',
                supportsAllDrives: true,
            });

            const fileId = response.data.id;

            await drive.permissions.create({
                fileId: fileId,
                requestBody: {
                    role: 'reader',
                    type: 'anyone',
                },
            });

            const url = `https://drive.google.com/uc?id=${fileId}`;
            await fs.promises.unlink(req.file.path);

            if (process.env.DISCORD_WEBHOOK_URL) {
                try {
                    await axios.post(process.env.DISCORD_WEBHOOK_URL, {
                        content: `New image uploaded: ${url}`,
                    });
                } catch (discordError) {
                    console.error('Discord notification failed:', discordError.message);
                }
            }

            res.status(200).json({ url });
        } catch (error) {
            console.error('Upload error:', error.message, error.response?.data || error.response);

            const fs = require('fs');
            if (req.file && fs.existsSync(req.file.path)) {
                await fs.promises.unlink(req.file.path).catch(unlinkErr =>
                    console.error('Failed to clean up file:', unlinkErr.message)
                );
            }

            // Handle specific token errors
            if (error.response?.data?.error === 'invalid_grant' ||
                error.code === 401 ||
                error.message?.includes('invalid_grant')) {
                return res.status(401).json({
                    error: 'Google Drive authentication expired. Please re-authenticate.',
                    action: 'reauth_required',
                    authUrl: '/get_gauth_link'
                });
            }

            res.status(500).json({ error: 'Upload failed. Please try again.' });
        }
    });

    app.get('/api/services', async (req, res) => {
        try {
            const [services] = await pool.query('SELECT * FROM services');
            res.status(200).json(services);
        } catch (error) {
            console.error('Services read error:', error.message);
            res.status(500).json({ error: 'Failed to retrieve services' });
        }
    });

    app.post('/api/services', upload.single('image'), async (req, res) => {
        try {
            const { name, price, desc, type } = req.body;

            const [maxIdRows] = await pool.query('SELECT MAX(id) as maxId FROM services');
            const newId = (maxIdRows[0].maxId || 0) + 1;

            if (!name || !price || !desc || !type) {
                return res.status(400).json({ error: 'Missing required fields: name, price, desc, type' });
            }

            let imagePath = null;
            if (req.file) {
                const dirPath = path.join('uploads', req.file.filename);
                imagePath = `https://levyni.com/${dirPath}`;
            }

            await pool.query(
                'INSERT INTO services (id, name, price, `desc`, type, image) VALUES (?, ?, ?, ?, ?, ?)',
                [newId, name, parseFloat(price), desc, type, imagePath]
            );

            const newService = { id: newId, name, price: parseFloat(price), desc, type, image: imagePath || null };

            res.status(201).json({ success: true, service: newService });
        } catch (error) {
            console.error('Service save error:', error.message);

            const fs = require('fs');
            if (req.file && fs.existsSync(req.file.path)) {
                await fs.promises.unlink(req.file.path).catch(unlinkErr => console.error('Failed to clean up file:', unlinkErr.message));
            }

            res.status(500).json({ error: 'Service save failed. Please try again.' });
        }
    });

    app.get('/api/events', async (req, res) => {
        try {
            const [events] = await pool.query('SELECT * FROM events WHERE reviewed = true');
            res.status(200).json(events);
        } catch (error) {
            console.error('Events read error:', error.message);
            res.status(500).json({ error: 'Failed to retrieve events' });
        }
    });

    // GET /admin/events/unreviewed - Get all unreviewed events
    admin.get('/events/unreviewed', async (req, res) => {
        const action = `${req.method} ${req.path}`;
        const ip = req.ip;
        logAdminAction(action, ip, { requestedBy: '' });

        try {
            const [events] = await pool.query('SELECT * FROM events WHERE reviewed = false');

            res.status(200).json({
                success: true,
                count: events.length,
                events
            });
        } catch (error) {
            console.error('Get unreviewed events error:', error.message);
            res.status(500).json({ error: 'Failed to retrieve unreviewed events' });
        }
    });

    // Fix the GET /admin/events/all endpoint typo
    admin.get('/events/all', async (req, res) => {
        const action = `${req.method} ${req.path}`;
        const ip = req.ip;
        logAdminAction(action, ip, { requestedBy: '' });

        try {
            const [events] = await pool.query('SELECT * FROM events');

            const reviewed = events.filter(e => e.reviewed === true);
            const unreviewed = events.filter(e => e.reviewed === false);

            res.status(200).json({
                success: true,
                total: events.length,
                reviewedCount: reviewed.length,
                unreviewedCount: unreviewed.length,
                events
            });
        } catch (error) {
            console.error('Get all events error:', error.message);
            res.status(500).json({ error: 'Failed to retrieve events' });
        }
    });

    app.post('/api/events', upload.single('image'), async (req, res) => {
        try {
            const { name, desc, type, url, email } = req.body;

            const sanitizedEmail = sanitizeEmail(email);

            const [maxIdRows] = await pool.query('SELECT MAX(id) as maxId FROM events');
            const newId = (maxIdRows[0].maxId || 0) + 1;

            if (!name || !url || !desc || !type || !sanitizedEmail) {
                return res.status(400).json({ error: 'Missing required fields: name, desc, type' });
            }

            let imagePath = null;
            if (req.file) {
                const dirPath = path.join('uploads', req.file.filename);
                imagePath = `https://levyni.com/${dirPath}`;
            }

            await pool.query(
                'INSERT INTO events (id, name, `desc`, type, url, reviewed, submittedBy, submittedAt, image) VALUES (?, ?, ?, ?, ?, true, ?, NOW(), ?)',
                [newId, name, desc, type, url, sanitizedEmail, imagePath]
            );

            const newEvent = {
                id: newId,
                name,
                desc,
                type,
                url,
                reviewed: true,
                submittedBy: sanitizedEmail,
                submittedAt: new Date().toISOString(),
                image: imagePath || null
            };

            res.status(201).json({ success: true, event: newEvent });
        } catch (error) {
            console.error('Event save error:', error.message);

            const fs = require('fs');
            if (req.file && fs.existsSync(req.file.path)) {
                await fs.promises.unlink(req.file.path).catch(unlinkErr => console.error('Failed to clean up file:', unlinkErr.message));
            }

            res.status(500).json({ error: 'Event save failed. Please try again.' });
        }
    });

    // Updated POST /api/request/events endpoint with email tracking
    app.post('/api/request/events', upload.single('image'), async (req, res) => {
        try {
            const { name, desc, type, url, userEmail } = req.body; // Added userEmail

            const [maxIdRows] = await pool.query('SELECT MAX(id) as maxId FROM events');
            const newId = (maxIdRows[0].maxId || 0) + 1;

            if (!req.file) {
                return res.status(400).json({ error: 'Please attach related image!' });
            }

            if (!name || !url || !desc || !type) {
                return res.status(400).json({ error: 'Missing required fields: name, desc, type, url' });
            }

            // Validate email if provided
            if (!userEmail) {
                return res.status(400).json({ error: 'User email is required for event submission' });
            }

            const sanitizedEmail = sanitizeEmail(userEmail);

            let imagePath = null;
            if (req.file) {
                const dirPath = path.join('uploads', req.file.filename);
                imagePath = `https://levyni.com/${dirPath}`;
            }

            await pool.query(
                'INSERT INTO events (id, name, `desc`, type, url, reviewed, submittedBy, submittedAt, image) VALUES (?, ?, ?, ?, ?, false, ?, NOW(), ?)',
                [newId, name, desc, type, url, sanitizedEmail, imagePath]
            );

            const newEvent = {
                id: newId,
                name,
                desc,
                type,
                url,
                reviewed: false,
                submittedBy: sanitizedEmail,
                submittedAt: new Date().toISOString(),
                image: imagePath || null
            };

            res.status(201).json({
                success: true,
                event: newEvent,
                message: 'Event submitted for review'
            });
        } catch (error) {
            console.error('Event save error:', error.message);

            const fs = require('fs');
            if (req.file && fs.existsSync(req.file.path)) {
                await fs.promises.unlink(req.file.path).catch(unlinkErr =>
                    console.error('Failed to clean up file:', unlinkErr.message)
                );
            }

            res.status(500).json({ error: 'Event save failed. Please try again.' });
        }
    });
    // Fix the typo in the stamp endpoint (reveiwed -> reviewed)
    admin.patch('/stamp/events/:id', async (req, res) => {
        const action = `${req.method} ${req.path}`;
        const ip = req.ip;

        try {
            const { id } = req.params;

            if (!id) {
                return res.status(400).json({ error: 'Event ID is required' });
            }

            const eventId = parseInt(id, 10);
            if (isNaN(eventId)) {
                return res.status(400).json({ error: 'Invalid event ID' });
            }

            const [eventRows] = await pool.query('SELECT * FROM events WHERE id = ?', [eventId]);

            if (eventRows.length === 0) {
                return res.status(404).json({ error: 'Event not found' });
            }

            const targetEvent = eventRows[0];

            if (targetEvent.reviewed === true) {
                return res.status(400).json({ error: 'Event is already reviewed/approved' });
            }

            // Log admin action
            logAdminAction(action, ip, {
                requestedBy: '',
                eventId,
                eventName: targetEvent.name,
                submittedBy: targetEvent.submittedBy
            });

            await pool.query(
                'UPDATE events SET reviewed = true, approvedBy = ?, approvedAt = NOW() WHERE id = ?',
                ['', eventId]
            );

            const [updatedEvent] = await pool.query('SELECT * FROM events WHERE id = ?', [eventId]);

            // TODO: Send approval notification to user

            res.status(200).json({
                success: true,
                message: 'Event approved successfully',
                event: updatedEvent[0]
            });

        } catch (error) {
            console.error('Event stamp error:', error.message);
            res.status(500).json({ error: 'Failed to approve event' });
        }
    });


    app.get('/api/tasks', async (req, res) => {
        try {
            const [tasks] = await pool.query('SELECT * FROM tasks');
            res.status(200).json(tasks);
        } catch (error) {
            console.error('Tasks read error:', error.message);
            res.status(500).json({ error: 'Failed to retrieve tasks' });
        }
    });

    app.post('/api/tasks', upload.single('image'), async (req, res) => {
        const { desc, type, reward, shortResponse } = req.body
        try {

            const [maxIdRows] = await pool.query('SELECT MAX(id) as maxId FROM tasks');
            const newId = (maxIdRows[0].maxId || 0) + 1;

            if (!desc || !type || !reward) {
                return res.status(400).json({ error: 'Missing required fields: desc, type, reward' });
            }

            let imagePath = null;
            if (req.file) {
                const dirPath = path.join('uploads', req.file.filename);
                imagePath = `https://levyni.com/${dirPath}`;
            }


            await pool.query(
                'INSERT INTO tasks (id, `desc`, type, shortResponse, reward, image) VALUES (?, ?, ?, ?, ?, ?)',
                [newId, desc, type, shortResponse, reward, imagePath]
            );

            const newTask = {
                id: newId,
                desc,
                type,
                shortResponse,
                reward,
                image: imagePath || null
            };

            res.status(201).json({ success: true, task: newTask });
        } catch (error) {
            console.error('Task save error:', error.message);

            const fs = require('fs');
            if (req.file && fs.existsSync(req.file.path)) {
                await fs.promises.unlink(req.file.path).catch(unlinkErr => console.error('Failed to clean up file:', unlinkErr.message));
            }

            res.status(500).json({ error: 'Task save failed. Please try again.' });
        }
    });

    app.get('/', async (req, res) => {
        try {
            res.sendFile(path.join(__dirname, '../public/'));
        } catch (error) {

        }
    });




    // ============================================
    // BACKEND - Node.js/Express Routes
    // ============================================

    // 1. POST /api/answers - Submit answer (NO image upload)
    app.post('/api/answers', async (req, res) => {
        const { email, taskId, response, reward, type } = req.body;

        try {
            if (!email || !taskId || !response || !type) {
                return res.status(400).json({ message: 'Invalid message: missing required fields' });
            }

            const sanitizedEmail = sanitizeEmail(email);

            const [existingAnswer] = await pool.query(
                'SELECT * FROM answers WHERE email = ? AND taskId = ?',
                [sanitizedEmail, taskId]
            );

            let id;
            if (existingAnswer.length > 0) {
                // CRITICAL FIX: Prevent updating reviewed answers
                if (existingAnswer[0].reviewed === true || existingAnswer[0].reviewed === 1) {
                    return res.status(403).json({
                        error: 'Cannot modify reviewed answers',
                        message: 'This answer has already been reviewed and cannot be changed'
                    });
                }

                id = existingAnswer[0].id;
                await pool.query(
                    'UPDATE answers SET type = ?, response = ?, reward = ?, reviewed = false WHERE email = ? AND taskId = ?',
                    [type, response, reward, sanitizedEmail, taskId]
                );
            } else {
                const [maxIdRows] = await pool.query(
                    'SELECT MAX(id) as maxId FROM answers WHERE email = ?',
                    [sanitizedEmail]
                );
                id = (maxIdRows[0].maxId || 0) + 1;
                await pool.query(
                    'INSERT INTO answers (id, email, taskId, type, response, reward, reviewed) VALUES (?, ?, ?, ?, ?, ?, false)',
                    [id, sanitizedEmail, taskId, type, response, reward]
                );
            }

            // Only add points for NEW answers (not updates)
            if (existingAnswer.length === 0) {
                await pool.query(
                    'UPDATE users SET unVerifiedPoints = unVerifiedPoints + ?, record = record + 1 WHERE email = ?',
                    [parseInt(reward), sanitizedEmail]
                );
            }

            const newAnswer = {
                id,
                taskId,
                type,
                response,
                reward,
                attachment: null,
                reviewed: false
            };

            res.status(200).json({
                success: true,
                data: newAnswer,
                message: 'Answer submitted successfully'
            });
        } catch (error) {
            console.error('Answer submission error:', error);
            res.status(500).json({
                error: 'Failed to submit answer',
                details: error.message
            });
        }
    });

    // 2. POST /api/answers/:email/attach-image - Upload image for specific answer
    app.post('/api/answers/:email/attach-image', upload.single('image'), async (req, res) => {
        const { email } = req.params;
        const { taskId } = req.body;

        const sanitizedEmail = sanitizeEmail(decodeURIComponent(email));

        try {
            if (!req.file) {
                return res.status(400).json({ error: 'No image uploaded' });
            }

            if (!taskId) {
                const fs = require('fs');
                if (fs.existsSync(req.file.path)) {
                    await fs.promises.unlink(req.file.path);
                }
                return res.status(400).json({ error: 'taskId is required' });
            }

            const [answerRows] = await pool.query(
                'SELECT * FROM answers WHERE email = ? AND taskId = ?',
                [sanitizedEmail, taskId]
            );

            if (answerRows.length === 0) {
                const fs = require('fs');
                if (fs.existsSync(req.file.path)) {
                    await fs.promises.unlink(req.file.path);
                }
                return res.status(404).json({ error: 'Answer not found' });
            }

            // CRITICAL FIX: Prevent modifying reviewed answers
            if (answerRows[0].reviewed === true || answerRows[0].reviewed === 1) {
                const fs = require('fs');
                if (fs.existsSync(req.file.path)) {
                    await fs.promises.unlink(req.file.path);
                }
                return res.status(403).json({
                    error: 'Cannot modify reviewed answers',
                    message: 'This answer has already been reviewed and cannot be changed'
                });
            }

            const dirPath = path.join('uploads', req.file.filename);
            const imagePath = `https://levyni.com/${dirPath}`;

            await pool.query(
                'UPDATE answers SET attachment = ? WHERE email = ? AND taskId = ?',
                [imagePath, sanitizedEmail, taskId]
            );

            const [updatedAnswer] = await pool.query(
                'SELECT * FROM answers WHERE email = ? AND taskId = ?',
                [sanitizedEmail, taskId]
            );

            res.status(200).json({
                success: true,
                message: 'Image attached successfully',
                answer: updatedAnswer[0]
            });
        } catch (error) {
            console.error('Attach image error:', error);

            const fs = require('fs');
            if (req.file && fs.existsSync(req.file.path)) {
                await fs.promises.unlink(req.file.path).catch(unlinkErr =>
                    console.error('Failed to clean up file:', unlinkErr.message)
                );
            }

            res.status(500).json({
                error: 'Failed to attach image',
                details: error.message
            });
        }
    });

    // 3. POST /api/answers/sync/:email - Sync answers from client
    app.post('/api/answers/sync/:email', async (req, res) => {
        const { email } = req.params;
        const sanitizedEmail = sanitizeEmail(decodeURIComponent(email));

        try {
            const userAnswers = req.body;

            if (!Array.isArray(userAnswers)) {
                return res.status(400).json({
                    error: 'Invalid data format: expected array'
                });
            }

            if (userAnswers.length === 0) {
                return res.status(400).json({
                    error: 'Invalid message: empty array'
                });
            }

            const [currentAnswers] = await pool.query(
                'SELECT * FROM answers WHERE email = ?',
                [sanitizedEmail]
            );

            for (const answer of userAnswers) {
                if (answer.taskId) {
                    const existing = currentAnswers.find(item => item.taskId === answer.taskId);

                    // CRITICAL FIX: Skip reviewed answers
                    if (existing && (existing.reviewed === true || existing.reviewed === 1)) {
                        console.log(`Skipping reviewed answer for taskId ${answer.taskId}`);
                        continue; // Skip this answer
                    }

                    const id = existing ? existing.id : (Math.max(...currentAnswers.map(a => a.id), 0) + 1);

                    if (existing) {
                        await pool.query(
                            'UPDATE answers SET type = ?, response = ?, reward = ?, attachment = ? WHERE email = ? AND taskId = ? AND reviewed = false',
                            [answer.type || 'Long-term', answer.response, answer.reward, answer.attachment || existing.attachment, sanitizedEmail, answer.taskId]
                        );
                    } else {
                        await pool.query(
                            'INSERT INTO answers (id, email, taskId, type, response, reward, attachment, reviewed, status) VALUES (?, ?, ?, ?, ?, ?, ?, false, ?)',
                            [id, sanitizedEmail, answer.taskId, answer.type || 'Long-term', answer.response, answer.reward, answer.attachment || null, null]
                        );
                    }
                }
            }

            const [updatedAnswers] = await pool.query(
                'SELECT * FROM answers WHERE email = ?',
                [sanitizedEmail]
            );

            res.status(200).json({
                success: true,
                data: updatedAnswers,
                message: 'Answers synced successfully (reviewed answers were preserved)'
            });
        } catch (error) {
            console.error('Sync error:', error);
            res.status(500).json({
                error: 'Failed to sync answers',
                details: error.message
            });
        }
    });

    // 4. GET /api/answers - Get all answers with task descriptions
    app.get('/api/answers', async (req, res) => {
        try {
            const [answers] = await pool.query(`
                SELECT a.*, u.email, t.\`desc\` as taskDesc 
                FROM answers a 
                JOIN users u ON a.email = u.email 
                JOIN tasks t ON a.taskId = t.id
            `);

            res.json(answers);
        } catch (error) {
            console.error('Error fetching answers:', error.message);
            res.status(500).json({ error: 'Failed to fetch answers. Please try again.' });
        }
    });

    // 5. GET /api/answers/:email - Get answers for specific user
    app.get('/api/answers/:email', async (req, res) => {
        const { email } = req.params;

        const sanitizedEmail = sanitizeEmail(decodeURIComponent(email));

        try {
            const [answers] = await pool.query('SELECT * FROM answers WHERE email = ?', [sanitizedEmail]);

            res.json(answers);
        } catch (error) {
            console.error('Error fetching user answers:', error);
            res.status(500).json({
                error: 'Failed to fetch user answers',
                details: error.message
            });
        }
    });

    // 6. ADMIN: PATCH /admin/answers - Validate or demote answer
    admin.patch('/answers', async (req, res) => {
        const { status, email, taskId } = req.body;

        if (!['validated', 'demoted'].includes(status) || !email || !taskId) {
            return res.status(400).json({
                error: 'Invalid or missing fields: status, email, taskId'
            });
        }

        const sanitizedEmail = sanitizeEmail(email);

        try {
            const [answerRows] = await pool.query('SELECT * FROM answers WHERE email = ? AND taskId = ?', [sanitizedEmail, taskId]);
            if (answerRows.length === 0) {
                return res.status(404).json({ error: 'Answer not found' });
            }
            const answer = answerRows[0];
            const reward = parseInt(answer.reward) || 0;

            const [userRows] = await pool.query('SELECT * FROM users WHERE email = ?', [sanitizedEmail]);
            if (userRows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            const user = userRows[0];

            const unVerified = parseInt(user.unVerifiedPoints) || 0;
            const verified = parseInt(user.verifiedPoints) || 0;

            let newUnVerified = unVerified;
            let newVerified = verified;

            if (status === 'validated') {
                newUnVerified = Math.max(0, unVerified - reward);
                newVerified = verified + reward;
            } else if (status === 'demoted') {
                newUnVerified = Math.max(0, unVerified - reward);
            }

            await pool.query(
                'UPDATE answers SET reviewed = true, status = ? WHERE email = ? AND taskId = ?',
                [status, sanitizedEmail, taskId]
            );

            await pool.query(
                'UPDATE users SET unVerifiedPoints = ?, verifiedPoints = ? WHERE email = ?',
                [newUnVerified, newVerified, sanitizedEmail]
            );

            res.json({
                success: true,
                message: `Answer ${status} successfully`,
                pointsUpdated: true
            });
        } catch (error) {
            console.error('Error updating answer:', error.message);
            res.status(500).json({ error: 'Failed to update answer.' });
        }
    });

    app.post('/api/auth/login', async (req, res) => {
        const { email, password } = req.body;
        try {
            if (!email || !password) {
                return res.status(400).json({ error: 'Email and password are required' });
            }

            const sanitizedEmail = sanitizeEmail(email);

            const [userRows] = await pool.query('SELECT * FROM users WHERE email = ?', [sanitizedEmail]);
            if (userRows.length === 0) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            const user = userRows[0];
            if (!user.userId || !user.hashedPassword) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const match = await bcrypt.compare(password, user.hashedPassword);
            if (!match) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            const token = jwt.sign(
                { email: sanitizedEmail, userId: user.userId },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );
            const { hashedPassword, ...safeUser } = user;
            res.json({ success: true, token, user: safeUser });
        } catch (error) {
            console.error('User login error:', error.message);
            res.status(500).json({ error: 'Login failed' });
        }
    });

    app.post('/api/auth/signin', async (req, res) => {
        const { username, email, password } = req.body;
        try {
            if (!username || !email || !password) {
                return res.status(400).json({ message: 'All fields are required!' });
            }

            const sanitizedEmail = sanitizeEmail(email);

            const [userRows] = await pool.query('SELECT * FROM users WHERE email = ?', [sanitizedEmail]);
            if (userRows.length > 0) {
                return res.status(409).json({ message: 'Email already registered' });
            }

            const [otpRows] = await pool.query('SELECT * FROM otps WHERE email = ?', [sanitizedEmail]);
            let pending = otpRows[0];
            if (pending) {
                if (Date.now() > pending.expires) {
                    await pool.query('DELETE FROM otps WHERE email = ?', [sanitizedEmail]);
                    pending = null;
                } else {
                    return res.status(409).json({ message: 'Email pending verification' });
                }
            }

            const userId = generateUserId();
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            // Generate 6-digit OTP
            const otp = Math.floor(100000 + Math.random() * 900000).toString();
            const expires = Date.now() + 10 * 60 * 1000; // 10 minutes from now

            // Store pending data
            await pool.query(
                'INSERT INTO otps (email, otp, expires, username, hashedPassword, userId) VALUES (?, ?, ?, ?, ?, ?)',
                [sanitizedEmail, otp, expires, username, hashedPassword, userId]
            );

            // Send OTP email
            const mailOptions = {
                from: process.env.SMTP_FROM,
                to: sanitizedEmail,
                subject: 'Your OTP for Registration',
                text: `Your one-time password (OTP) is ${otp}. It expires in 10 minutes. Please use it to complete your registration.`
            };

            await transporter.sendMail(mailOptions);

            // Optional: Discord notification
            if (process.env.DISCORD_WEBHOOK_URL) {
                try {
                    await axios.post(process.env.DISCORD_WEBHOOK_URL, {
                        content: `OTP sent for new user registration: ${sanitizedEmail}`
                    });
                } catch (discordError) {
                    console.error('Discord notification failed:', discordError.message);
                }
            }

            res.status(200).json({ success: true, message: 'OTP sent to your email. Please verify to complete registration.' });
        } catch (error) {
            console.error('Signup error:', error.message);
            res.status(500).json({ error: 'Failed to process signup request' });
        }
    });
    app.post('/api/auth/verify-otp', async (req, res) => {
        const { email, otp } = req.body;
        try {
            if (!email || !otp) {
                return res.status(400).json({ message: 'Email and OTP are required' });
            }

            const sanitizedEmail = sanitizeEmail(email);

            const [otpRows] = await pool.query('SELECT * FROM otps WHERE email = ?', [sanitizedEmail]);
            if (otpRows.length === 0) {
                return res.status(404).json({ error: 'No pending registration found for this email' });
            }
            const pending = otpRows[0];

            if (Date.now() > pending.expires) {
                await pool.query('DELETE FROM otps WHERE email = ?', [sanitizedEmail]);
                return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
            }

            if (otp !== pending.otp) {
                return res.status(400).json({ error: 'Invalid OTP' });
            }

            // Create the user with defaults
            await pool.query(
                'INSERT INTO users (email, userId, username, hashedPassword, profileImage, whatsappNo, accountNo, accountName, accountBank, verifiedPoints, unVerifiedPoints, marketPoints, record, pending, role, badgeType) VALUES (?, ?, ?, ?, null, 0, null, null, null, 20, 0, 0, 0, 0, "user", "Verified")',
                [sanitizedEmail, pending.userId, pending.username, pending.hashedPassword]
            );

            // Clean up OTP
            await pool.query('DELETE FROM otps WHERE email = ?', [sanitizedEmail]);

            const [newUserRows] = await pool.query('SELECT * FROM users WHERE email = ?', [sanitizedEmail]);
            const newUser = newUserRows[0];

            // Generate token
            const token = jwt.sign(
                { email: sanitizedEmail, userId: newUser.userId },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );

            // Optional: Discord notification
            if (process.env.DISCORD_WEBHOOK_URL) {
                try {
                    await axios.post(process.env.DISCORD_WEBHOOK_URL, {
                        content: `New user registered: ${sanitizedEmail}`
                    });
                } catch (discordError) {
                    console.error('Discord notification failed:', discordError.message);
                }
            }

            const { hashedPassword, ...safeUser } = newUser;
            res.status(200).json({ success: true, token, user: safeUser });
        } catch (error) {
            console.error('OTP verification error:', error.message);
            res.status(500).json({ error: 'Failed to verify OTP' });
        }
    });
    app.post('/api/auth/resend-otp', async (req, res) => {
        const { email } = req.body;
        try {
            if (!email) {
                return res.status(400).json({ message: 'Email is required' });
            }

            const sanitizedEmail = sanitizeEmail(email);

            const [otpRows] = await pool.query('SELECT * FROM otps WHERE email = ?', [sanitizedEmail]);
            if (otpRows.length === 0) {
                return res.status(404).json({ error: 'No pending registration found for this email' });
            }
            const pending = otpRows[0];

            if (Date.now() > pending.expires) {
                await pool.query('DELETE FROM otps WHERE email = ?', [sanitizedEmail]);
                return res.status(400).json({ error: 'OTP has expired. Please start the signup process again.' });
            }

            // Resend the same OTP
            const mailOptions = {
                from: process.env.SMTP_FROM,
                to: sanitizedEmail,
                subject: 'Your OTP for Registration',
                text: `Your one-time password (OTP) is ${pending.otp}. It expires in 10 minutes. Please use it to complete your registration.`
            };

            await transporter.sendMail(mailOptions);

            // Optional: Discord notification
            if (process.env.DISCORD_WEBHOOK_URL) {
                try {
                    await axios.post(process.env.DISCORD_WEBHOOK_URL, {
                        content: `OTP resent for user registration: ${sanitizedEmail}`
                    });
                } catch (discordError) {
                    console.error('Discord notification failed:', discordError.message);
                }
            }

            res.status(200).json({ success: true, message: 'OTP resent to your email.' });
        } catch (error) {
            console.error('Resend OTP error:', error.message);
            res.status(500).json({ error: 'Failed to resend OTP' });
        }
    });

    // POST /api/users/save-push-token - Save Expo push token for user (authenticated)
    app.post('/api/users/save-push-token', async (req, res) => {
        const { pushToken, userEmail } = req.body;

        console.log('Received pushToken:', pushToken);
        console.log('Received userEmail:', userEmail);

        if (!pushToken || typeof pushToken !== 'string') {
            return res.status(400).json({ error: 'Valid pushToken is required' });
        }

        const email = userEmail || req.user.email;

        try {
            const connection = await pool.getConnection();
            try {
                // First, try to find existing token
                const [existing] = await connection.query(
                    'SELECT id FROM user_push_tokens WHERE user_email = ? AND push_token = ?',
                    [email, pushToken]
                );

                if (existing.length === 0) {
                    // Insert new token
                    await connection.query(
                        'INSERT INTO user_push_tokens (user_email, push_token) VALUES (?, ?)',
                        [email, pushToken]
                    );
                }

                res.json({ success: true, message: 'Push token saved' });
            } finally {
                connection.release();
            }
        } catch (error) {
            console.error('Save push token error:', error.message);
            console.error('Email:', email);
            console.error('Push Token length:', pushToken?.length);
            console.error('Push Token preview:', pushToken?.substring(0, 50));
            res.status(500).json({ error: 'Failed to save push token', details: error.message });
        }
    });

    // Test route - Send push notification to user by email (PUBLIC - remove auth for testing)
    app.get('/api/test/send-notification/:email', async (req, res) => {
        const { email } = req.params;

        if (!email) {
            return res.status(400).json({ error: 'Email parameter is required' });
        }

        try {
            const result = await sendToUser(
                email,
                'info • levyni',
                'This is a test push notification for you!',
                {
                    type: 'test',
                    timestamp: new Date().toISOString(),
                    message: 'Hello from the server!'
                }
            );

            if (result.success) {
                res.json({
                    success: true,
                    message: `Notification sent to ${email}`,
                    result
                });
            } else {
                res.status(404).json({
                    success: false,
                    message: result.message || 'Failed to send notification',
                    error: result.error
                });
            }
        } catch (error) {
            console.error('Test notification error:', error.message);
            res.status(500).json({
                error: 'Failed to send test notification',
                details: error.message
            });
        }
    });

    // PATCH /api/users/:email - Update user profile data
    app.patch('/api/users/:email', async (req, res) => {
        const { email } = req.params;
        const {
            username,
            whatsappNo,
            accountNo,
            accountName,
            accountBank
        } = req.body;

        try {
            const sanitizedEmail = sanitizeEmail(decodeURIComponent(email));

            // Check if user exists
            const [userRows] = await pool.query('SELECT * FROM users WHERE email = ?', [sanitizedEmail]);
            if (userRows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            // Build dynamic update query based on provided fields
            const updates = [];
            const values = [];

            if (username !== undefined) {
                updates.push('username = ?');
                values.push(username);
            }
            if (whatsappNo !== undefined) {
                updates.push('whatsappNo = ?');
                values.push(whatsappNo);
            }
            if (accountNo !== undefined) {
                updates.push('accountNo = ?');
                values.push(accountNo);
            }
            if (accountName !== undefined) {
                updates.push('accountName = ?');
                values.push(accountName);
            }
            if (accountBank !== undefined) {
                updates.push('accountBank = ?');
                values.push(accountBank);
            }

            // If no fields to update
            if (updates.length === 0) {
                return res.status(400).json({ error: 'No fields to update' });
            }

            // Add email to values for WHERE clause
            values.push(sanitizedEmail);

            // Execute update
            await pool.query(
                `UPDATE users SET ${updates.join(', ')} WHERE email = ?`,
                values
            );

            // Return updated user data
            const [updatedUser] = await pool.query(
                'SELECT email, userId, username, profileImage, whatsappNo, accountNo, accountName, accountBank, verifiedPoints, unVerifiedPoints, marketPoints, record, pending, role, badgeType FROM users WHERE email = ?',
                [sanitizedEmail]
            );

            res.status(200).json({
                success: true,
                message: 'User profile updated successfully',
                user: updatedUser[0]
            });

        } catch (error) {
            console.error('User update error:', error.message);
            res.status(500).json({ error: 'Failed to update user profile' });
        }
    });

    // PATCH /api/users/:email/password - Change user password
    app.patch('/api/users/:email/password', async (req, res) => {
        const { email } = req.params;
        const { currentPassword, newPassword } = req.body;

        try {
            if (!currentPassword || !newPassword) {
                return res.status(400).json({ error: 'Current password and new password are required' });
            }

            if (newPassword.length < 6) {
                return res.status(400).json({ error: 'New password must be at least 6 characters long' });
            }

            const sanitizedEmail = sanitizeEmail(decodeURIComponent(email));

            // Get user with password
            const [userRows] = await pool.query('SELECT * FROM users WHERE email = ?', [sanitizedEmail]);
            if (userRows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            const user = userRows[0];

            // Verify current password
            const match = await bcrypt.compare(currentPassword, user.hashedPassword);
            if (!match) {
                return res.status(401).json({ error: 'Current password is incorrect' });
            }

            // Hash new password
            const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

            // Update password
            await pool.query(
                'UPDATE users SET hashedPassword = ? WHERE email = ?',
                [hashedPassword, sanitizedEmail]
            );

            res.status(200).json({
                success: true,
                message: 'Password changed successfully'
            });

        } catch (error) {
            console.error('Password change error:', error.message);
            res.status(500).json({ error: 'Failed to change password' });
        }
    });


    app.patch('/api/users/:email/profile_avatar', async (req, res) => {
        const { uri } = req.body;
        const { email } = req.params;
        try {
            const sanitizedEmail = sanitizeEmail(decodeURIComponent(email));

            const [userRows] = await pool.query('SELECT * FROM users WHERE email = ?', [sanitizedEmail]);
            if (userRows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            await pool.query('UPDATE users SET profileImage = ? WHERE email = ?', [uri, sanitizedEmail]);

            res.status(200).json({ message: 'Update Successful!' })

        } catch (error) {
            console.log('Avatar error: ', error)
            res.status(500).json({ error: 'Failed to update avatar' });
        }
    })

    // GET single user by email (public / no auth)
    app.get('/api/users/:email', async (req, res) => {
        const { email } = req.params;

        try {
            const sanitizedEmail = sanitizeEmail(decodeURIComponent(email));
            const [userRows] = await pool.query('SELECT * FROM users WHERE email = ?', [sanitizedEmail]);

            if (userRows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            const { hashedPassword, ...safeUser } = userRows[0];

            // Send notification in background (don't block the response)
            sendToUser(sanitizedEmail, 'Status check', 'You\'re verified on Levyni co')
                .then(result => {
                    console.log('Notification sent to:', sanitizedEmail, result);
                })
                .catch(error => {
                    console.error('Failed to send notification to:', sanitizedEmail, error);
                });

            res.json(safeUser);
        } catch (error) {
            console.error('Get user by email error:', error.message);
            res.status(500).json({ error: 'Failed to retrieve user' });
        }
    });

    // GET all users (public / no auth)
    app.get('/api/users', async (req, res) => {
        try {
            const [users] = await pool.query('SELECT email, userId, username, profileImage, whatsappNo, accountNo, accountName, accountBank, verifiedPoints, unVerifiedPoints, marketPoints, record, pending, role, badgeType FROM users');

            res.json(users);
        } catch (error) {
            console.error('Get all users error:', error.message);
            res.status(500).json({ error: 'Failed to retrieve users' });
        }
    });

    // ============================================================
    // ACCOUNT DELETION API
    // Add these routes inside the main async IIFE in server.js,
    // alongside the other app.post / app.get routes.
    // ============================================================

    // --- STEP 1: Request account deletion ---
    // Sends a 6-digit OTP to the user's email to verify identity.
    // POST /api/auth/delete/request
    // Body: { email, password }
    app.post('/api/auth/delete/request', async (req, res) => {
        const { email, password } = req.body;

        try {
            if (!email || !password) {
                return res.status(400).json({ error: 'Email and password are required' });
            }

            const sanitizedEmail = sanitizeEmail(email);

            // Verify user exists
            const [userRows] = await pool.query('SELECT * FROM users WHERE email = ?', [sanitizedEmail]);
            if (userRows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            const user = userRows[0];

            // Verify password before proceeding
            if (!user.hashedPassword) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            const match = await bcrypt.compare(password, user.hashedPassword);
            if (!match) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            // Generate a 6-digit OTP
            const otp = Math.floor(100000 + Math.random() * 900000).toString();
            const expires = Date.now() + 15 * 60 * 1000; // 15 minutes

            // Store OTP in deletion_otps table (or reuse otps table with a type flag)
            // Using a separate key prefix to avoid conflict with registration OTPs
            await pool.query(
                `INSERT INTO otps (email, otp, expires, username, hashedPassword, userId)
             VALUES (?, ?, ?, 'DELETE_ACCOUNT', '', ?)
             ON DUPLICATE KEY UPDATE otp = ?, expires = ?`,
                [sanitizedEmail, otp, expires, user.userId, otp, expires]
            );

            // Send OTP email
            const mailOptions = {
                from: process.env.SMTP_FROM,
                to: sanitizedEmail,
                subject: 'Account Deletion Request - OTP Verification',
                text: `You requested to delete your account.\n\nYour verification code is: ${otp}\n\nThis code expires in 15 minutes.\n\nIf you did not request this, please ignore this email and your account will remain active.\n\nNote: Before deleting, you can download a report of all your data at:\nGET /api/auth/delete/report?email=${encodeURIComponent(sanitizedEmail)}`
            };

            await transporter.sendMail(mailOptions);

            res.status(200).json({
                success: true,
                message: 'A verification code has been sent to your email. Please verify to proceed with account deletion.',
                reportUrl: `/api/auth/delete/report?email=${encodeURIComponent(sanitizedEmail)}`,
                hint: 'Download your account report before confirming deletion.'
            });

        } catch (error) {
            console.error('Delete request error:', error.message);
            res.status(500).json({ error: 'Failed to initiate account deletion' });
        }
    });


    // --- STEP 2: Download account data report ---
    // User can download all their data as JSON before deleting.
    // GET /api/auth/delete/report?email=user@example.com
    app.get('/api/auth/delete/report', async (req, res) => {
        const { email } = req.query;

        try {
            if (!email) {
                return res.status(400).json({ error: 'Email is required' });
            }

            const sanitizedEmail = sanitizeEmail(decodeURIComponent(email));

            // Verify user exists
            const [userRows] = await pool.query(
                'SELECT userId, email, username, verifiedPoints, unVerifiedPoints, marketPoints, record, pending FROM users WHERE email = ?',
                [sanitizedEmail]
            );
            if (userRows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            // Gather all user data across tables
            const [answers] = await pool.query(
                'SELECT taskId, type, response, reward, attachment, reviewed, status FROM answers WHERE email = ?',
                [sanitizedEmail]
            );

            const [serviceRequests] = await pool.query(
                'SELECT serviceId, serviceName, price, status, createdAt, validatedAt FROM service_requests WHERE email = ?',
                [sanitizedEmail]
            );

            const [events] = await pool.query(
                'SELECT name, `desc`, type, url, reviewed, submittedAt, image FROM events WHERE submittedBy = ?',
                [sanitizedEmail]
            );

            // Build the report object
            const report = {
                exportedAt: new Date().toISOString(),
                notice: 'This is a full export of your account data. Keep this file safe.',
                account: userRows[0],
                taskAnswers: answers,
                serviceRequests: serviceRequests,
                submittedEvents: events,
                summary: {
                    totalAnswers: answers.length,
                    totalServiceRequests: serviceRequests.length,
                    totalEventsSubmitted: events.length,
                    verifiedPoints: userRows[0].verifiedPoints,
                    unverifiedPoints: userRows[0].unVerifiedPoints
                }
            };

            // Send as a downloadable JSON file
            res.setHeader('Content-Type', 'application/json');
            res.setHeader(
                'Content-Disposition',
                `attachment; filename="account-report-${sanitizedEmail.replace('@', '_at_')}-${Date.now()}.json"`
            );
            res.status(200).send(JSON.stringify(report, null, 2));

        } catch (error) {
            console.error('Report generation error:', error.message);
            res.status(500).json({ error: 'Failed to generate account report' });
        }
    });


    // --- STEP 3: Confirm and permanently delete account ---
    // Verifies the OTP then deletes all user data.
    // POST /api/auth/delete/confirm
    // Body: { email, otp }
    app.post('/api/auth/delete/confirm', async (req, res) => {
        const { email, otp } = req.body;

        try {
            if (!email || !otp) {
                return res.status(400).json({ error: 'Email and OTP are required' });
            }

            const sanitizedEmail = sanitizeEmail(email);

            // Find the pending deletion OTP
            const [otpRows] = await pool.query(
                "SELECT * FROM otps WHERE email = ? AND username = 'DELETE_ACCOUNT'",
                [sanitizedEmail]
            );

            if (otpRows.length === 0) {
                return res.status(400).json({
                    error: 'No deletion request found. Please request account deletion first.',
                    action: 'request_deletion_first'
                });
            }

            const otpRecord = otpRows[0];

            // Check expiry
            if (Date.now() > otpRecord.expires) {
                await pool.query("DELETE FROM otps WHERE email = ? AND username = 'DELETE_ACCOUNT'", [sanitizedEmail]);
                return res.status(400).json({
                    error: 'Verification code has expired. Please request a new one.',
                    action: 'otp_expired'
                });
            }

            // Check OTP match
            if (otpRecord.otp !== otp.trim()) {
                return res.status(400).json({ error: 'Invalid verification code' });
            }

            // Verify user still exists
            const [userRows] = await pool.query('SELECT * FROM users WHERE email = ?', [sanitizedEmail]);
            if (userRows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            // --- PERMANENTLY DELETE ALL USER DATA ---
            // Delete in safe order (child records first)
            await pool.query('DELETE FROM answers WHERE email = ?', [sanitizedEmail]);
            await pool.query('DELETE FROM service_requests WHERE email = ?', [sanitizedEmail]);
            await pool.query(
                'UPDATE events SET submittedBy = "[deleted]" WHERE submittedBy = ?',
                [sanitizedEmail]
            ); // Keep submitted events but anonymize them
            await pool.query("DELETE FROM otps WHERE email = ?", [sanitizedEmail]);
            await pool.query('DELETE FROM admins WHERE email = ?', [sanitizedEmail]); // Remove admin role if any
            await pool.query('DELETE FROM users WHERE email = ?', [sanitizedEmail]);

            // Send goodbye email
            try {
                await transporter.sendMail({
                    from: process.env.SMTP_FROM,
                    to: sanitizedEmail,
                    subject: 'Your account has been deleted',
                    text: `Hello,\n\nYour account (${sanitizedEmail}) has been permanently deleted as requested.\n\nAll your personal data, answers, and service requests have been removed.\n\nIf this was a mistake, please contact support immediately.\n\nThank you for using our platform.`
                });
            } catch (mailErr) {
                console.error('Goodbye email failed:', mailErr.message);
                // Don't block deletion if email fails
            }

            res.status(200).json({
                success: true,
                message: 'Your account has been permanently deleted. All your data has been removed.'
            });

        } catch (error) {
            console.error('Account deletion error:', error.message);
            res.status(500).json({ error: 'Failed to delete account' });
        }
    });

    app.get('/delete-account', (req, res) => {
        res.send(`
      <html>
        <body style="font-family:sans-serif;max-width:400px;margin:80px auto;text-align:center">
          <h2>Delete Your Account</h2>
          <p>To permanently delete your account and all your data, 
             open the app and go to <strong>Profile → Delete Account</strong>.</p>
          <p>Or email us at <a href="mailto:thelivingconnect@gmail.com">support@levyni.com</a></p>
        </body>
      </html>
    `);
    });

    
    const sso = createSSORouter(pool, transporter);
app.use('/auth',  sso.auth);    // unified, refresh, logout, me
app.use('/oauth', sso.oauth);   // authorize, token, introspect, userinfo, revoke, clients

    

    // Global error handler
    app.use((err, req, res, next) => {
        console.error('Global error:', err.message);
        res.status(500).json({ error: 'An unexpected error occurred. Please try again.' });
    });

    const PORT = process.env.PORT || 5000;

    // Add this endpoint after other routes, before app.listen

    app.get('/api/migrate/json-to-sql', async (req, res) => {
        try {
            const fsPromises = require('fs/promises');
            const mysql = require('mysql2'); // For escaping values

            // Helper to escape values
            const escape = mysql.escape;

            const queries = [];

            // settings - admin_key from admins.json
            const adminsData = JSON.parse(await fsPromises.readFile(ADMINS_FILE, 'utf8'));
            if (adminsData.key) {
                queries.push(`INSERT INTO settings (name, value) VALUES ('admin_key', ${escape(adminsData.key)});`);
            }

            // admins
            for (const [email, admin] of Object.entries(adminsData.admins || {})) {
                const id = admin.id || 'NULL';
                const rank = admin.rank || 'NULL';
                const userId = admin.userId || 'NULL';
                const hashedPassword = admin.hashedPassword || 'NULL';
                queries.push(`INSERT INTO admins (id, email, rank, userId, hashedPassword) VALUES (${escape(id)}, ${escape(email)}, ${escape(rank)}, ${escape(userId)}, ${escape(hashedPassword)});`);
            }

            // users
            const usersData = JSON.parse(await fsPromises.readFile(USERS_FILE, 'utf8'));
            for (const [email, user] of Object.entries(usersData)) {
                const userId = user.userId || 'NULL';
                const username = user.username || 'NULL';
                const hashedPassword = user.hashedPassword || 'NULL';
                const profileImage = user.profileImage || 'NULL';
                const whatsappNo = user.whatsappNo || 0;
                const accountNo = user.accountNo || 'NULL';
                const accountName = user.accountName || 'NULL';
                const accountBank = user.accountBank || 'NULL';
                const verifiedPoints = user.verifiedPoints || 0;
                const unVerifiedPoints = user.unVerifiedPoints || 0;
                const marketPoints = user.marketPoints || 0;
                const record = user.record || 0;
                const pending = user.pending || 0;
                const role = user.role || 'user';
                const badgeType = user.badgeType || 'member';
                queries.push(`INSERT INTO users (email, userId, username, hashedPassword, profileImage, whatsappNo, accountNo, accountName, accountBank, verifiedPoints, unVerifiedPoints, marketPoints, record, pending, role, badgeType) VALUES (${escape(email)}, ${escape(userId)}, ${escape(username)}, ${escape(hashedPassword)}, ${escape(profileImage)}, ${escape(whatsappNo)}, ${escape(accountNo)}, ${escape(accountName)}, ${escape(accountBank)}, ${escape(verifiedPoints)}, ${escape(unVerifiedPoints)}, ${escape(marketPoints)}, ${escape(record)}, ${escape(pending)}, ${escape(role)}, ${escape(badgeType)});`);
            }

            // services
            const servicesData = JSON.parse(await fsPromises.readFile(SERVICES_FILE, 'utf8'));
            for (const service of servicesData) {
                const id = service.id || 'NULL';
                const name = service.name || 'NULL';
                const price = service.price || 0;
                const desc = service.desc || 'NULL';
                const type = service.type || 'NULL';
                const image = service.image || 'NULL';
                queries.push(`INSERT INTO services (id, name, price, \`desc\`, type, image) VALUES (${escape(id)}, ${escape(name)}, ${escape(price)}, ${escape(desc)}, ${escape(type)}, ${escape(image)});`);
            }

            // events
            const eventsData = JSON.parse(await fsPromises.readFile(EVENTS_FILE, 'utf8'));
            for (const event of eventsData) {
                const id = event.id || 'NULL';
                const name = event.name || 'NULL';
                const desc = event.desc || 'NULL';
                const type = event.type || 'NULL';
                const url = event.url || 'NULL';
                const reviewed = event.reviewed ? 1 : 0;
                const submittedBy = event.submittedBy || 'NULL';
                const submittedAt = event.submittedAt ? `STR_TO_DATE(${escape(event.submittedAt)}, '%Y-%m-%dT%H:%i:%s.%fZ')` : 'NULL';
                const image = event.image || 'NULL';
                const approvedBy = event.approvedBy || 'NULL';
                const approvedAt = event.approvedAt ? `STR_TO_DATE(${escape(event.approvedAt)}, '%Y-%m-%dT%H:%i:%s.%fZ')` : 'NULL';
                queries.push(`INSERT INTO events (id, name, \`desc\`, type, url, reviewed, submittedBy, submittedAt, image, approvedBy, approvedAt) VALUES (${escape(id)}, ${escape(name)}, ${escape(desc)}, ${escape(type)}, ${escape(url)}, ${reviewed}, ${escape(submittedBy)}, ${submittedAt}, ${escape(image)}, ${escape(approvedBy)}, ${approvedAt});`);
            }

            // tasks
            const tasksData = JSON.parse(await fsPromises.readFile(TASKS_FILE, 'utf8'));
            for (const task of tasksData) {
                const id = task.id || 'NULL';
                const desc = task.desc || 'NULL';
                const type = task.type || 'NULL';
                const shortResponse = task.shortResponse || 'NULL';
                const reward = task.reward || 0;
                const image = task.image || 'NULL';
                queries.push(`INSERT INTO tasks (id, \`desc\`, type, shortResponse, reward, image) VALUES (${escape(id)}, ${escape(desc)}, ${escape(type)}, ${escape(shortResponse)}, ${escape(reward)}, ${escape(image)});`);
            }

            // service_requests (requests.json)
            const requestsData = JSON.parse(await fsPromises.readFile(REQUESTS_FILE, 'utf8'));
            for (const [email, userRequests] of Object.entries(requestsData)) {
                for (const request of userRequests) {
                    const id = request.id || 'NULL';
                    const serviceId = request.serviceId || 'NULL';
                    const serviceName = request.serviceName || 'NULL';
                    const price = request.price || 0;
                    const status = request.status || 'pending';
                    const createdAt = request.createdAt ? `STR_TO_DATE(${escape(request.createdAt)}, '%Y-%m-%dT%H:%i:%s.%fZ')` : 'NULL';
                    const validatedAt = request.validatedAt ? `STR_TO_DATE(${escape(request.validatedAt)}, '%Y-%m-%dT%H:%i:%s.%fZ')` : 'NULL';
                    const validatedBy = request.validatedBy || 'NULL';
                    queries.push(`INSERT INTO service_requests (id, email, serviceId, serviceName, price, status, createdAt, validatedAt, validatedBy) VALUES (${escape(id)}, ${escape(email)}, ${escape(serviceId)}, ${escape(serviceName)}, ${escape(price)}, ${escape(status)}, ${createdAt}, ${validatedAt}, ${escape(validatedBy)});`);
                }
            }

            // answers
            const answersData = JSON.parse(await fsPromises.readFile(ANSWERS_FILE, 'utf8'));
            for (const [email, userAnswers] of Object.entries(answersData)) {
                for (const answer of userAnswers) {
                    const id = answer.id || 'NULL';
                    const taskId = answer.taskId || 'NULL';
                    const type = answer.type || 'NULL';
                    const response = answer.response || 'NULL';
                    const reward = answer.reward || 0;
                    const attachment = answer.attachment || 'NULL';
                    const reviewed = answer.reviewed ? 1 : 0;
                    const status = answer.status || 'NULL';
                    queries.push(`INSERT INTO answers (id, email, taskId, type, response, reward, attachment, reviewed, status) VALUES (${escape(id)}, ${escape(email)}, ${escape(taskId)}, ${escape(type)}, ${escape(response)}, ${escape(reward)}, ${escape(attachment)}, ${reviewed}, ${escape(status)});`);
                }
            }

            // otps
            const otpsData = JSON.parse(await fsPromises.readFile(OTPS_FILE, 'utf8'));
            for (const [email, otpData] of Object.entries(otpsData)) {
                const otp = otpData.otp || 'NULL';
                const expires = otpData.expires || 0;
                const username = otpData.username || 'NULL';
                const hashedPassword = otpData.hashedPassword || 'NULL';
                const userId = otpData.userId || 'NULL';
                queries.push(`INSERT INTO otps (email, otp, expires, username, hashedPassword, userId) VALUES (${escape(email)}, ${escape(otp)}, ${escape(expires)}, ${escape(username)}, ${escape(hashedPassword)}, ${escape(userId)});`);
            }

            // data.json for appConfig
            const dataData = JSON.parse(await fsPromises.readFile(DATA_FILE, 'utf8'));
            const appConfig = dataData.appConfig || {};
            for (const [key, value] of Object.entries(appConfig)) {
                const name = `app_${key.toLowerCase().replace(/([a-z])([A-Z])/g, '$1_$2')}`;
                let val = value;
                if (typeof val === 'boolean') val = val ? 'true' : 'false';
                if (val === null) continue;
                queries.push(`INSERT INTO settings (name, value) VALUES (${escape(name)}, ${escape(val)});`);
            }

            res.json({ queries });
        } catch (error) {
            console.error('Migration query generation error:', error.message);
            res.status(500).json({ error: 'Failed to generate migration queries' });
        }
    });

    app.get('/get_gauth_link', (req, res) => {
        const oAuth2Client = new google.auth.OAuth2(
            process.env.CLIENT_ID,
            process.env.CLIENT_SECRET,
            "urn:ietf:wg:oauth:2.0:oob"
        );

        const authUrl = oAuth2Client.generateAuthUrl({
            access_type: "offline",
            prompt: "consent",
            scope: SCOPES,
        });

        res.json({ url: authUrl });
    });


    app.post('/set_gauth_code', async (req, res) => {
        const { code } = req.body;
        if (!code) {
            return res.status(400).json({ error: 'Code required' });
        }

        try {
            const oAuth2Client = new google.auth.OAuth2(
                process.env.CLIENT_ID,
                process.env.CLIENT_SECRET,
                "urn:ietf:wg:oauth:2.0:oob"
            );

            const { tokens } = await oAuth2Client.getToken(code.trim());
            const fs = require('fs');
            fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokens));

            // Refresh global auth
            auth = oAuth2Client;
            auth.setCredentials(tokens);
            drive = google.drive({ version: 'v3', auth });

            res.json({ success: true, message: 'Token set successfully' });
        } catch (error) {
            console.error('Set token error:', error.message);
            res.status(500).json({ error: 'Failed to set token' });
        }
    });

    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
})();


async function getOAuth2Client() {
    const oAuth2Client = new google.auth.OAuth2(
        process.env.CLIENT_ID,
        process.env.CLIENT_SECRET,
        "urn:ietf:wg:oauth:2.0:oob"
    );

    // Try environment variable first
    if (process.env.GOOGLE_TOKEN) {
        try {
            const tokens = JSON.parse(process.env.GOOGLE_TOKEN);
            oAuth2Client.setCredentials(tokens);

            // Set up automatic token refresh
            oAuth2Client.on('tokens', (tokens) => {
                if (tokens.refresh_token) {
                    // Update the stored token
                    const existingTokens = JSON.parse(process.env.GOOGLE_TOKEN || '{}');
                    const updatedTokens = { ...existingTokens, ...tokens };

                    // Save to file
                    const fs = require('fs');
                    fs.writeFileSync(TOKEN_PATH, JSON.stringify(updatedTokens, null, 2));
                    console.log('Token refreshed and saved');
                }
            });

            return oAuth2Client;
        } catch (e) {
            console.error('Invalid GOOGLE_TOKEN env:', e.message);
        }
    }

    
    // Try token file
    if (fs.existsSync(TOKEN_PATH)) {
        try {
            const tokens = JSON.parse(fs.readFileSync(TOKEN_PATH, 'utf8'));
            oAuth2Client.setCredentials(tokens);

            // Set up automatic token refresh
            oAuth2Client.on('tokens', (tokens) => {
                if (tokens.refresh_token) {
                    const existingTokens = JSON.parse(fs.readFileSync(TOKEN_PATH, 'utf8'));
                    const updatedTokens = { ...existingTokens, ...tokens };
                    fs.writeFileSync(TOKEN_PATH, JSON.stringify(updatedTokens, null, 2));
                    console.log('Token refreshed and saved to file');
                }
            });

            return oAuth2Client;
        } catch (e) {
            console.error('Error reading token file:', e.message);
        }
    }

    console.log('No Google token found. Drive features disabled until configured.');
    return oAuth2Client;
}