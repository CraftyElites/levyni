const path = require('path');
const fs = require('fs').promises;
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const DUMB_LIST_FILE = path.join(__dirname, 'dumb_list.json');
const ROBOT_USERS_FILE = path.join(__dirname, 'robot_users.json');
const SALT_ROUNDS = 10;
const SYNC_INTERVAL = 30000; // Check every 30 seconds

/**
 * Generate a secure random password
  */
function generateSecurePassword() {
    const length = 16;
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let password = '';
    const randomBytes = crypto.randomBytes(length);

    for (let i = 0; i < length; i++) {
        password += charset[randomBytes[i] % charset.length];
    }

    return password;
}

/**
 * Generate user ID
  */
function generateUserId() {
    const year = new Date().getFullYear();
    const randomBytes = crypto.randomBytes(5);
    const randomPart = randomBytes.toString('hex').toUpperCase();
    return `USR-${year}-${randomPart}`;
}

/**
 * Sanitize email
  */
function sanitizeEmail(email) {
    if (!email || typeof email !== 'string') {
        throw new Error('Invalid email');
    }
    return email.trim().toLowerCase();
}

/**
 * Load dumb list with emails and names
  * Expected format: { "email@example.com": { "name": "Wisdom" }, ... }
   */
async function loadDumbList() {
    try {
        const data = await fs.readFile(DUMB_LIST_FILE, 'utf8');
        const parsed = JSON.parse(data);

        // Convert object to array of {email, name}
        const users = [];
        for (const [email, userData] of Object.entries(parsed)) {
            if (userData && userData.name) {
                users.push({
                    email: sanitizeEmail(email),
                    name: userData.name
                });
            } else {
                console.warn(`Invalid entry for ${email}: missing name`);
            }
        }

        return users;
    } catch (error) {
        if (error.code === 'ENOENT') {
            // Create empty file if it doesn't exist
            const template = {
                "example@example.com": {
                    "name": "Example User"
                }
            };
            await fs.writeFile(DUMB_LIST_FILE, JSON.stringify(template, null, 2));
            console.log('Created empty dumb_list.json template');
            return [];
        }
        console.error('Error loading dumb_list.json:', error.message);
        return [];
    }
}

/**
 * Load existing robot users from JSON backup
  */
async function loadRobotUsers() {
    try {
        const data = await fs.readFile(ROBOT_USERS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') {
            return {};
        }
        console.error('Error loading robot_users.json:', error.message);
        return {};
    }
}

/**
 * Save robot users to JSON backup
  */
async function saveRobotUsers(robotUsers) {
    try {
        await fs.writeFile(ROBOT_USERS_FILE, JSON.stringify(robotUsers, null, 2));
        console.log(`Robot users backup updated: ${Object.keys(robotUsers).length} users`);
    } catch (error) {
        console.error('Error saving robot_users.json:', error.message);
    }
}

/**
 * Create a robot user in the database
  */
async function createRobotUser(pool, email, name) {
    try {
        const sanitizedEmail = sanitizeEmail(email);

        // Check if user already exists
        const [existing] = await pool.query('SELECT * FROM users WHERE email = ?', [sanitizedEmail]);
        if (existing.length > 0) {
            console.log(`Robot user already exists: ${sanitizedEmail}`);
            return existing[0];
        }

        // Generate credentials
        const userId = generateUserId();
        const password = generateSecurePassword();
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        const username = name || `robot_${sanitizedEmail.split('@')[0]}`;

        // Create user in database
        await pool.query(
            `INSERT INTO users (
                email, userId, username, hashedPassword, 
                profileImage, whatsappNo, accountNo, accountName, accountBank,
                verifiedPoints, unVerifiedPoints, marketPoints, 
                record, pending, role, badgeType
             ) VALUES (?, ?, ?, ?, NULL, 0, NULL, NULL, NULL, 20, 0, 0, 0, 0, 'user', 'verified')`,
            [sanitizedEmail, userId, username, hashedPassword]
        );

        console.log(`✓ Created robot user: ${sanitizedEmail} (${username})`);

        return {
            email: sanitizedEmail,
            userId,
            username,
            password, // Store plain password in JSON backup only
            hashedPassword,
            createdAt: new Date().toISOString(),
            badgeType: 'verified',
            role: 'user',
            verifiedPoints: 20,
            unVerifiedPoints: 0,
            marketPoints: 0
        };
    } catch (error) {
        console.error(`Error creating robot user ${email}:`, error.message);
        return null;
    }
}

/**
 * Delete a robot user from the database
  */
async function deleteRobotUser(pool, email) {
    try {
        const sanitizedEmail = sanitizeEmail(email);

        const [result] = await pool.query('DELETE FROM users WHERE email = ?', [sanitizedEmail]);

        if (result.affectedRows > 0) {
            console.log(`✓ Deleted robot user: ${sanitizedEmail}`);
            return true;
        } else {
            console.log(`Robot user not found in database: ${sanitizedEmail}`);
            return false;
        }
    } catch (error) {
        console.error(`Error deleting robot user ${email}:`, error.message);
        return false;
    }
}

/**
 * Sync robot users with database
  */
async function syncRobotUsers(pool) {
    try {
        console.log('--- Robot Users Sync Started ---');

        // Load current state
        const dumbListUsers = await loadDumbList(); // Now returns [{email, name}, ...]
        const robotUsers = await loadRobotUsers();

        // Create maps for easier lookup
        const dumbListMap = new Map();
        dumbListUsers.forEach(user => {
            dumbListMap.set(user.email, user.name);
        });

        const dumbListEmails = new Set(dumbListMap.keys());
        const robotUsersEmails = new Set(Object.keys(robotUsers));

        // Find emails to add (in dumb_list but not in robot_users)
        const emailsToAdd = [...dumbListEmails].filter(email => !robotUsersEmails.has(email));

        // Find emails to remove (in robot_users but not in dumb_list)
        const emailsToRemove = [...robotUsersEmails].filter(email => !dumbListEmails.has(email));

        console.log(`Emails to add: ${emailsToAdd.length}`);
        console.log(`Emails to remove: ${emailsToRemove.length}`);

        // Create new users
        for (const email of emailsToAdd) {
            const name = dumbListMap.get(email);
            const user = await createRobotUser(pool, email, name);
            if (user) {
                robotUsers[email] = user;
            }
        }

        // Delete removed users
        for (const email of emailsToRemove) {
            const deleted = await deleteRobotUser(pool, email);
            if (deleted) {
                delete robotUsers[email];
            }
        }

        // Save updated robot users
        await saveRobotUsers(robotUsers);

        console.log('--- Robot Users Sync Completed ---');
        console.log(`Total robot users: ${Object.keys(robotUsers).length}\n`);

    } catch (error) {
        console.error('Error during robot users sync:', error.message);
    }
}

/**
 * Initialize and start the robot users manager
  */
async function initRobotUsersManager(pool) {
    console.log('🤖 Robot Users Manager Starting...');

    // Initial sync
    await syncRobotUsers(pool);

    // Set up periodic sync
    setInterval(() => {
        syncRobotUsers(pool);
    }, SYNC_INTERVAL);

    console.log(`🤖 Robot Users Manager Running (checking every ${SYNC_INTERVAL / 1000}s)\n`);
}

module.exports = { initRobotUsersManager, syncRobotUsers };