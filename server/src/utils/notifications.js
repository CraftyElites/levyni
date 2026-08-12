const { Expo } = require('expo-server-sdk');
const mysql = require('mysql2/promise');

let expo = new Expo();

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

async function initNotifications() {
    try {
        await pool.query(`
      CREATE TABLE IF NOT EXISTS user_push_tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_email VARCHAR(255) NOT NULL,
        push_token VARCHAR(500) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY unique_user_token (user_email, push_token)
      );
    `);
        console.log('user_push_tokens table created or already exists');
    } catch (error) {
        console.error('Error creating user_push_tokens table:', error.message);
    }
}

// Send push notifications to an array of tokens
async function sendPushNotifications(tokens, title, body, data = {}) {
    const messages = [];
    for (let pushToken of tokens) {
        if (!Expo.isExpoPushToken(pushToken)) {
            console.error(`Invalid Expo push token: ${pushToken}`);
            continue;
        }
        messages.push({
            to: pushToken,
            sound: 'default',
            title,
            body,
            data,
        });
    }

    const chunks = expo.chunkPushNotifications(messages);
    const tickets = [];
    for (let chunk of chunks) {
        try {
            const ticketChunk = await expo.sendPushNotificationsAsync(chunk);
            tickets.push(...ticketChunk);
            // TODO: Handle errors in ticketChunk if needed (e.g., invalid tokens)
        } catch (error) {
            console.error('Error sending push chunk:', error.message);
        }
    }

    // Optionally handle receipts (e.g., remove invalid tokens)
    // For now, skipping for simplicity; add later if needed.
    return tickets;
}

// Send to a specific user by email (fetches all their tokens)
async function sendToUser(email, title, body, data = {}) {
    try {
        const [rows] = await pool.query('SELECT push_token FROM user_push_tokens WHERE user_email = ?', [email]);
        const tokens = rows.map(r => r.push_token);
        if (tokens.length === 0) {
            console.log(`No push tokens found for user: ${email}`);
            return { success: false, message: 'No tokens found' };
        }
        await sendPushNotifications(tokens, title, body, data);
        return { success: true };
    } catch (error) {
        console.error(`Error sending to user ${email}:`, error.message);
        return { success: false, error: error.message };
    }
}

module.exports = { initNotifications, sendToUser, sendPushNotifications };