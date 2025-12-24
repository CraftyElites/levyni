const express = require('express');
const multer = require('multer');
const cors = require('cors');
const { google } = require('googleapis');
const fs = require('fs');
const fsPromises = require('fs/promises');
const path = require('path');
const axios = require('axios');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const readline = require('readline');
require('dotenv').config();

const app = express();
const upload = multer({ dest: 'uploads/' });

app.use(cors());
app.use(express.json());
app.use('/assets', express.static(path.join(__dirname, 'assets')));

const saltRounds = 10;

const DATA_FILE = path.join(__dirname, 'data.json');
const USERS_FILE = path.join(__dirname, 'users.json');
const SERVICES_FILE = path.join(__dirname, 'services.json');
const EVENTS_FILE = path.join(__dirname, 'events.json');
const TASKS_FILE = path.join(__dirname, 'tasks.json');
const ADMINS_FILE = path.join(__dirname, 'admins.json');
const ANSWERS_FILE = path.join(__dirname, 'answers.json');
const TOKEN_PATH = path.join(__dirname, 'google-token.json');
const LOG_FILE = path.join(__dirname, 'admin-actions.log');
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

(async () => {
  try {
    auth = await getOAuth2Client();
    drive = google.drive({ version: 'v3', auth });
  } catch (e) {
    console.error('OAuth2 setup failed:', e.message);
    // Continue without crashing; uploads will fail gracefully
  }

  // Ensure data files exist asynchronously
  async function ensureFilesExist() {
    try {
      if (!fs.existsSync(DATA_FILE)) {
        await fsPromises.writeFile(DATA_FILE, JSON.stringify({}));
      }
      if (!fs.existsSync(USERS_FILE)) {
        await fsPromises.writeFile(USERS_FILE, JSON.stringify({}));
      }
      if (!fs.existsSync(SERVICES_FILE)) {
        await fsPromises.writeFile(SERVICES_FILE, JSON.stringify([]));
      }
      if (!fs.existsSync(EVENTS_FILE)) {
        await fsPromises.writeFile(EVENTS_FILE, JSON.stringify([]));
      }
      if (!fs.existsSync(TASKS_FILE)) {
        await fsPromises.writeFile(TASKS_FILE, JSON.stringify([]));
      }
      if (!fs.existsSync(ANSWERS_FILE)) {
        await fsPromises.writeFile(ANSWERS_FILE, JSON.stringify({}));
      }
      if (!fs.existsSync(ADMINS_FILE)) {
        await fsPromises.writeFile(ADMINS_FILE, JSON.stringify({
          "key": "Nets",
          "admins": {  // Improved: renamed "users" to "admins" for clarity
            "enochatenaga@gmail.com": {  // Improved: added ".com" assuming typo
              "id": 1,
              "rank": "custom",
              
            }
          }
        }));
      }
      if (!fs.existsSync(LOG_FILE)) {
        await fsPromises.writeFile(LOG_FILE, '');
      }
    } catch (error) {
      console.error('Error initializing files:', error.message);
    }
  }
  await ensureFilesExist();

  // Function to log admin actions
  function logAdminAction(action, ip, data) {
    const date = new Date().toISOString();
    const logLine = JSON.stringify({ action, date, ip, data }) + '\n';
    fs.appendFile(LOG_FILE, logLine, (err) => {
      if (err) console.error('Log write error:', err.message);
    });
  }
  const authenticateToken = (req, res, next) => {
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
  };

  //--- ADMIN ROUTES ---
  const admin = express.Router()
  app.use('/admin', admin);

  admin.get('/validate/:token', async (req, res) => {
    const { token } = req.params;
    const action = `${req.method} ${req.path}`;
    const ip = req.ip;
    const data = { token };
    logAdminAction(action, ip, data);

    if(!token) {
      res.status(401).send('Not Found');
    }
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      console.log('Token is valid:', decoded);
      const currentTime = Math.floor(Date.now() / 1000);
      if (decoded.exp < currentTime) {
        res.status(401).json({message: 'Token has Expired'});
      } else {
        res.status(209).json({message: 'Token is valid'});
      }
    } catch (error) {
      res.status(500).json({message: 'Token is Invalid'});
      console.log(error.name)
    }
  });

  admin.post('/create', async (req, res) => {
    const { id, userId, password, email, rank, adminKey } = req.body;  // Improved: added email, rank, separated adminKey from password
    const action = `${req.method} ${req.path}`;
    const ip = req.ip;
    const data = { id, userId, email, rank, adminKey }; // Exclude password for security
    logAdminAction(action, ip, data);
    
    try {
      if(!id || !userId || !password || !email || !rank || !adminKey) {
        return res.status(400).json({ error: 'Invalid data: all fields are required' });      
      }
    
      if (adminKey !== process.env.ADMIN_KEY) {
        return res.status(403).json({ message: 'Unauthorized' });
      }

      const hashedPassword = await bcrypt.hash(password, saltRounds);

      const currentAdmins = JSON.parse(await fsPromises.readFile(ADMINS_FILE, 'utf8'));

      if (currentAdmins.admins[email]) {
        return res.status(409).json({ error: 'Email already exists' });
      }

      currentAdmins.admins[email] = {
        id,
        rank,
        userId,
        hashedPassword
      };

      await fsPromises.writeFile(ADMINS_FILE, JSON.stringify(currentAdmins, null, 2));

      res.json({ message: 'Created!', data: { id, userId, email } });
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
      const currentAdmins = JSON.parse(await fsPromises.readFile(ADMINS_FILE, 'utf8'));
      const allAdmins = Object.values(currentAdmins.admins).map(({ hashedPassword, ...rest }) => rest);
      res.json(allAdmins);
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
      const currentAdmins = JSON.parse(await fsPromises.readFile(ADMINS_FILE, 'utf8'));
      const adminUser = currentAdmins.admins[email];
      if (!adminUser) {
        return res.status(404).json({ error: 'Admin not found' });
      }
      const { hashedPassword, ...rest } = adminUser;
      res.json(rest);
    } catch (error) {
      console.error('Get single admin error:', error.message);
      res.status(500).json({ error: 'Failed to retrieve admin' });
    }
  });

  admin.post('/login', async (req, res) => {
    const { email, password, adminKey} = req.body;
    const action = `${req.method} ${req.path}`;
    const ip = req.ip;
    const data = { email }; // Exclude password for security
    logAdminAction(action, ip, data);

    try {
      if (!email || !password || !adminKey) {
        return res.status(400).json({ error: 'Key and password are required' });
      }
      const currentAdmins = JSON.parse(await fsPromises.readFile(ADMINS_FILE, 'utf8'));
      const currentUsers =  JSON.parse(await fsPromises.readFile(USERS_FILE, 'utf8'));


      if (adminKey !== currentAdmins.key) {
        return res.status(403).json({error: 'No Admin Access. Invalid Key'})
      }

      const adminUserCheck = currentAdmins.admins[email];
      
      const adminUser = currentUsers[adminUserCheck.email];
      if (!adminUser || !adminUser.hashedPassword) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      const match = await bcrypt.compare(password, adminUser.hashedPassword);
      if (!match) {
        return res.status(401).json({ error: 'Invalid credentials, password mismatch' });
      }
      const token = jwt.sign(
        { email, userId: adminUser.userId, rank: adminUser.rank },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      console.log('Admin Login Success by', email)
      
      res.status(200).json({
        success: true,
        token,
        signedDate: Math.floor(Date.now() / 1000),  // current time in seconds
        duration: 3600,                             // 1 hour session
        message: "Login successful"
      });
    } catch (error) {
      console.error('Admin login error:', error.message);
      res.status(500).json({ error: 'Login failed' });
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

// GET route for admin logs with time filter
admin.get('/config/logs', async (req, res) => {
  const action = `${req.method} ${req.path}`;
  const ip = req.ip;
  const data = req.query;
  logAdminAction(action, ip, data);

  const { from } = req.query;
  try {
    const logContent = await fsPromises.readFile(LOG_FILE, 'utf8');
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
admin.use(authenticateToken, requireAdmin);

// 1. DELETE USER BY EMAIL
admin.delete('/users/:email', async (req, res) => {
  const { email } = req.params;
  const action = `DELETE_USER ${email}`;
  const ip = req.ip;
  logAdminAction(action, ip, { deletedBy: req.user.email });

  try {
    const currentUsers = JSON.parse(await fsPromises.readFile(USERS_FILE, 'utf8'));

    if (!currentUsers[email]) {
      return res.status(404).json({ error: 'User not found' });
    }

    delete currentUsers[email];
    await fsPromises.writeFile(USERS_FILE, JSON.stringify(currentUsers, null, 2));

    res.json({ success: true, message: 'User deleted successfully' });
  } catch (error) {
    console.error('Delete user error:', error.message);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// 2. CHANGE MASTER ADMIN KEY (very sensitive!)
admin.patch('/key', authenticateToken, async (req, res) => {
  const { newKey } = req.body;
  const action = 'CHANGE_ADMIN_KEY';
  const ip = req.ip;
  logAdminAction(action, ip, { changedBy: req.user.email });

  if (!newKey || typeof newKey !== 'string' || newKey.trim().length < 6) {
    return res.status(400).json({ error: 'New key must be at least 6 characters' });
  }

  try {
    const currentAdmins = JSON.parse(await fsPromises.readFile(ADMINS_FILE, 'utf8'));
    currentAdmins.key = newKey.trim();

    await fsPromises.writeFile(ADMINS_FILE, JSON.stringify(currentAdmins, null, 2));

    // Also update env if possible (optional, not persistent across restarts unless using file-based .env)
    process.env.ADMIN_KEY = newKey.trim();

    res.json({ success: true, message: 'Admin master key updated successfully' });
  } catch (error) {
    console.error('Change admin key error:', error.message);
    res.status(500).json({ error: 'Failed to update admin key' });
  }
});

// 3. SET APP UPDATE AVAILABILITY (for forcing update in app)
const APP_UPDATE_FILE = path.join(__dirname, 'app-update.json');

admin.patch('/app-update', async (req, res) => {
  const { available, version, message, force = false } = req.body;
  const action = 'SET_APP_UPDATE';
  const ip = req.ip;
  logAdminAction(action, ip, { available, version, force, changedBy: req.user.email });

  if (typeof available !== 'boolean') {
    return res.status(400).json({ error: 'available (boolean) is required' });
  }
  if (!version || !message) {
    return res.status(400).json({ error: 'version and message are required' });
  }

  const updateData = {
    available,
    version: version.trim(),
    message: message.trim(),
    force: !!force,
    updatedAt: new Date().toISOString(),
    updatedBy: req.user.email
  };

  try {
    await fsPromises.writeFile(APP_UPDATE_FILE, JSON.stringify(updateData, null, 2));
    res.json({ success: true, update: updateData });
  } catch (error) {
    console.error('App update config error:', error.message);
    res.status(500).json({ error: 'Failed to save update config' });
  }
});

// Public endpoint so your mobile/web app can check for updates
app.get('/api/app-update', async (req, res) => {
  try {
    if (!fs.existsSync(APP_UPDATE_FILE)) {
      return res.json({ available: false });
    }
    const data = JSON.parse(await fsPromises.readFile(APP_UPDATE_FILE, 'utf8'));
    res.json(data);
  } catch (error) {
    console.error('Read app-update error:', error.message);
    res.status(500).json({ available: false, error: 'Failed to check update status' });
  }
});
  // GET route for admin logs with time filter
  admin.get('/logs', async (req, res) => {
    const action = `${req.method} ${req.path}`;
    const ip = req.ip;
    const data = req.query;
    logAdminAction(action, ip, data);

    const { from } = req.query;
    try {
      const logContent = await fsPromises.readFile(LOG_FILE, 'utf8');
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

  //--- OTHER ROUTES  ---

  app.post('/api/upload', upload.single('file'), async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    if (!drive) {
      return res.status(503).json({ error: 'Google Drive service unavailable' });
    }

    try {
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

      // Make file public
      await drive.permissions.create({
        fileId: fileId,
        requestBody: {
          role: 'reader',
          type: 'anyone',
        },
      });

      const url = `https://drive.google.com/uc?id=${fileId}`;

      // Clean up temp file
      await fsPromises.unlink(req.file.path);

      // Send notification to Discord if configured
      if (process.env.DISCORD_WEBHOOK_URL) {
        try {
          await axios.post(process.env.DISCORD_WEBHOOK_URL, {
            content: `New image uploaded: ${url}`,
          });
        } catch (discordError) {
          console.error('Discord notification failed:', discordError.message);
          // Don't fail the response due to notification error
        }
      }

      res.status(200).json({ url });
    } catch (error) {
      console.error('Upload error:', error.message, error.response?.data || error.response);
      
      // Clean up temp file on error
      if (req.file && fs.existsSync(req.file.path)) {
        await fsPromises.unlink(req.file.path).catch(unlinkErr => console.error('Failed to clean up file:', unlinkErr.message));
      }

      if (error.response?.data?.error === 'invalid_grant') {
        res.status(503).json({ error: 'Authentication failed with Google Drive. Please check credentials and try again later.' });
      } else if (error.code === 'ENOENT' || error.code === 'EACCES') {
        res.status(500).json({ error: 'File system error occurred. Please try again.' });
      } else {
        res.status(500).json({ error: 'Upload failed. Please try again.' });
      }
    }
  });

  app.post('/api/data', async (req, res) => {
    if (!req.body || !req.body.type) {
      return res.status(400).json({ error: 'Invalid data: type is required' });
    }

    try {
      const data = req.body;
      const type = data.type;

      if (type === 'new_user' || type === 'profile_update') {
        // Save to users.json
        const currentUsers = JSON.parse(await fsPromises.readFile(USERS_FILE, 'utf8'));
        const user = data.user;
        if (!user || !user.email) {
          return res.status(400).json({ error: 'Invalid user data' });
        }
        if (user.password) {
          user.password = await bcrypt.hash(user.password, saltRounds);  // Added: hash password if provided
        }
        const key = user.email; // or user.userId if preferred
        currentUsers[key] = user;
        await fsPromises.writeFile(USERS_FILE, JSON.stringify(currentUsers, null, 2));
      } else {
        // Append to data.json for other types
        const currentData = JSON.parse(await fsPromises.readFile(DATA_FILE, 'utf8'));
        currentData.push(data);
        await fsPromises.writeFile(DATA_FILE, JSON.stringify(currentData, null, 2));
      }

      // Send notification to Discord if configured
      if (process.env.DISCORD_WEBHOOK_URL) {
        try {
          await axios.post(process.env.DISCORD_WEBHOOK_URL, {
            content: `New data received (type: ${type}) by ${user.email}`,
          });
        } catch (discordError) {
          console.error('Discord notification failed:', discordError.message);
          // Don't fail the response
        }
      }

      res.status(200).json({ success: true });
    } catch (error) {
      console.error('Data save error:', error.message);
      if (error.code === 'ENOENT' || error.code === 'EACCES') {
        res.status(500).json({ error: 'File system error occurred. Please try again.' });
      } else if (error instanceof SyntaxError) {
        res.status(500).json({ error: 'Data file corruption detected. Contact support.' });
      } else {
        res.status(500).json({ error: 'Data save failed. Please try again.' });
      }
    }
  });

  app.get('/api/services', async (req, res) => {
    try {
      const services = JSON.parse(await fsPromises.readFile(SERVICES_FILE, 'utf8'));
      res.status(200).json(services);
    } catch (error) {
      console.error('Services read error:', error.message);
      if (error.code === 'ENOENT') {
        res.status(404).json({ error: 'Services file not found' });
      } else if (error instanceof SyntaxError) {
        res.status(500).json({ error: 'Invalid services data format' });
      } else {
        res.status(500).json({ error: 'Failed to retrieve services' });
      }
    }
  });

  app.post('/api/services', upload.single('image'), async (req, res) => {
    try {
      const { name, price, desc, type } = req.body;

      const currentServices = JSON.parse(await fsPromises.readFile(SERVICES_FILE, 'utf8'));

      
        const newId = currentServices.length  + 1
        console.log(newId)
      
      if (!name || !price || !desc || !type) {
        return res.status(400).json({ error: 'Missing required fields: id, name, price, desc, type' });
      }

      // Handle image if uploaded
      let imagePath = null;
      if (req.file) {
        imagePath = path.join('uploads', req.file.filename);
        // Note: File stays in uploads/ - no cleanup or Drive upload
      }

      const newService = {
        id: parseInt(newId),
        name,
        price: parseFloat(price),
        desc,
        type,
        image: imagePath || null
      };

      currentServices.push(newService);
      await fsPromises.writeFile(SERVICES_FILE, JSON.stringify(currentServices, null, 2));

      res.status(201).json({ success: true, service: newService });
    } catch (error) {
      console.error('Service save error:', error.message);
      
      // Clean up uploaded file on error if it exists
      if (req.file && fs.existsSync(req.file.path)) {
        await fsPromises.unlink(req.file.path).catch(unlinkErr => console.error('Failed to clean up file:', unlinkErr.message));
      }

      if (error.code === 'ENOENT' || error.code === 'EACCES') {
        res.status(500).json({ error: 'File system error occurred. Please try again.' });
      } else if (error instanceof SyntaxError) {
        res.status(500).json({ error: 'Data file corruption detected. Contact support.' });
      } else {
        res.status(500).json({ error: 'Service save failed. Please try again.' });
      }
    }
  });

  app.get('/api/events', async (req, res) => {
    try {
      const events = JSON.parse(await fsPromises.readFile(EVENTS_FILE, 'utf8'));
      res.status(200).json(events);
    } catch (error) {
      console.error('Events read error:', error.message);
      if (error.code === 'ENOENT') {
        res.status(404).json({ error: 'Events file not found' });
      } else if (error instanceof SyntaxError) {
        res.status(500).json({ error: 'Invalid events data format' });
      } else {
        res.status(500).json({ error: 'Failed to retrieve events' });
      }
    }
  });

  app.post('/api/events', upload.single('image'), async (req, res) => {
    try {
      const { name, desc, type, url } = req.body;

      const currentEvents = JSON.parse(await fsPromises.readFile(EVENTS_FILE, 'utf8'));

      
        const newId = currentEvents.length  + 1
        console.log(newId)
      
      if (!name || !url || !desc || !type) {
        return res.status(400).json({ error: 'Missing required fields: id, name, desc, type' });
      }

      // Handle image if uploaded
      let imagePath = null;
      if (req.file) {
        imagePath = path.join('uploads', req.file.filename);
        // Note: File stays in uploads/ - no cleanup or Drive upload
      }

      const newEvent = {
        id: parseInt(newId),
        name,
        desc,
        type,
        url,
        image: imagePath || null
      };

      currentEvents.push(newEvent);
      await fsPromises.writeFile(EVENTS_FILE, JSON.stringify(currentEvents, null, 2));

      res.status(201).json({ success: true, event: newEvent });
    } catch (error) {
      console.error('Event save error:', error.message);
      
      // Clean up uploaded file on error if it exists
      if (req.file && fs.existsSync(req.file.path)) {
        await fsPromises.unlink(req.file.path).catch(unlinkErr => console.error('Failed to clean up file:', unlinkErr.message));
      }

      if (error.code === 'ENOENT' || error.code === 'EACCES') {
        res.status(500).json({ error: 'File system error occurred. Please try again.' });
      } else if (error instanceof SyntaxError) {
        res.status(500).json({ error: 'Data file corruption detected. Contact support.' });
      } else {
        res.status(500).json({ error: 'Event save failed. Please try again.' });
      }
    }
  });

  app.get('/api/tasks', async (req, res) => {
    try {
      //console.log('fetching task...')
      const tasks = JSON.parse(await fsPromises.readFile(TASKS_FILE, 'utf8'));
      res.status(200).json(tasks);
      //console.log('Task Success')
    } catch (error) {
      console.error('Tasks read error:', error.message);
      if (error.code === 'ENOENT') {
        res.status(404).json({ error: 'Events file not found' });
      } else if (error instanceof SyntaxError) {
        res.status(500).json({ error: 'Invalid tasks data format' });
      } else {
        res.status(500).json({ error: 'Failed to retrieve tasks' });
      }
    }
  });

  app.post('/api/tasks', upload.single('image'), async (req, res) => {
    const { desc, type, reward, shortResponse } = req.body
    try {

      const currentTasks = JSON.parse(await fsPromises.readFile(TASKS_FILE, 'utf8'));

      
        const newId = currentTasks.length  + 1
        console.log('Data Recieved:', desc, type, reward, shortResponse)
      
      if (!desc || !type || !reward) {
        console.log('Tasks Data Incomplete')
        return res.status(400).json({ error: 'Missing required fields: id, desc, type' });
      }

      // Handle image if uploaded
      let imagePath = null;
      if (req.file) {
        imagePath = path.join('uploads', req.file.filename);
        // Note: File stays in uploads/ - no cleanup or Drive upload
      }

      const newTask = {
        id: parseInt(newId),
        desc,
        type,
        shortResponse,
        reward,
        image: imagePath || null
      };

      currentTasks.push(newTask);
      await fsPromises.writeFile(TASKS_FILE, JSON.stringify(currentTasks, null, 2));

      res.status(201).json({ success: true, task: newTask });
    } catch (error) {
      console.error('Event save error:', error.message);
      
      // Clean up uploaded file on error if it exists
      if (req.file && fs.existsSync(req.file.path)) {
        await fsPromises.unlink(req.file.path).catch(unlinkErr => console.error('Failed to clean up file:', unlinkErr.message));
      }

      if (error.code === 'ENOENT' || error.code === 'EACCES') {
        res.status(500).json({ error: 'File system error occurred. Please try again.' });
      } else if (error instanceof SyntaxError) {
        res.status(500).json({ error: 'Data file corruption detected. Contact support.' });
      } else {
        res.status(500).json({ error: 'Task save failed. Please try again.' });
      }
    }
  });

  app.get('/', async (req, res) => {
    try {
      res.sendFile(path.join(__dirname, '../public'));
    } catch(error) {

    }
  });
  app.post('/api/answers', async (req, res) => {
    const { email, taskId, response, reward, type } = req.body;
    try {
      console.log('Requesting...')
      if(!email || !taskId || !response || !type) {
        return res.status(400).json({message: 'Invalid message'});
      }
      console.log('info intact')
      const answers = JSON.parse(await fsPromises.readFile(ANSWERS_FILE, 'utf8'));
      const users = JSON.parse(await fsPromises.readFile(USERS_FILE, 'utf8'));

      const userAnswers = answers[email] ? answers[email] : [];

      const id = userAnswers.length + 1
      let imagePath = null;
      if (req.file) {
        imagePath = path.join('uploads', req.file.filename);
        // Note: File stays in uploads/ - no cleanup or Drive upload
      }
      const newAnswer = {
        id,
        taskId,
        type,
        response,
        reward,
        attachment: imagePath ? imagePath : null,
        reviewed: false
      }

      userAnswers.push(newAnswer);
      answers[email] = userAnswers;

      const user= users[email]
      users[email]= {...user, unVerifiedPoints: parseInt(user.unVerifiedPoints) + parseInt(reward)}
      await fsPromises.writeFile(ANSWERS_FILE, JSON.stringify(answers, null, 2));
      await fsPromises.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
      res.status(200).json({success: true, data: newAnswer})
      console.log('Answered!')
    } catch(error) {
      console.log('AError:', error)
    }
  });

  app.get('/api/answers', async (req, res) => {
    try {
      const answers = JSON.parse(await fsPromises.readFile(ANSWERS_FILE, 'utf8'));
      const allAnswers = Object.values(answers).flat()
      res.json(allAnswers)
    } catch (error) {
      
    }
  });

  app.get('/api/answers/:email', async (req, res) => {
    const { email } = req.params;
    const { taskId, response, reward, type } = req.body;
    try {
      const answers = JSON.parse(await fsPromises.readFile(ANSWERS_FILE, 'utf8'));
      const userAnswers = answers[email]
      res.json(userAnswers)
    } catch (error) {
      console.log('AError:', error)
    }
  });

  app.post('/api/answers/sync/:email', async (req, res) => {
    const { email } = req.params;
    try {
      if (!req.body || req.body === JSON.parse('[]')) {
        return res.status(400).json({error: 'Invalid message!'})
      }
      const answers = JSON.parse(await fsPromises.readFile(ANSWERS_FILE, 'utf8'));
      const userAnswers = req.body
      const userkey  = answers[email] ? answers[email] : [];
      const generateId = (reqId) => {
        const data = userkey.filter((item) => item.taskId === reqId)
        console.log(data)
        const ansJson = data[0]
        
        return ansJson.id ? ansJson.id : ansJson.length + 1
      }
      const updated = userAnswers.map((answer) => 
        answer.taskId ? {
          id: generateId(answer.taskId)|| userkey.length + 1 || null,
        taskId: answer.taskId,
        type: answer.type || 'Long-term',
        response: answer.response,
        reward: answer.reward,
        attachment: answer.attachment || null,
        reviewed: false
        } : answer
      )
      answers[email] = updated
      await fsPromises.writeFile(ANSWERS_FILE, JSON.stringify(answers, null, 2));
      res.status(200).json({success: true, message: answers[email]})
    } catch (error) {
      console.log('AError:', error)
    }
  });

  app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
      if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
      }
      const currentUsers = JSON.parse(await fsPromises.readFile(USERS_FILE, 'utf8'));
      const user = currentUsers[email];
      if (!user || !user.userId || !user.hashedPassword) {  // Added: Check for hashedPassword existence
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      // Optional: Add type check for hashedPassword (should be a string starting with $2b$ or similar)
      if (typeof user.hashedPassword !== 'string' || !user.hashedPassword.startsWith('$2')) {
        return res.status(500).json({ error: 'Invalid user data' });  // Or handle as needed
      }
      const match = await bcrypt.compare(password, user.hashedPassword);
      if (!match) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      const token = jwt.sign(
        { email, userId: user.userId || user.id },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.json({ success: true, token, user: { ...user, hashedPassword: undefined } });
    } catch (error) {
      console.error('User login error:', error.message);
      res.status(500).json({ error: 'Login failed' });
    }
  });
  app.post('/api/auth/signin', async (req, res) => {
    const { username, email, password } = req.body;
    try {
      if(!username || !email || !password) {
        res.status(400).json({message: 'All field are required!'});
        return
      }
      const currentUsers = JSON.parse(await fsPromises.readFile(USERS_FILE, 'utf8'));
      if(currentUsers[email]) {
        res.status(401).json({message: "Email Already Exists"});
        return
      }
      const userId = generateUserId();
      const newHashed = await bcrypt.hash(password, saltRounds);
      const newUser = {
        email: email,
        userId: userId,
        username: username,
        hashedPassword: newHashed,
        profileImage: null,
        whatsappNo: 0,
        accountNo: null,
        accountName: null,
        accountBank: null,
        verifiedPoints: 20,
        unVerifiedPoints: 0,
        marketPoints: 0,
        record: 0,
        pendding: 0,
        role: 'user',
        badgeType: 'member'
      }

      const key = email;
      currentUsers[key] = newUser;
      
      await fsPromises.writeFile(USERS_FILE, JSON.stringify(currentUsers, null, 2));
      const token = jwt.sign(
        { email, userId },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      // Send notification to Discord if configured
      if (process.env.DISCORD_WEBHOOK_URL) {
        try {
          await axios.post(process.env.DISCORD_WEBHOOK_URL, {
            content: `New user added: ${email}`,
          });
        } catch (discordError) {
          console.error('Discord notification failed:', discordError.message);
          // Don't fail the response due to notification error
        }
      }

      res.status(200).json({success: true, token, user: {...newUser, hashedPassword: undefined}});

    } catch (error) {
      console.log('Auth Error:', error);
      res.status(500).json({error: error.name});
    }
  });

  app.patch('/api/users/:email/profile_avatar', async (req, res) => {
    const { uri } = req.body;
    const { email } = req.params;
    try {
      const currentUsers = JSON.parse(await fsPromises.readFile(USERS_FILE, 'utf8'));
      const user = currentUsers[email];
      const updated = {
        ...user,
        profileImage: uri,
      }
      currentUsers[email] = updated
      await fsPromises.writeFile(USERS_FILE, JSON.stringify(currentUsers, null, 2));
      res.status(200).json({message: 'Update Successful!'})

    } catch (error) {
      console.log('Avatar error: ', error)
    }
  })

  // GET single user by email (public / no auth)
app.get('/api/users/:email', async (req, res) => {
  const { email } = req.params;

  try {
    const currentUsers = JSON.parse(await fsPromises.readFile(USERS_FILE, 'utf8'));
    const user = currentUsers[email];

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Remove sensitive data before sending
    const { hashedPassword, ...safeUser } = user;

    res.json(safeUser);
  } catch (error) {
    console.error('Get user by email error:', error.message);
    res.status(500).json({ error: 'Failed to retrieve user' });
  }
});

// GET all users (public / no auth)
app.get('/api/users', async (req, res) => {
  try {
    const currentUsers = JSON.parse(await fsPromises.readFile(USERS_FILE, 'utf8'));
    
    // Convert object to array and remove hashedPassword from every user
    const allUsers = Object.values(currentUsers).map(user => {
      const { hashedPassword, ...safeUser } = user;
      return safeUser;
    });

    res.json(allUsers);
  } catch (error) {
    console.error('Get all users error:', error.message);
    res.status(500).json({ error: 'Failed to retrieve users' });
  }
});

  // Global error handler
  app.use((err, req, res, next) => {
    console.error('Global error:', err.message);
    res.status(500).json({ error: 'An unexpected error occurred. Please try again.' });
  });

  const PORT = process.env.PORT || 5000;

  
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

  if (process.env.GOOGLE_TOKEN) {
    try {
      const tokens = JSON.parse(process.env.GOOGLE_TOKEN);
      oAuth2Client.setCredentials(tokens);
      return oAuth2Client;
    } catch (e) {
      console.error('Invalid GOOGLE_TOKEN env:', e.message);
    }
  }

  if (fs.existsSync(TOKEN_PATH)) {
    const token = JSON.parse(fs.readFileSync(TOKEN_PATH));
    oAuth2Client.setCredentials(token);
    return oAuth2Client;
  }

  // No token, return without credentials
  console.log('No Google token found. Drive features disabled until configured.');
  return oAuth2Client;
}
