const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const csrf = require('csurf');
require('dotenv').config();

const app = express();
const port = 3000;

// Import Singleton Pattern for database
const db = require('./database').getConnection();

// Import Observer Pattern for logging
const logger = require('./logger');

// Import reusable middleware (DRY Principle)
const { csrfProtection, validateSession } = require('./middleware');

// Subscribe to logger
logger.subscribe((logMessage) => console.log(logMessage)); // Console logging
logger.subscribe((logMessage) => {
  const [action, user, details] = logMessage.split(' by ')[1].split(': ');
  db.run(`INSERT INTO logs (action, user, details) VALUES (?, ?, ?)`, [action, user, details]);
}); // Database logging

// Basic security middleware
app.use(helmet()); // Security headers
app.use(rateLimit({ // Brute force protection
  windowMs: 15 * 60 * 1000, // 15 minutes per ip
  max: 100 // limit each IP to 100 requests
}));

// Session setup
app.use(session({
  // Uses env variable with fallback
  secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true, // Prevent client-side JS access
    sameSite: 'strict' // CSRF protection
  }
}));

// Initialize CSRF middleware
app.use(express.static(__dirname));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Display the login/register page to the user
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Display the comment page after the user logs in
app.get('/afterlogin', validateSession, csrfProtection, (req, res) => {
  if (!req.session.username) {
    logger.log('access_denied', 'guest', 'Attempt to access /afterlogin without auth');
    return res.redirect('/');
  }
  logger.log('page_access', req.session.username, 'Accessed /afterlogin');
  res.sendFile(path.join(__dirname, 'afterlogin.html'));
});

// Get CSRF token for AJAX requests
app.get('/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// SQLite setup
// Create tables if they don't exist
db.serialize(() => {
  // Unique constraint to username
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`, (err) => {
    if (err) logger.log('db_error', 'system', `Failed to create users table: ${err.message}`);
    else logger.log('db_success', 'system', 'Users table ready');
  });

  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    comment TEXT
  )`, (err) => {
    if (err) logger.log('db_error', 'system', `Failed to create comments table: ${err.message}`);
    else logger.log('db_success', 'system', 'Comments table ready');
  });

  // Logging table for database
  db.run(`CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    action TEXT,
    user TEXT,
    details TEXT
  )`, (err) => {
    if (err) logger.log('db_error', 'system', `Failed to create logs table: ${err.message}`);
    else logger.log('db_success', 'system', 'Logs table ready');
  });

  // Create admin account if it doesn't exist
  const adminPassword = bcrypt.hashSync('adminpassword', 12); // Admin Password
  db.run(`INSERT OR IGNORE INTO users (username, password) VALUES ('admin', ?)`, [adminPassword], (err) => {
    if (err) logger.log('db_error', 'system', `Failed to create admin account: ${err.message}`);
    else logger.log('db_success', 'system', 'Admin account ready');
  });
});

// XSS protection
const escapeHtml = (unsafe) => {
  return unsafe.replace(/[&<>"']/g, match => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  }[match]));
};

// Register user
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, 
      [username, hashedPassword], 
      (err) => {
        if (err) {
          logger.log('register_failed', username, `User creation error: ${err.message}`);
          return res.status(500).send('Error registering user');
        }
        logger.log('register_success', username, 'New user created');
        res.send('Registered successfully. <a href="/">Login here</a>');
      });
  } catch (err) {
    logger.log('register_error', username, `Hashing error: ${err.message}`);
    res.status(500).send('System error');
  }
});

// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, row) => {
    if (err) {
      logger.log('login_error', username, `Database error: ${err.message}`);
      return res.status(500).send('Error logging in');
    }
    if (row && await bcrypt.compare(password, row.password)) {
      req.session.username = row.username;
      logger.log('login_success', username, 'User logged in');
      res.redirect('/afterlogin');
    } else {
      logger.log('login_failed', username, 'Invalid credentials');
      res.send('Login failed. <a href="/">Try again</a>');
    }
  });
});

// Get all comments
app.get('/comments', validateSession, csrfProtection, (req, res) => {
  db.all('SELECT * FROM comments', [], (err, rows) => {
    if (err) {
      logger.log('comment_fetch_error', req.session.username, `Error: ${err.message}`);
      return res.status(500).send(err.message);
    }
    logger.log('comment_fetch', req.session.username, `Retrieved ${rows.length} comments`);
    res.json(rows);
  });
});

// Create new comment
app.post('/create', validateSession, csrfProtection, (req, res) => { 
  const username = req.session.username;
  const comment = escapeHtml(req.body.comment);
  
  db.run(`INSERT INTO comments(name, comment) VALUES (?, ?)`, 
    [username, comment], 
    (err) => {
      if (err) {
        logger.log('comment_create_error', username, `Error: ${err.message}`);
        return res.status(500).send(err.message);
      }
      logger.log('comment_create', username, 'New comment created');
      res.sendStatus(200);
    });
});

// Update comment
app.post('/update/:id', validateSession, csrfProtection, (req, res) => {
  const comment = escapeHtml(req.body.comment);
  const { id } = req.params;
  
  db.get(`SELECT * FROM comments WHERE id = ?`, [id], (err, row) => {
    if (err) {
      logger.log('comment_update_error', req.session.username, `Error: ${err.message}`);
      return res.status(500).send(err.message);
    }

    if (!row || (row.name !== req.session.username && req.session.username !== 'admin')) {
      logger.log('comment_update_denied', req.session.username, `Unauthorized attempt to update comment ${id}`);
      return res.status(403).send('Unauthorized');
    }

    db.run(`UPDATE comments SET comment = ? WHERE id = ?`, [comment, id], (err) => {
      if (err) {
        logger.log('comment_update_error', req.session.username, `Error: ${err.message}`);
        return res.status(500).send(err.message);
      }
      logger.log('comment_update', req.session.username, `Updated comment ${id}`);
      res.sendStatus(200);
    });
  });
});

// Delete comment
app.post('/delete/:id', validateSession, csrfProtection, (req, res) => {
  const { id } = req.params;

  db.get(`SELECT * FROM comments WHERE id = ?`, [id], (err, row) => {
    if (err) {
      logger.log('comment_delete_error', req.session.username, `Error: ${err.message}`);
      return res.status(500).send(err.message);
    }

    if (!row || (row.name !== req.session.username && req.session.username !== 'admin')) {
      logger.log('comment_delete_denied', req.session.username, `Unauthorized attempt to delete comment ${id}`);
      return res.status(403).send('Unauthorized');
    }

    db.run(`DELETE FROM comments WHERE id = ?`, [id], (err) => {
      if (err) {
        logger.log('comment_delete_error', req.session.username, `Error: ${err.message}`);
        return res.status(500).send(err.message);
      }
      logger.log('comment_delete', req.session.username, `Deleted comment ${id}`);
      res.sendStatus(200);
    });
  });
});

// Search bar
app.get('/search', validateSession, csrfProtection, (req, res) => {
  const username = escapeHtml(req.query.username || '');
  db.all(`SELECT * FROM comments WHERE name = ?`, [username], (err, comments) => {
    if (err) {
      logger.log('search_error', req.session.username, `Error: ${err.message}`);
      return res.send(`Error: ${escapeHtml(err.message)}`);
    }

    logger.log('search', req.session.username, `Searched for user: ${username} (${comments.length} results)`);
    
    let results = `<h3>Comments by ${username}:</h3>`;
    results += `<a href="/afterlogin">Back to comments</a><br><br>`;
    
    if (comments.length === 0) {
      results += `<p>No comments found for user: ${username}</p>`;
    } else {
      comments.forEach(c => {
        results += `<p><strong>${escapeHtml(c.name)}:</strong> ${escapeHtml(c.comment)}</p>`;
      });
    }

    res.send(results);
  });
});

// Start server
app.listen(port, () => {
  logger.log('server_start', 'system', `Server running at http://localhost:${port}`);
});