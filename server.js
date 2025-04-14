const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');

const app = express();
const port = 3000;

// Session setup
app.use(session({
  secret: '123',
  resave: false,
  saveUninitialized: true
}));

app.use(express.static(__dirname));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Display the login/register page to the user
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Display the comment page after the user logs in
app.get('/afterlogin', (req, res) => {
  if (!req.session.username) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'afterlogin.html'));
});

// SQLite setup
const db = new sqlite3.Database('./database.db');

// Create user and comments tables if they don't exist
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    comment TEXT
  )`);
});

// Register user
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const query = `INSERT INTO users (username, password) VALUES ('${username}', '${password}')`;
  db.run(query, err => {
    if (err) return res.status(500).send('Error registering user');
    res.send('Registered successfully. <a href="/">Login here</a>');
  });
});

// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  db.get(query, (err, row) => {
    if (err) return res.status(500).send('Error logging in');
    if (row) {
      req.session.username = row.username;
      res.redirect('/afterlogin');
    } else {
      res.send('Login failed. <a href="/">Try again</a>');
    }
  });
});

// Get all comments
app.get('/comments', (req, res) => {
  db.all('SELECT * FROM comments', [], (err, rows) => {
    if (err) return res.status(500).send(err.message);
    res.json(rows);
  });
});

// Create new comment
app.post('/create', (req, res) => {
  const username = req.session.username;
  const { comment } = req.body;
  const query = `INSERT INTO comments(name, comment) VALUES ('${username}', '${comment}')`;
  db.run(query, err => {
    if (err) return res.status(500).send(err.message);
    res.sendStatus(200);
  });
});

// Update comment
app.post('/update/:id', (req, res) => {
  const { comment } = req.body;
  const { id } = req.params;
  const query = `UPDATE comments SET comment = '${comment}' WHERE id = ${id}`;
  db.run(query, err => {
    if (err) return res.status(500).send(err.message);
    res.sendStatus(200);
  });
});

// Delete comment
app.post('/delete/:id', (req, res) => {
  const { id } = req.params;
  const query = `DELETE FROM comments WHERE id = ${id}`;
  db.run(query, err => {
    if (err) return res.status(500).send(err.message);
    res.sendStatus(200);
  });
});

// Search bar
app.get('/search', (req, res) => {
  if (!req.session.username) {
    return res.redirect('/');
  }
  
  const username = req.query.username || '';
  const query = `SELECT * FROM comments WHERE name = '${username}'`;

  db.all(query, [], (err, comments) => {
    if (err) {
      return res.send(`Error: ${err.message}`);
    }

    let results = `<h3>Comments by ${username}:</h3>`;
    results += `<a href="/afterlogin">Back to comments</a><br><br>`;
    
    if (comments.length === 0) {
      results += `<p>No comments found for user: ${username}</p>`;
    } else {
      comments.forEach(c => {
        results += `<p><strong>${c.name}:</strong> ${c.comment}</p>`;
      });
    }

    res.send(results);
  });
});

// Start server
app.listen(port, () => {
  console.log(`Insecure app running at http://localhost:${port}`);
});
