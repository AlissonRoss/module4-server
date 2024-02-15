const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
//Users table should have refreshToken datatype VARCHAR 60
//username-> VARCHAR 15 and password -> BLOB, UserID -> INT

//BlogPost Database -> id (Blog ID) -> INT, Date posted -> DATETIME, UserID -> INT, 
//title of blog -> VARCHAR, content of blog -> VARCHAR
//deleted_flag -> TINYINT
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

const port = process.env.PORT;

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  port: process.env.DB_PORT
});

app.post('/login', async function(req, res) {
  try {
    const { token, username } = req.body;

    if (token) {
      // If token is provided, verify it and generate a new access token
      jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) {
          return res.sendStatus(403);
        }
        const accessToken = generateAccess({ username: user.name });
        res.json({ accessToken });
      });
    } else if (username) {
      // If username is provided, log in the user
      const [userRows, userFields] = await pool.query(`SELECT * FROM users WHERE username = ?`, [username]);
      const user = userRows[0];
      if (!user) {
        return res.status(404).json({ msg: 'User not found' });
      }
      const accessToken = generateAccess({ username: user.username });
      const refreshToken = jwt.sign({ username: user.username }, process.env.REFRESH_TOKEN_SECRET);
      res.json({ accessToken, refreshToken });
    } else {
      // If neither token nor username is provided, return an error
      return res.status(400).json({ msg: 'Neither token nor username provided' });
    }
  } catch(err) {
    console.error(err);
    res.status(500).json({ msg: 'Internal server error' });
  }
});

app.post('/register', async function(req, res) {
  try {
    const { username, password } = req.body;

    // Check if username already exists in the database
    const [existingUserRows, existingUserFields] = await pool.query(`SELECT * FROM users WHERE username = ?`, [username]);
    if (existingUserRows.length > 0) {
      return res.status(400).json({ msg: 'Username already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database
    await pool.query(`INSERT INTO users (username, password, refresh_token) VALUES (?, ?, ?)`, [username, hashedPassword, process.env.REFRESH_TOKEN_SECRET]);

    res.status(201).json({ msg: 'User registered successfully' });
  } catch(err) {
    console.error(err);
    res.status(500).json({ msg: 'Internal server error' });
  }
});

function generateAccess(user){
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15s' }); // Expiration time set to 1 hour
}

app.listen(port, () => console.log(`212 API Example listening on http://localhost:${port}`));
