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
app.use(async (req, res, next) => {
  try {
    // Connecting to our SQL db. req gets modified and is available down the line in other middleware and endpoint functions
    req.db = await pool.getConnection();
    req.db.connection.config.namedPlaceholders = true; //THIS IS VERY IMPORTANT

    // Traditional mode ensures not null is respected for unsupplied fields, ensures valid JavaScript dates, etc.
    await req.db.query('SET SESSION sql_mode = "TRADITIONAL"');
    await req.db.query(`SET time_zone = '-8:00'`);

    // Moves the request on down the line to the next middleware functions and/or the endpoint it's headed for
    await next();

    // After the endpoint has been reached and resolved, disconnects from the database
    req.db.release();
  } catch (err) {
    // If anything downstream throw an error, we must release the connection allocated for the request
    console.log(err)
    // If an error occurs, disconnects from the database
    if (req.db) req.db.release();
    throw err;
  }
});
app.post('/login', async function(req, res) {
  try {
    const { token, username, password } = req.body;
    if (token) {
      // If token is provided, verify it and generate a new access token
      jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) {
          return res.sendStatus(403);
        }
        const accessToken = generateAccess({ username: user.name });
        res.json({ accessToken });
      });
    } else if (username && password) {
      // If username and password are provided, attempt to log in the user
      const [userRows] = await pool.query(`SELECT * FROM users WHERE username = :username`, {username});
      const user = userRows[0];
      if (!user) {
        return res.status(404).json({ msg: 'User not found' });
      }
      // Compare the provided password with the hashed password stored in the database
      const passwordMatch = await bcrypt.compare(String(password), String(user.password));
      if (!passwordMatch) {
        return res.status(401).json({ msg: 'Invalid password' });
      }
      // If password is correct, generate tokens and send the response
      const accessToken = generateAccess({ username: user.username });
      const refreshToken = jwt.sign({ username: user.username }, process.env.REFRESH_TOKEN_SECRET);
      await pool.query('UPDATE `users` SET refresh_token =:refreshToken WHERE username =:username', {refreshToken, username});
      res.json({ accessToken, refreshToken });
    } else {
      // If neither token, nor username and password are provided, return an error
      return res.status(400).json({ msg: 'Neither token nor username/password provided' });
    }
  } catch(err) {
    console.error(err);
    res.status(500).json({ msg: 'Internal server error: Error login user in' });
  }
});

app.post('/register', async function(req, res) {
  try {
    const { username, password } = req.body;
    const refresh_token = process.env.REFRESH_TOKEN_SECRET;
    // Check if username already exists in the database
    const [existingUserRows] = await pool.query('SELECT * FROM users WHERE username = :username', { username });

    if (existingUserRows.length > 0) {
      return res.status(400).json({ msg: 'Username already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database
    await pool.query(`INSERT INTO users (username, password, refresh_token) VALUES (:username, :hashedPassword, :refresh_token)`, {username, hashedPassword, refresh_token});

    res.status(201).json({ msg: 'User registered successfully' });
  } catch(err) {
    console.error(err);
    res.status(500).json({ msg: 'Internal server error' });
  }
});

function generateAccess(user){
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '60s' }); // Expiration time set to 60s for debugging
}

app.listen(port, () => console.log(`212 API Example listening on http://localhost:${port}`));
