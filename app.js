const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const uuid = require('uuid');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken')

require('dotenv').config();

const port = process.env.PORT;

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  port: process.env.DB_PORT,
  access: process.env.ACCESS_TOKEN_SECRET,
  refresh: process.env.REFRESH_TOKEN_SECRET
});


//LOGIN USER  
app.post('/login', authenticateToken, (req, res) => {
  try{
    const username = req.body.username;
    const user = {name: username}
    const accessToken = jwt.sign(user, access)
    res.json({ accessToken: accessToken})
  } catch(err){
    res.status(400).json({ msg: 'Error logging user in'})
  }
});
//REGISTER USER
app.post('/register', async function (req, res){
  try{
    const hashPass = await bcrypt.hash(req.body.password, 10);
  } catch(err){

  }
});
function verifyJwt(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]
  
};
app.listen(port, () => console.log(`212 API Example listening on http://localhost:${port}`));