const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const app = express();
// const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken')
//Users table should have refreshToken datatype VARCHAR 60
//username-> VARCHAR 15 and password -> BLOB, UserID -> INT

//BlogPost Database -> id (Blog ID) -> INT, Date posted -> DATETIME, UserID -> INT, 
//title of blog -> VARCHAR, content of blog -> VARCHAR
//deleted_flag -> TINYINT
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
//gets blog posts for the user
app.get('/posts', (req, res)=>{
  res.json(posts.filter( post => post.username === req.user.name))

})
app.post('/login',(req, res)=>{
  const refreshToken = req.body.token
  if(refreshToken == null){
    return res.sendStatus(401)
  }
  if(refreshToken.includes(refreshToken)){
    return res.sendStatus(403)
  }
  jwt.verify(refreshToken, refresh, (err, user)=>{
    if(err){
      return res.sendStatus(403)
    }
    const accessToken = generateAccess({name: user.name})
    res.json({ accessToken: accessToken})
  })
})
//LOGIN USER  
app.post('/login', async function(req, res) {
  try{
    const username = req.body.username;
    const user = await req.db.query(`SELECT * FROM user WHERE user_name = :username`, { username });
    const accessToken = generateAccess(user)
    const refreshToken = jwt.sign(user,refresh)
    res.json({ accessToken: accessToken, refreshToken: refreshToken})
  } catch(err){
    res.status(400).json({ msg: 'Error logging user in'})
  }
});
//REGISTER USER
// app.post('/register', async function (req, res){
//   try{
//     const hashPass = await bcrypt.hash(req.body.password, 10);
//   } catch(err){

//   }
// });

function generateAccess(user){
  return jwt.sign(user, access, {expiresIn: '15s'})
}

//
app.listen(port, () => console.log(`212 API Example listening on http://localhost:${port}`));