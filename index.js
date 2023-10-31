const cors = require("cors");
const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { cookie } = require("express/lib/response");
const session = require("express-session");
require("dotenv").config();
const mysql = require("mysql2/promise");

app.use(express.json());
app.use(
  cors({
    credentials: true,
    origin: "http://localhost:8081",
  })
);

app.use(
  session({
    secret: "secret",
    resave: false,
    saveUninitialized: true,
  })
);

const port = process.env.PORT;
const secret = "mysupersecret";

let conn = null;

// function init connection mysql
const initMySQL = async () => {
  conn = await mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
  });
};

app.get("/", (req, res) => {
  res.send("Hello World!");
});

// function Register
app.post("/api/register", async (req, res) => {
  try {
    const { username, password, cid } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const userData = {
      username,
      password:hashedPassword,
    };
    const [results] = await conn.query("INSERT INTO users SET ?", userData);
    res.json({ message: "User created!", results });
  } catch (error) {
    console.log("error", error);
    res.json({ message: "User not created!", error });
  }
});

// function Login
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const [results] = await conn.query(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );
    const userData = results[0];
    console.log("userData", userData);
    const comparePw = await bcrypt.compare(password, userData.password);
    console.log("comparePw", comparePw)
    if (!comparePw) {
      res.status(400).json({ message: "Login Fail (wrong user pass)" });
      return false;
    }
    // create JWTToken
    const token = jwt.sign({ username, role:'user' }, secret, { expiresIn: "1h" });
    res.json({ message: "Login Success!", token });


    // res.json({ message: "Login Success!", userData });
  } catch (error) {
    console.log("error", error);
    res.status(401).json({ message: "Login Fail!", error });
  }
});


// app.get('/api/users', async (req, res) => {
//   try {
//     const [results] = await conn.query('SELECT * FROM personal');
//     res.json({
//       users: results
//     })
//   } catch (error) {
//     console.log('error', error);
//     res.status(403).json({ message: 'Authentication Fail!', error });
//   }
// });

// Listen
app.listen(port, async () => {
  await initMySQL();
  console.log("Server started at", process.env.PORT);
});
