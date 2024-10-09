import express from "express";
import bodyParser from "body-parser";
import env from "dotenv";
import pg from "pg";
import CryptoJS from "crypto-js";



const app = express();
const port = 3000;
env.config();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
const db= new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT
});

const key=process.env.SECRET_KEY;

db.connect();
function encrypt(text, key) {
    return CryptoJS.AES.encrypt(text, key).toString();
  }

  function decrypt(encryptedText, key) {
    const bytes = CryptoJS.AES.decrypt(encryptedText, key);
    return bytes.toString(CryptoJS.enc.Utf8);
  }

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  try {
    const result= await db.query("SELECT * FROM users WHERE email = $1",[req.body.username]);
  if(result.rows.length>0){
    res.send("User already registered , try logging in");
    res.render('login.ejs');
  }
  else{
    const encPassword=encrypt(req.body.password,key);
    await db.query("INSERT INTO users (email,password) VALUES ($1,$2)",[req.body.username,encPassword]);
    res.render('home.ejs');
  }
  } catch (error) {
    console.log("Error registering User "+ error);
  }
  
});

app.post("/login", async (req, res) => {
  try {
    const result= await db.query("SELECT * FROM users WHERE email = $1",[req.body.username]);
    if(result.rows.length>0){
        const decryptedPassword=decrypt(result.rows[0].password,key)
      if(decryptedPassword===req.body.password){
        res.render('secrets.ejs');
      }
      else{
        res.send("Incorrect Password , try Again");
     
      }
    }
    else{
      res.send("NO user found try register again");
     
    }
  } catch (error) {
    console.log("Error logging in" + error)
  }

});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
