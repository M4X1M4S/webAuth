//OAuth (OPEN AUTHORISATION)..
import express from "express";
import bodyParser from "body-parser";
import env from "dotenv";
import pg from "pg";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import bcrypt from "bcrypt";
import GoogleStrategy from "passport-google-oauth2";




const app = express();
const port = 3000;
env.config();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

//SESSION MIDDLEWARE SETUP
//Configures the Express session middleware with a secret key, which is used to sign the session ID cookie.
app.use(
  session({
  secret:"MYTOPSECRET",
  resave:false,
  saveUninitialized:true,
  
})
);

//PASSPORT MIDDLEWARE SETUP
app.use(passport.initialize());
app.use(passport.session());

const db= new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT
});

db.connect();

// Function to hash a password
async function hashPassword(password) {
  const saltRounds = 10; // Number of rounds to generate salt
  const hashedPassword = await bcrypt.hash(password, saltRounds); // Hash the password
  return hashedPassword;
}

// Function to verify a password
async function verifyPassword(password, hashedPassword) {
  const match = await bcrypt.compare(password, hashedPassword); // Compare plain password with hashed password
  return match; // Returns true if the password matches
}

console.log(process.env.GOOGLE_CLIENT_ID);
app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/auth/google",passport.authenticate("google",{
    scope:["profile","email"],
}));

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req,res)=>{
  req.logout((err)=>{
    if (err) console.log(err);
    res.redirect("/")
  })
})
app.get("/auth/google/secrets",
  passport.authenticate("google",{
    successRedirect:"/secrets",
    failureRedirect:"/login",
  }
));

app.get('/secrets',(req,res)=>{
   //this has access to user 
  //console.log(req.user)
  if (req.isAuthenticated){
    res.render("secrets.ejs");
  }
  else{
    res.render("login.ejs");
  }
})

app.post("/register", async (req, res) => {
  try {
    const result= await db.query("SELECT * FROM users WHERE email = $1",[req.body.username]);
  if(result.rows.length>0){
    res.send("User already registered , try logging in");
    res.render('login.ejs');
  }
  else{
    const hashedPassword= hashPassword(req.body.password);
    await db.query("INSERT INTO users (email,password) VALUES ($1,$2)",[req.body.username,hashedPassword]);
    res.render('home.ejs');
  }
  } catch (error) {
    console.log("Error registering User "+ error);
  }
  
});

//Handles the login form submission using Passport's local strategy.
//If authentication succeeds, redirects to the secrets page; otherwise, redirects back to the login page.
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
   
  })
);




//PASSPORT LOCAL STRATEGY SETUP
passport.use("local",
  new Strategy (async function verify(username,password,cb){ //verify gets the username and password from the form which submits that
    try {
      const result= await db.query("SELECT * FROM users WHERE email = $1",[username]);
      const user=result.rows[0];

      if(result.rows.length>0){
          
        if(verifyPassword(password,result.rows[0].password)){
           return cb(null,user);
        }
        else{
          return cb(null,false);
       
        }
      }
      else{
        return cb("NO user found try register again");
       
      }
    } catch (error) {
      return cb(error);
    }
  })
)

passport.use(
    "google",
    new GoogleStrategy({
        clientID:process.env.GOOGLE_CLIENT_ID,
        clientSecret:process.env.GOOGLE_CLIENT_SECRET,
        callbackURL:"http://localhost:3000/auth/google/secrets",
        userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo",
    },
      async(accessToken , refreshToken , profile , cb)=>{
        console.log(profile);
        try {
          const result = await db.query("SELECT * FROM users WHERE email = $1",[profile.email,]);
          if (result.rows.length === 0){
            const newUser = await db.query("INSERT INTO users (email, password) VALUES ($1, $2)",[profile.email, "google"]);
            cb(null, newUser.rows[0]);
          }else{
            //Already Existing user
            cb(null, result.rows[0]);
          }
        } catch (error) {
          cb(err);
        }
      })
)

//passport.serializeUser: is a function provided by Passport that determines which data of the user object should be stored in the session.
//Once you've determined what data to store, you call the callback cb with null (to indicate that there's no error) and the data you want to store.

passport.serializeUser((user,cb)=>{
  cb(null,user);
});

//passport.deserializeUser: is a function provided by Passport that retrieves the data stored in the session and converts it into a user object.
//Once you've retrieved the user object, you call the callback cb with null (to indicate that there's no error) and the user object.

passport.deserializeUser((user,cb)=>{
  cb(null,user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
