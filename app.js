//jshint esversion:6
require('dotenv').config();
//.ENV is used to store sensitive data, to keep out of reach of hackers
//.env file is used to hold environment variables
//SECRET is our encryption key in .env file
//.env and .gitignore are very important to keep our secret files at bay
const express= require("express");
const bodyParser= require("body-parser");
const ejs= require("ejs");
const mongoose=require("mongoose");
// const encrypt=require("mongoose-encryption");
//using mongoose-encryption schema
// const md5=require("md5");
//md5 is required to implement the hash function
const session = require('express-session');
const passport= require('passport');
//We have also downloaded passport-local as it required by passport-local-mongoose but we don't really need to require it in our code
const passportLocalMongoose= require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')

const app=express();

// console.log(process.env.API_KEY);

app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

//Setting our session package
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

//Tell our app to use passport and initialize package
app.use(passport.initialize());
//Using  passport to manage our session
app.use(passport.session());


mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema= new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

//This schema in order to have a plugin, needs to have a mongoose schema

//we are using passportLocalMongoose to salt and hash our passwords
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//We only want to encrypt the password
//process.env. is used to take components from .env file
// userSchema.plugin(encrypt, { secret: process.env.SECRET , encryptedFields: ["password"] });


const User=new mongoose.model("User",userSchema);

// use static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(function(user, done) {
  done(null,user.id);
});

passport.deserializeUser(function(id,done) {
  User.findById(id,function(err,user){
    done(err,user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res){
  res.render("home");
});

//Using passport to authenticate the user using google strategy
app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

app.get("/login",function(req,res){
  res.render("login");
});

app.get("/register",function(req,res){
  res.render("register");
});

app.get("/secrets",function(req,res){
  //Checking for the fields for which secret field is not equals to null
  User.find({"secret": {$ne:null}}, function(err,foundUsers){
    if(err){
      console.log(err);
    } else{
      if(foundUsers){
        res.render("secrets",{usersWithSecrets: foundUsers});
      }
    }
  });
});

app.post("/submit",function(req,res){
  const submittedSecret=req.body.secret;


  User.findById(req.user.id,function(err,foundUser){
    if(err){
      console.log(err);
    } else{
      if(foundUser){
        foundUser.secret=submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
})

app.get("/submit",function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  } else{
    res.redirect("/login");
  }
});

app.get("/logout", function(req,res){
  req.logout(function(err){
    if(err){
      console.log(err);
    }
  });
  res.redirect("/");
});

//post targeting the register route
app.post("/register",function(req,res){
//This register method comes from passport-local-mongoose
    User.register({username: req.body.username},req.body.password,function(err,user){
      if(err){
        console.log(err);
        res.redirect("/redirect");
      } else{
        passport.authenticate("local")(req,res,function(){
          res.redirect("/secrets");
        });
      }
    });

});

app.post("/login",function(req,res){
  const user=new User({
    username: req.body.username,
    password:req.body.password
  });

  req.login(user,function(err){
    if(err){
      console.log(err);
    } else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  });
});



app.listen(3000,function(){
  console.log("Server started on port 3000");
})
