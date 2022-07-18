//jshint esversion:6
require('dotenv').config();
//.ENV is used to store sensitive data, to keep out of reach of hackers
//.env file is used to hold environment variables
//SECRET is our encryption key in .env file
const express= require("express");
const bodyParser= require("body-parser");
const ejs= require("ejs");
const mongoose=require("mongoose");
const encrypt=require("mongoose-encryption");
//using mongoose-encryption schema

const app=express();

console.log(process.env.API_KEY);

app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));


mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema= new mongoose.Schema({
  email: String,
  password: String
});


//We only want to encrypt the password
//process.env. is used to take components from .env file
userSchema.plugin(encrypt, { secret: process.env.SECRET , encryptedFields: ["password"] });


const User=new mongoose.model("User",userSchema);

app.get("/",function(req,res){
  res.render("home");
});

app.get("/login",function(req,res){
  res.render("login");
});

app.get("/register",function(req,res){
  res.render("register");
});

//post targeting the register route
app.post("/register",function(req,res){
//This is where the encryption is done
  const newUser= new User({
    email: req.body.username,
    password:req.body.password
  });
//When the save is done, mongoose encrypt encrypts the password
  newUser.save(function(err){
    if(err){
      console.log(err);
    } else{
      res.render("secrets");
    }
  });
});

app.post("/login",function(req,res){
  const username= req.body.username;
  const password= req.body.password;

// When we try to find the user based on username, at this stage decryption of password field is done
  User.findOne({email: username},function(err,foundUser){
    if(err){
      console.log(err);
    } else{
      if(foundUser){
        if(foundUser.password === password){
          res.render("secrets");
        }
      }
    }
  });
});
















app.listen(3000,function(){
  console.log("Server started on port 3000");
})
