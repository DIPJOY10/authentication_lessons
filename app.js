//jshint esversion:6
require('dotenv').config();
const express=require('express');
const app=express();
const mongoose=require('mongoose');
const bodyParser=require('body-parser');
const ejs=require('ejs');
const encrypt=require('mongoose-encryption');
//const md5=require('md5');
const bcrypt=require('bcrypt');
const saltRounds=10;

app.use(express.static("public"));
app.set("view engine","ejs");

app.use(bodyParser.urlencoded({extended:true}));

mongoose.connect("mongodb://localhost:27017/secretDB",{useNewUrlParser:true,useUnifiedTopology:true});

const accountSchema=new mongoose.Schema({
  username:String,
  password:String
});
//level 2 security
//encryption using mongoose-encryption package
// accountSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:["password"]});

const User=new mongoose.model("User",accountSchema);

app.get("/register",function(req,res){
  res.render("register");
});
//level 1 security using basic registration
app.post("/register",function(req,res){
  //level 4 through salting with saltrounds
  bcrypt.hash(req.body.password,saltRounds,function(err,hash){
    const user=new User({
      username:req.body.username,
      password:hash //level 3 with md5 converted to level 4 security using salting with bcrypt through hashing using md5
    });
    user.save(function(err){
      if(err)
      console.log(err);
      else
      res.render("secrets");
    });
  });
});

app.get("/login",function(req,res){
  res.render("login");
});
app.post("/login",function(req,res){
  User.findOne({username:req.body.username},function(err,foundUser){
    if(foundUser){
      bcrypt.compare(req.body.password,foundUser.password,function(err,result){
        if(result===true)
        res.render("secrets");
        else
        res.send("wrong password");
      });
    }
    else
    res.send("no matching email found");
  });
});
app.get("/",function(req,res){
  res.render("home");
});
app.listen(3000,function(){
  console.log("Server running on port 3000");
});
