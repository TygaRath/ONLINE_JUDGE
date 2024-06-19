const express=require('express');
const app=express();
const {DBConnection} = require('./database/db.js');
const user = require('./models/users.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
dotenv.config();


//add middlewares
app.use(express.json());
app.use(express.urlencoded({extended: true}));
DBConnection();

//get response
app.get("/",(req, res)=>{
    res.send("helo");
});

app.post("/register", async (req, res)=>{
    console.log(req);
    try{
        //DESTRUCTURING
        const {username,email,password,confirmPassword} = req.body;
    
        // check data exists
        if(!(username && email && password && confirmPassword)){
            return res.status(400).send("Please enter all the required fields!");
        }

        //check user exists
        const existingUser= await user.findOne({email});
        if(existingUser){
            return res.status(400).send("User already exists!");
        }

        //username taken
        const existingName= await user.findOne({username});
        if(existingName){
            return res.status(400).send("Username taken!");
        }

        if(password!=confirmPassword){
            return res.status(400).send("Passwords don't match!");
        }

        const hashPassword = bcrypt.hashSync(password,10);

        const User = await user.create({
            username,
            email,
            confirmPassword,
            password: hashPassword

        });

        const token=jwt.sign({id:User._id,email},process.env.SECRET_KEY,{
            expiresIn:"3h"
        });
        User.token=token;
        //IMP
        User.password=undefined;
        res.status(200).json({
            message: "You have successfully registered",
            User
        });


    }catch(error){
        console.log(error);
    }
});

app.post("/login", async (req,res)=>{
    try{
        const {username,password}= req.body;
        if(!(username && password)){
            return res.status(400).send("Please enter all the required fields!");
        }
        const User=await user.findOne({username});
        if(!User){
            return res.status(401).send("User does not exist!");
        }
        //Match password
        const enteredPassword=await bcrypt.compare(password,User.password);
        if(!enteredPassword){
            return res.status(401).send("Wrong Password");
        }

        const token=jwt.sign({id:User._id},process.env.SECRET_KEY,{
            expiresIn: "3h",
        });
        User.token=token;
        User.password=undefined;

        //store cookies
        const options = {
            expires: new Date(Date.now()+3*60*60*1000),
            httpOnly: true,
        };

        //send it
        res.status(200).cookie("token",token,options).json({
            message: "Logged in",
            success: true,
            token,
        });
        
    }catch(error){
        console.log(error);
    }
})

app.listen(8000, ()=>{
    console.log("Server at 8000");
});