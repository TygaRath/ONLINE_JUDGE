const mongoose = require('mongoose');
const dotenv = require('dotenv');
dotenv.config();

const DBConnection = async ()=>{
    const MONGODB_URL=process.env.MONGODB_URI;
    try{
        await mongoose.connect(MONGODB_URL, {useNewURLParser:true});
        console.log("DB connection done");
    }catch(error){
        console.log("error connection to mongodb " +error);
    }
};

module.exports={DBConnection};