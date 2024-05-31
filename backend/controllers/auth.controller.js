import bcrypt from "bcryptjs"
import User from "../models/user.model.js";
import generateTokenAndSetCookie from "../utils/generateToken.js";
export const signup = async(req,res)=>{
    try {
        const{fullname,username,password,confirmpassword,gender} = req.body;
        if(password !== confirmpassword){
            return res.status(400).json({error:"Passwords don't match"})
        }
        const user = await User.findOne({username})
        if(user){
            return res.status(400).json({error:"Useraname already exists"})
        }
        const salt =  await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password,salt)
        const boyProfilePic = `https://avatar.iran.liara.run/public/boy?username = ${username}`
        const girlProfilePic = `https://avatar.iran.liara.run/public/girl?username = ${username}`
        const newUser = new User({
            fullname,
            username,
            password:hashedPassword,
            gender,
            profilepic:gender === 'male' ? boyProfilePic : girlProfilePic
        })
        if(newUser){
            generateTokenAndSetCookie(newUser._id,res)
            await newUser.save()
            res.status(201).json({
                _id:newUser._id,
                fullname:newUser.fullname,
                username:newUser.username,
                profilepic:newUser.profilepic
            })
        }
        else{
            res.status(400).json({error:"Invalid user data"})
        }
    } catch (error) {
        console.log("Error in signup control",error.message)
        res.status(500).json({error:"Internal server error"})
    }
}
export const login = async(req,res)=>{
    try {
        const {username,password} = req.body
        const user = await User.findOne({username})
        const isPasswordCorrect = await bcrypt.compare(password,user?.password ||"")
        if(!user || !isPasswordCorrect){
            return res.status(400).json({error:"Invalid Username or Password"})
        }
        generateTokenAndSetCookie(user._id,res)
        res.status(200).json({
            _id:user._id,
            fullname:user.fullname,
            username:user.username,
            profilepic:user.profilepic
        })
    } catch (error) {
        console.log("Error in login controller",error.message)
        res.status(500).json({error:"Internal Server Error"})
    }
}
export const logout = (req,res)=>{
    try {
        res.cookie("jwt","",{maxAge:0})
        res.status(400).json({message:"Logged Out Successfully"})
    } catch (error) {
        console.log("Error in logout controller",error.message)
        res.status(500).json({error:"Internal Server Error"})
    }
}