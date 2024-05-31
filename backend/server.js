import express from "express"
import dotenv from "dotenv"
import cookieParser from "cookie-parser"
import authRoutes from "./routes/authroutes.js"
import messageRoutes from "./routes/message.routes.js" 
import userRoutes from "./routes/user.routes.js" 
import connectToMongoDB from "./db/connectToMongoDB.js"
const app = express()
dotenv.config()
app.use(express.json())
app.use(cookieParser())
app.use("/api/auth",authRoutes)
app.use("/api/messages",messageRoutes)
app.use("/api/users",userRoutes)
const PORT = process.env.PORT || 5000
// app.get("/",(req,res)=>{
//     res.send("hello world !!")
// })
app.listen(PORT,()=>{
    connectToMongoDB();
    console.log(`server is running on port ${PORT}`)
})