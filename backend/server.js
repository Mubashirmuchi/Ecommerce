import express from "express";
import dotenv from "dotenv"

import authRoute from "./routes/auth.route.js"
import { connectDB } from "./lib/db.js";

dotenv.config();

const app = express()
const PORT = process.env.PORT || 8000

app.use(express.json())

app.use("/api/auth",authRoute)
app.listen(PORT,()=>{
    connectDB() 
    console.log("server is running on http://localhost:"+PORT)})

