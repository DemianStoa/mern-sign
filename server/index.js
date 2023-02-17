import mongoose from "mongoose";
import cors from "cors"
import dotenv from "dotenv"
import express from "express";
import bodyParser from "body-parser";
import authRoutes from "./routes/auth.js";
//import userRoutes from "./routes/user.js";
import {errorHandler} from "./middleWare/errorHandler.js"
import cookieParser from "cookie-parser"

dotenv.config()
const app = express()
app.use(express.json())
app.use(cookieParser())
app.use(express.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(cors())

// app.get("/", (req, res) => {
//     res.send("Home Page")
//   })
app.use("/auth", authRoutes);
//app.use("user", userRoutes)


// Error Middleware
app.use(errorHandler);

const PORT = process.env.PORT || 5001;

mongoose.set('strictQuery', true);
mongoose.connect(process.env.MONGO_URI,{
    useNewUrlParser: true,
    useUnifiedTopology: true,
}
    ).then(() => {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`)
    })
}).catch((err) => console.log(err))