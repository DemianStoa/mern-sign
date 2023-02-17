import express from "express"
import { protect } from "../middleWare/authChecker.js"
import {   getUser, updateUser, changePassword,  } from "../controller/user.js"


const router = express.Router()


router.get("/getuser", protect, getUser);
router.patch("/updateuser", protect, updateUser);
router.patch("/changepassword", protect, changePassword);


export default router;