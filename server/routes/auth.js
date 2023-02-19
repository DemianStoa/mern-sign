import express from "express"
import { loginUser, registerUser, logout, forgotPassword, resetPassword, 
    loginStatus, loginWithGoogle } from "../controller/auth.js"

 
const router = express.Router()

router.get("/logout", logout);
router.post('/login', loginUser);
router.post('/google', loginWithGoogle);
router.post('/register', registerUser);
router.post("/forgotpassword", forgotPassword);
router.put("/resetpassword/:resetToken", resetPassword);
router.get("/loggedin", loginStatus);


export default router;