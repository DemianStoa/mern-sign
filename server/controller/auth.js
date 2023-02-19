import User from "../models/User.js"
import asyncHandler from "express-async-handler";
import jwt  from "jsonwebtoken"
import bcrypt  from "bcrypt"
import jwt_decode from "jwt-decode"
import Token  from "../models/Token.js"
import crypto  from "crypto"
import bcryt from 'bcrypt'
import {sendEmail}  from  "../utils/sendEmail.js"
import { OAuth2Client } from "google-auth-library";

// Generate Token
export const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
  };
  
  // Register User
export  const registerUser = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;
  
    // Validation
    if (!name || !email || !password) {
      res.status(400);
      throw new Error("Please fill in all required fields");
    }
    if (password.length < 6) {
      res.status(400);
      throw new Error("Password must be up to 6 characters");
    }
  
    // Check if user email already exists
    const userExists = await User.findOne({ email });
  
    if (userExists) {
      res.status(400);
      throw new Error("Email has already been registered");
    }

    //harsh password
    // const salt = await bcrypt.genSalt()
    // const passwordHash = await bcrypt.hash(password, salt)
  
    // Create new user
    const user = await User.create({
      name,
      email,
      password,
    });
  
    //   Generate Token
    const token = generateToken(user._id);
  
    // Send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: "none",
      secure: true,
    });
  
    if (user) {
      const { _id, name, email, avatar,  bio } = user;
      res.status(201).json({
        _id,
        name,
        email,
        avatar,
        
        bio,
        token,
      });
    } else {
      res.status(400);
      throw new Error("Invalid user data");
    }
  });
  
export const loginWithGoogle = asyncHandler(async (req, res) => {
    const { userToken } = req.body;

      const client = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID);

  const ticket = await client.verifyIdToken({
    idToken: userToken,
    audience: process.env.GOOGLE_CLIENT_ID,
  });
 
  const payload = ticket.getPayload();
  

    // payload = jwt_decode(userToken)
     console.log(payload)
    const { name, email, picture, sub } = payload;
    const password = Date.now() + sub;
    
  
    // Check if user exists
    const user = await User.findOne({ email });
  
    if (!user) {
      //   Create new user
      const newUser = await User.create({
        name,
        email,
        password,
        avatar: picture,
        isVerified: true,
      });
  
      if (newUser) {
        // Generate Token
        const token = generateToken(newUser._id);
  
        // Send HTTP-only cookie
        res.cookie("token", token, {
          path: "/",
          httpOnly: true,
          expires: new Date(Date.now() + 1000 * 86400), // 1 day
          sameSite: "none",
          secure: true,
        });
  
        const { _id, name, email, bio, avatar, role, isVerified } = newUser;
  
        res.status(201).json({
          _id,
          name,
          email,
          bio,
          avatar,
          role,
          isVerified,
          token,
        });
      }
    }
  
    // User exists, login
    if (user) {
      const token = generateToken(user._id);
  
      // Send HTTP-only cookie
      res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), // 1 day
        sameSite: "none",
        secure: true,
      });
  
      const { _id, name, email, bio, avatar, role, isVerified } = user;
  
      res.status(201).json({
        _id,
        name,
        email,
        bio,
        avatar,
        role,
        isVerified,
        token,
      });
    }
  });

  // Login User
export   const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;
  
    // Validate Request
    if (!email || !password) {
      res.status(400);
      throw new Error("Please add email and password");
    }
  
    // Check if user exists
    const user = await User.findOne({ email });
  
    if (!user) {
      res.status(400);
      throw new Error("User not found, please signup");
    }
  
    // User exists, check if password is correct
    const passwordIsCorrect = await bcrypt.compare(password, user.password);
    
    //   Generate Token
    const token = generateToken(user._id);
    console.log(password, user)
    
    if(passwordIsCorrect){
     // Send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: "none",
      secure: true,
    });
  }
    if (user && passwordIsCorrect) {
      const { _id, name, email, avatar,  bio, isVerified, role } = user;
      res.status(200).json({
        _id,
        name,
        email,
        bio,
        avatar,
        role,
        isVerified,
        token,
      });
    } else {
      res.status(400);
      throw new Error("Invalid email or password");
    }
  });

  // Logout User
export const logout = asyncHandler(async (req, res) => {
    res.cookie("token", "", {
      path: "/",
      httpOnly: true,
      expires: new Date(0),
      sameSite: "none",
      secure: true,
    });
    return res.status(200).json({ message: "Successfully Logged Out" });
  });

 export  const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User does not exist");
  }

  // Delete token if it exists in DB
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  // Create Reste Token
  let resetToken = crypto.randomBytes(32).toString("hex") + user._id;
  console.log(resetToken);

  // Hash token before saving to DB
  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // Save Token to DB
  await new Token({
    userId: user._id,
    token: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 30 * (60 * 1000), // Thirty minutes
  }).save();

  // Construct Reset Url
  const resetUrl = `${process.env.FRONTEND_URL}/resetpassword/${resetToken}`;

  // Reset Email
  const message = `
      <h2>Hello ${user.name}</h2>
      <p>Please use the url below to reset your password</p>  
      <p>This reset link is valid for only 30minutes.</p>

      <a href=${resetUrl} clicktracking=off>${resetUrl}</a>

      <p>Regards...</p>
      <p>Demian JS</p>
    `;
  const subject = "Password Reset Request";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;

  try {
    await sendEmail(subject, message, send_to, sent_from);
    res.status(200).json({ success: true, message: "Reset Email Sent" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again");
  }
});

// Reset Password
export const resetPassword = asyncHandler(async (req, res) => {
  const { password } = req.body;
  const { resetToken } = req.params;

  // Hash token, then compare to Token in DB
  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // fIND tOKEN in DB
  const userToken = await Token.findOne({
    token: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired Token");
  }

  // Find user
  const user = await User.findOne({ _id: userToken.userId });
  user.password = password;
  await user.save();
  res.status(200).json({
    message: "Password Reset Successful, Please Login",
  });
});

  // Get Login Status
  export const loginStatus = asyncHandler(async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
      return res.json(false);
    }
    // Verify Token
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    if (verified) {
      return res.json(true);
    }
    return res.json(false);
  });
  
