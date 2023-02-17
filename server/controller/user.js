import User from "../models/User.js"
import asyncHandler from "express-async-handler";
import bcrypt  from "bcrypt"
  
  // Update User
  export const updateUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);
  
    if (user) {
      const { name, email, avatar,  bio } = user;
      user.email = email;
      user.name = req.body.name || name;
      user.bio = req.body.bio || bio;
      user.avatar = req.body.avatar || avatar;
  
      const updatedUser = await user.save();
      res.status(200).json({
        _id: updatedUser._id,
        name: updatedUser.name,
        email: updatedUser.email,
        avatar: updatedUser.avatar,
        bio: updatedUser.bio,
      });
    } else {
      res.status(404);
      throw new Error("User not found");
    }
  });
  
  export const changePassword = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);
    const { oldPassword, password } = req.body;
  
    if (!user) {
      res.status(400);
      throw new Error("User not found, please signup");
    }
    //Validate
    if (!oldPassword || !password) {
      res.status(400);
      throw new Error("Please add old and new password");
    }
  
    // check if old password matches password in DB
    const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);
  
    // Save new password
    if (user && passwordIsCorrect) {
      user.password = password;
      await user.save();
      res.status(200).send("Password change successful");
    } else {
      res.status(400);
      throw new Error("Old password is incorrect");
    }
  });

  export const getUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);
  
    if (user) {
      const { _id, name, email, avatar,  bio } = user;
      res.status(200).json({
        _id,
        name,
        email,
        avatar,
        
        bio,
      });
    } else {
      res.status(400);
      throw new Error("User Not Found");
    }
  });