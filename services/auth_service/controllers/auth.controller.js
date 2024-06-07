import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/user.model.js';
import CreatorUser from '../models/creatorUser.model.js';
import { sendOTPEmail } from '../../../utils/email.utils.js';
import { generateOTP, verifyOTP } from '../../../utils/otp.utils.js';
import {Username} from '../../../utils/username.utils.js'

// User registration
const registerUser = async (req, res) => {
  try {
    const { phoneNumber, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ phoneNumber }, { email }] });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate OTP
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

    //Generate username
    const username = Username()


    // Create new user
    const newUser = new User({
      phoneNumber,
      email,
      username,
      password: hashedPassword,
      otp,
      otpExpiry
    });

    // Save user to database
    await newUser.save();

    // Send OTP to user's email
    await sendOTPEmail(email, otp);

    res.status(201).json({ message: 'User registered successfully. Please verify your OTP.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error register' });
  }
};

// User login
const loginUser = async (req, res) => {
  try {
    const { emailOrPhone, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ $or: [{ email: emailOrPhone }, { phoneNumber: emailOrPhone }] });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email/phone or password' });
    }

    // Check if password is correct
    const isPasswordValid = await bcrypt.compare(password, User.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid email/phone or password' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: User._id }, process.env.JWT_SECRET, { expiresIn: '30d' });


    User.token = token;
    await User.save();

    res.status(200).json({ status: 'success', userId: User._id, username: User.username, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: 'error',message: 'Internal server error' });
  }
};

// OTP verification
const verifymyOTP = async (req, res) => {
  try {
    const { otp } = req.body;

    // Verify OTP
    const isOTPValid = verifyOTP(otp, User.otp);
    if (!isOTPValid) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    // Check if OTP has expired
    const now = new Date();
    if (now > User.otpExpiry) {
      return res.status(400).json({ message: 'OTP has expired' });

    }
    const token = jwt.sign({ userId: User._id }, process.env.JWT_SECRET, { expiresIn: '30d' });
    // Update user's OTP and OTP expiry
    User.otp = null;
    User.otpExpiry = null;
    User.token = token;
    await User.save();
    

    res.status(200).json({ message: 'OTP verified successfully' , userId: User._id, username: User.username, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error OTP' });
  }
};
// Resend OTP
const resendOTP = async (req, res) => {
  try {
    const { email } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    // Generate new OTP
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // OTP expires in 10 minutes

    // Update user's OTP and OTP expiry
    
    User.otp = otp;
    User.otpExpiry = otpExpiry;
    await User.save();

    // Send new OTP to user's email
    await sendOTPEmail(email, otp);

    res.status(200).json({ message: 'New OTP sent to your email' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
};
// Reset password
const resetPassword = async (req, res) => {
  try {
    const { email } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    // Generate OTP
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // OTP expires in 10 minutes

    // Update user's OTP and OTP expiry
    User.otp = otp;
    User.otpExpiry = otpExpiry;
    await User.save();

    // Send OTP to user's email
    await sendOTPEmail(email, otp);

    res.status(200).json({ message: 'OTP sent to your email for password reset' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
};
//update forgot password
const updatePasswordWithOTP = async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    // Verify OTP
    const isOTPValid = verifyOTP(otp, User.otp);
    if (!isOTPValid) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    // Check if OTP has expired
    const now = new Date();
    if (now > User.otpExpiry) {
      return res.status(400).json({ message: 'OTP has expired' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    // Generate JWT token
    const token = jwt.sign({ userId: User._id }, process.env.JWT_SECRET, { expiresIn: '30d' });


    // Update user's password and reset OTP and OTP expiry
    User.password = hashedPassword;
    User.token = token
    User.otp = null;
    User.otpExpiry = null;
    await User.save();

    

    res.status(200).json({ status: 'success',  userId: User._id, username: User.username, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
};
// Update password
const updatePassword = async (req, res) => {
  try {
    const { userId, currentPassword, newPassword } = req.body;

    // Check if user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(400).json({ status: 'error', message: 'User not found' });
    }

    // Check if current password is correct
    const isPasswordValid = await bcrypt.compare(currentPassword, User.password);
    if (!isPasswordValid) {
      return res.status(400).json({ status: 'error', message: 'Current password is incorrect' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user's password
    User.password = hashedPassword;
    await User.save();

    res.status(200).json({ status: 'success', message: 'Password updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
};
// Creator user 
const createCreatorUser = async (req, res) => {
  try {
    const userId = req.body.userId;
    const fullName = req.body.fullName;
    const idNumber = req.body.idNumber;
    const address = req.body.address;

    // Extract the file paths from the request object
    const idFrontImage = req.files.idFrontImage[0].path;
    const idBackImage = req.files.idBackImage[0].path;
    const profileImage = req.files.profileImage[0].path;

    // Check if the user exists and is a general user (userType 0)
    const user = await User.findById(userId);
    if (!user || User.userType !== 0) {
      return res.status(400).json({ message: 'Already a creator' });
    }

    // Create a new creator user
    const newCreatorUser = new CreatorUser({
      fullName,
      idNumber,
      address,
      idFrontImage,
      idBackImage,
      profileImage,
    });

    // Save the creator user to the database
    await newCreatorUser.save();

    // Update the user's userType to 1 (creator)
    User.userType = 1;
    await User.save();

    res.status(201).json({ message: 'Creator user created successfully', usertype: User.userType, token:User.token , fullName : CreatorUser.fullName, profileImage: CreatorUser.profileImage  });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
};
//update user profile
const updateUserProfile = async (req, res) => {
  try {
    // Get the token
    const token = req.headers.authorization;

    // Check token
    if (!token) {
      return res.status(401).json({ status: 'error', message: 'No token provided' });
    }

    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.userId;

    // Check if user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ status: 'error', message: 'User not found' });
    }

    // Update bio
    if (req.body.bio) {
      User.bio = req.body.bio;
    }

    // Update profile picture
    if (req.file) {
      User.profilePicture = req.file.path;
    }

    await User.save();

    res.status(200).json({ status: 'success', message: 'User profile updated successfully' });
  } catch (err) {
    if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
      return res.status(401).json({ status: 'error', message: 'Invalid or expired token' });
    }
    console.error(err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
};
//Update creator profile
const updateCreatorProfile = async (req, res) => {
  try {
    // Get the token
    const token = req.headers.authorization;

    // Check token
    if (!token) {
      return res.status(401).json({ status: 'error', message: 'No token provided' });
    }

    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.userId;

    // Check if user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ status: 'error', message: 'User not found' });
    }

    // Update 
    if (req.body.address) {
      CreatorUser.address = req.body.address;
    }
    if (req.body.bankName) {
      CreatorUser.bankName = req.body.bankName;
    }
    if (req.body.mpesaNumber) {
      CreatorUser.mpesaNumber= req.body.mpesaNumber;
    }
    if (req.body.bankAccNumber) {
      CreatorUser.bankAccNumber= req.body.bankAccNumber;
    }
    
    await CreatorUser.save();

    res.status(200).json({ status: 'success', message: 'Creator profile updated successfully' });
  } catch (err) {
    if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
      return res.status(401).json({ status: 'error', message: 'Invalid or expired token' });
    }
    console.error(err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
};



export default { updateCreatorProfile, updateUserProfile, createCreatorUser, registerUser, loginUser, verifymyOTP, resendOTP, resetPassword, updatePasswordWithOTP, updatePassword};