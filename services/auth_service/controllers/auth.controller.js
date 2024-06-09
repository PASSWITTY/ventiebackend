import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/user.model.js';
import CreatorUser from '../models/creatorUser.model.js';
import { sendOTPEmail } from '../../../utils/email.utils.js';
import { generateOTP } from '../../../utils/otp.utils.js';
import {Username} from '../../../utils/username.utils.js'
//import client from '../../../config/redisClient.js';

const redisClient = createClient();
redisClient.on('error', (err) => console.error('Redis Client Error:', err));

(async () => {
  try {
    await redisClient.connect();
    console.log('Connected to Redis!');
  } catch (err) {
    console.error('Redis Connection Error:', err);
    process.exit(1);
  }
})();


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

    // Generate OTP and expiry
    const otp = generateOTP();
    const otpExpiry = Date.now() + 10 * 60 * 1000;

    //generate username
    const username = Username()

    // Create new user
    const newUser = new User({
      phoneNumber,
      email,
      password: hashedPassword,
      username,
      
    });

    // Save user to database
    await newUser.save();

    // Store OTP in Redis
    const otpKey = `otp:${newUser._id}`;
    await redisClient.setEx(otpKey, 600, otp); 

    // Send OTP to user's email
    await sendOTPEmail(email, otp);

    res.status(201).json({ message: 'User registered successfully. Please verify your OTP.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error during registration' });
  }
};

// OTP verification
const verifyOTP = async (req, res) => {
  try {
    const { otp } = req.body;

    // Retrieve OTP data from Redis
    const otpData = await redisClient.get(`otp:${otp}`);
    if (!otpData) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    const { userId, otpExpiry } = JSON.parse(otpData);

    // Check if OTP has expired
    if (Date.now() > otpExpiry) {
      await redisClient.del(`otp:${otp}`); // Delete expired OTP from Redis
      return res.status(400).json({ message: 'OTP has expired' });
    }

    // Retrieve user from the database
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Update user as verified and generate JWT token
    user.verified = true;
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '30d' });
    user.token = token;
    await user.save();

    // Delete OTP from Redis
    await redisClient.del(`otp:${otp}`);

    res.status(200).json({ message: 'OTP verified successfully',userId: user._id, username: user.username,  token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error during OTP verification' });
  }
};

// Resend OTP
const resendOTP = async (req, res) => {
  try {
    const { email } = req.body;

    // Retrieve user from the database
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate new OTP
    const otp = generateOTP();
    const otpExpiry = Date.now() + 10 * 60 * 1000; // OTP expires in 10 minutes

    // Update user's OTP and OTP expiry
    user.otp = otp;
    user.otpExpiry = otpExpiry;
    await user.save();

    // Store new OTP in Redis
    const otpKey = `otp:${otp}`;
    await redisClient.setEx(otpKey, 600, JSON.stringify({ userId: user._id, otpExpiry }));

    // Send new OTP to user's email
    await sendOTPEmail(user.email, otp);

    res.status(200).json({ message: 'New OTP sent to your email' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// User login
const loginUser = async (req, res) => {
  try {
    const { emailOrPhone, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ $or: [{ email: emailOrPhone }, { phoneNumber: emailOrPhone }] });
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    // Check if password is correct
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid password' });
    }

    // Check if user is verified
    if (!user.verified) {
      return res.status(403).json({ message: 'Please verify your account before logging in' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '30d' });

    res.status(200).json({ message: 'Login successful',userId: user._id, username: user.username,  token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
};



const sendPasswordResetOTP = async (req, res) => {
  try {
    const { email } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate OTP
    const otp = generateOTP();
    const otpExpiry = Date.now() + 10 * 60 * 1000;

    // Store OTP in Redis
    const otpKey = `passwordReset:${otp}`;
    await redisClient.setEx(otpKey, 600, JSON.stringify({ userId: user._id, otpExpiry }));

    // Send OTP to user's email
    await sendOTPEmail(email, otp, 'Password Reset');

    res.status(200).json({ message: 'Password reset OTP sent to your email' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
};

const resetPassword = async (req, res) => {
  try {
    const { otp, newPassword } = req.body;

    // Retrieve OTP data from Redis
    const otpData = await redisClient.get(`passwordReset:${otp}`);
    if (!otpData) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    const { userId, otpExpiry } = JSON.parse(otpData);

    // Check if OTP has expired
    if (Date.now() > otpExpiry) {
      await redisClient.del(`passwordReset:${otp}`);
      return res.status(400).json({ message: 'OTP has expired' });
    }

    // Retrieve user from the database
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user's password
    user.password = hashedPassword;
    await user.save();

    // Delete OTP from Redis
    await redisClient.del(`passwordReset:${otp}`);

    res.status(200).json({ message: 'Password reset successful', userId: user._id, username: user.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error during password reset' });
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
    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ status: 'error', message: 'Current password is incorrect' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user's password
    user.password = hashedPassword;
    await user.save();

    res.status(200).json({ status: 'success', message: 'Password updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
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
      user.bio = req.body.bio;
    }

    // Update profile picture
    if (req.file) {
      user.profilePicture = req.file.path;
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
    if (!user || user.userType !== 0) {
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
    user.userType = 1;
    await user.save();

    res.status(201).json({ message: 'Creator user created successfully', usertype: User.userType, fullName : newCreatorUser.fullName, profileImage: newCreatorUser.profileImage  });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
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



export default { updateCreatorProfile, updateUserProfile, createCreatorUser, registerUser, loginUser, verifyOTP, resendOTP, resetPassword, sendPasswordResetOTP, updatePassword};