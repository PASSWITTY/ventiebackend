import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from './user.model.js';
import { sendOTPEmail } from '../../utils/email.utils.js';
import { generateOTP, verifyOTP } from '../../utils/otp.utils.js';

// User registration
const registerUser = async (req, res) => {
  try {
    const { phoneNumber, email, username, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ phoneNumber }, { email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate OTP
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

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
      return res.status(400).json({ message: 'Invalid email/phone or password' });
    }

    // Check if password is correct
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid email/phone or password' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// OTP verification
const verifymyOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or OTP' });
    }

    // Verify OTP
    const isOTPValid = verifyOTP(otp, user.otp);
    if (!isOTPValid) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    // Check if OTP has expired
    const now = new Date();
    if (now > user.otpExpiry) {
      return res.status(400).json({ message: 'OTP has expired' });
    }

    // Update user's OTP and OTP expiry
    user.otp = null;
    user.otpExpiry = null;
    await user.save();

    res.status(200).json({ message: 'OTP verified successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
};

export default { registerUser, loginUser, verifymyOTP };