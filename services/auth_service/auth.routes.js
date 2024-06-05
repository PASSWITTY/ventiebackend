import express from 'express';
import authController from '../auth_service/auth.controller.js';

const router = express.Router();

// User registration
router.post('/register', authController.registerUser);

// User login
router.post('/login', authController.loginUser);

// OTP verification
router.post('/verify-otp', authController.verifymyOTP);

export default router;