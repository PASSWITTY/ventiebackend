import express from 'express';
import authController from '../controllers/auth.controller.js';
import {uploadMiddlewarePP, uploadMiddlewareMM} from '../middlewares/uploadMiddleware.js';

const router = express.Router();

// User registration
router.post('/register', authController.registerUser);

// User login
router.post('/login', authController.loginUser);

// OTP verification
router.post('/verify-otp', authController.verifymyOTP);

//Otp resend
router.post('/resend-otp', authController.resendOTP);

router.post('/reset-pwd-otp', authController.resetPassword);

router.post('/update-forgot-pwd', authController.updatePasswordWithOTP);

router.post('/create-creator-user',uploadMiddlewareMM, authController.createCreatorUser);

router.put('/update-user-profile', uploadMiddlewarePP, authController.updateUserProfile);

router.put('/update-creator-profile', authController.updateCreatorProfile);

export default router;
