import express from 'express';
import authController from '../controllers/auth.controller.js';
import {uploadMiddlewarePP, uploadMiddlewareMM} from '../middlewares/uploadMiddleware.js';

const router = express.Router();

// User registration
router.post('/register', authController.registeruser);

// User login
router.post('/login', authController.loginuser);

// OTP verification
router.post('/verify-otp', authController.verifymyOTP);

//Otp resend
router.post('/resend-otp', authController.resendOTP);

router.post('/reset-pwd-otp', authController.resetPassword);

router.post('/update-forgot-pwd', authController.updatePasswordWithOTP);

router.post('/create-creator-user',uploadMiddlewareMM, authController.createCreatoruser);

router.put('/update-user-profile', uploadMiddlewarePP, authController.updateuserProfile);

router.put('/update-creator-profile', authController.updateCreatorProfile);

export default router;
