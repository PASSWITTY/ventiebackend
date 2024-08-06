import express from 'express';
import authController from '../controllers/auth.controller.js';
import multer from 'multer';


const router = express.Router();
const upload = multer({ dest: 'uploads/' });


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

router.put('/update-password', authController.updatePassword);

router.post('/create-creator-user',
  upload.fields([{ name: 'idFrontImage', maxCount: 1 },{ name: 'idBackImage', maxCount: 1 },{ name: 'profileImage', maxCount: 1 }]), 
  authController.createCreatoruser
);


router.put('/update-user-profile',upload.single('profilePicture'),  authController.updateuserProfile);

router.put('/update-creator-profile', authController.updateCreatorProfile);

router.get('/all-user-details', authController.getUserDetails);

router.get('/all-creator-details', authController.getCreatorUserDetails);

export default router;
