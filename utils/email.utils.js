import nodemailer from 'nodemailer';
import validator from 'validator'; // For email validation
import dotenv from 'dotenv'; // For loading environment variables
dotenv.config();

// SMTP Configuration (using App Password)
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465, // Use 465 for SSL
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS, // Use App Password
  },
});

// Email Template (using backticks for string interpolation)
const otpEmailTemplate = (otp) => `
<!DOCTYPE html>
<html>
<body>
  <p>Your OTP for verification is: <b>${otp}</b></p>
</body>
</html>
`;

// Rate Limiting (basic example - adjust as needed)
let emailsSent = 0;
const maxEmailsPerMinute = 5;

const sendOTPEmail = async (email, otp) => {
  try {
    // Input Validation
    if (!validator.isEmail(email)) {
      throw new Error('Invalid email address');
    }

    // Rate Limiting
    if (emailsSent >= maxEmailsPerMinute) {
      throw new Error('Too many emails sent recently. Please try again later.');
    }

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'OTP Verification',
      html: otpEmailTemplate(otp),
    };

    await transporter.sendMail(mailOptions);
    console.log('OTP email sent successfully');

    emailsSent++;
    setTimeout(() => {
      emailsSent--;
    }, 60000); // Reset counter after 1 minute
  } catch (error) {
    console.error('Failed to send OTP email:', error.message); // Log only the error message
  }
};

export { sendOTPEmail };
