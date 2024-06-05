import crypto from 'crypto'

const generateOTP = () => {
  const otp = crypto.randomInt(100000, 999999).toString();
  return otp;
};

const verifyOTP = (inputOTP, storedOTP) => {
  return inputOTP === storedOTP;
};

export { generateOTP, verifyOTP };