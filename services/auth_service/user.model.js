import mongoose from 'mongoose'

const userSchema = new mongoose.Schema({
  phoneNumber: { type: String, unique: true },
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  otp: { type: String, default: null },
  otpExpiry: { type: Date, default: null },
});

const User = mongoose.model('User', userSchema);

export default User;