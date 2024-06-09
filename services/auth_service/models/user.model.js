import mongoose from 'mongoose'

const userSchema = new mongoose.Schema({
  phoneNumber: { type: String, unique: true },
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  token: {type:String , require: true  },
  verified: {type: Boolean, default: false},
  userType: {type: Number, default: 0  },
  bio: {type: String, maxlength: 150},
  profilePicture: {type: String},
});

const User = mongoose.model('User', userSchema);

export default User;