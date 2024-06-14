import mongoose from 'mongoose';

const creatorUserSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true,
  },
  fullName: {
    type: String,
    required: true,
  },
  idNumber: {
    type: String,
    required: true,
  },
  address: {
    type: String,
    required: true,
  },
  idFrontImage: {
    type: String,
    required: true,
  },
  idBackImage: {
    type: String,
    required: true,
  },
  profileImage: {
    type: String,
    required: true,
  },
  mpesaNumber: {
    type: Number
  },
  bankName: {
    type: String
  },
  bankAccNumber: {
   type: Number
  }
});

const CreatorUser = mongoose.model('CreatorUser', creatorUserSchema);

export default CreatorUser;