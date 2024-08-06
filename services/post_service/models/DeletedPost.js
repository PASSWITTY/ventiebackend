import mongoose from 'mongoose';

const DeletedPostSchema = new mongoose.Schema({
  originalPost: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Post',
    required: true
  },
  deletedAt: {
    type: Date,
    default: Date.now
  },
  deletedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  postData: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  }
});

export default mongoose.model('DeletedPost', DeletedPostSchema);