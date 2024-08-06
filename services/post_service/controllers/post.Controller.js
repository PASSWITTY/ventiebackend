import Post from '../models/Post.js';
import uploadToS3 from '../../../utils/fileUpload.js';
import DeletedPost from '../models/DeletedPost.js';


export const createPost = async (req, res) => {
  try {
    const { caption } = req.body;
    const imageUrl = await uploadToS3(req.file);
    
    const post = new Post({
      imageUrl,
      caption,
      user: req.user.id
    });
    
    await post.save();
    res.status(201).json({status:'200', message:'post created'});
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const getAllPosts = async (req, res) => {
  try {
    const posts = await Post.find().populate('user', 'username').sort('-createdAt');
    res.json(posts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const likePost = async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: 'Post not found' });

    const userId = req.user.id;
    if (post.likes.includes(userId)) {
      post.likes.pull(userId);
    } else {
      post.likes.push(userId);
    }

    await post.save();
    res.json({status:'200', message:'post liked'});
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const commentOnPost = async (req, res) => {
  try {
    const { text } = req.body;
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: 'Post not found' });

    post.comments.push({
      user: req.user.id,
      text
    });

    await post.save();
    res.status(201).json({status:'200', message:'coment posted'});
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const deletePost = async (req, res) => {
  try {
    const postId = req.params.id;
    const userId = req.user.id;

  
    const post = await Post.findById(postId);

    
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    
    if (post.user.toString() !== userId.toString()) {
      return res.status(403).json({ error: 'You do not have permission to delete this post' });
    }

    
    const deletedPost = new DeletedPost({
      originalPost: post._id,
      deletedBy: userId,
      postData: post.toObject()
    });

    await deletedPost.save();

    
    await Post.findByIdAndDelete(postId);

    res.json({ message: 'Post moved to deleted posts successfully' });
  } catch (error) {
    console.error('Error in deletePost:', error);
    res.status(500).json({ error: 'An error occurred while deleting the post' });
  }
};