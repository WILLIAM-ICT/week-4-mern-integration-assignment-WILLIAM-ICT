const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
require('dotenv').config();

// === CONFIG ===
const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/mern-blog';
const JWT_SECRET = process.env.JWT_SECRET || 'secret123';

app.use(cors());
app.use(express.json());

// === DATABASE ===
mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

// === MODELS ===
const userSchema = new mongoose.Schema({
  username: String,
  password: String
});
const User = mongoose.model('User', userSchema);

const postSchema = new mongoose.Schema({
  title: String,
  content: String,
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}, { timestamps: true });
const Post = mongoose.model('Post', postSchema);

// === MIDDLEWARE ===
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// === ROUTES ===
// Register
app.post('/api/users/register', async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hash });
  await user.save();
  res.json({ message: 'User created' });
});

// Login
app.post('/api/users/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ message: 'User not found' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ message: 'Invalid credentials' });

  const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1d' });
  res.json({ token });
});

// Create Post
app.post('/api/posts', auth, async (req, res) => {
  const { title, content } = req.body;
  const post = new Post({ title, content, author: req.userId });
  await post.save();
  res.json(post);
});

// Get All Posts
app.get('/api/posts', async (req, res) => {
  const posts = await Post.find().populate('author', 'username');
  res.json(posts);
});

// Get One Post
app.get('/api/posts/:id', async (req, res) => {
  const post = await Post.findById(req.params.id).populate('author', 'username');
  if (!post) return res.status(404).json({ message: 'Post not found' });
  res.json(post);
});

// Update Post
app.put('/api/posts/:id', auth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post) return res.status(404).json({ message: 'Post not found' });

  if (post.author.toString() !== req.userId) {
    return res.status(403).json({ message: 'Unauthorized' });
  }

  post.title = req.body.title || post.title;
  post.content = req.body.content || post.content;
  await post.save();
  res.json(post);
});

// Delete Post
app.delete('/api/posts/:id', auth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post) return res.status(404).json({ message: 'Post not found' });

  if (post.author.toString() !== req.userId) {
    return res.status(403).json({ message: 'Unauthorized' });
  }

  await post.remove();
  res.json({ message: 'Post deleted' });
});

// === START SERVER ===
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
