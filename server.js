require('dotenv').config();
const express = require('express');
const http = require('http');
const path = require('path');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret_in_production';
const MONGO_URI = process.env.MONGO_URI;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

mongoose
  .connect(MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB connection error:', err.message));

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, minlength: 3, maxlength: 20 },
  password: { type: String, required: true, minlength: 6 },
  createdAt: { type: Date, default: Date.now }
});
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});
userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};
const User = mongoose.model('User', userSchema);

const messageSchema = new mongoose.Schema({
  from: { type: String, required: true },
  text: { type: String, required: true, maxlength: 1000 },
  deleted: { type: Boolean, default: false },
  timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', messageSchema);

function createRateLimiter(maxAttempts, windowMs) {
  const attempts = new Map();
  return function (req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const record = attempts.get(ip);

    if (!record || now > record.resetAt) {
      attempts.set(ip, { count: 1, resetAt: now + windowMs });
      return next();
    }

    if (record.count >= maxAttempts) {
      const retryAfterSec = Math.ceil((record.resetAt - now) / 1000);
      return res.status(429).json({
        error: `Too many attempts. Try again in ${retryAfterSec}s.`
      });
    }

    record.count++;
    next();
  };
}
const authLimiter = createRateLimiter(8, 60 * 1000);

function validateCredentials(username, password) {
  if (!username || !password) return 'Username and password are required';
  if (typeof username !== 'string' || typeof password !== 'string') return 'Invalid input format';
  if (username.length < 3 || username.length > 20) return 'Username must be 3-20 characters';
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return 'Username can only contain letters, numbers, and underscores';
  if (password.length < 6) return 'Password must be at least 6 characters';
  return null;
}

app.post('/api/register', authLimiter, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const validationError = validateCredentials(username, password);
    if (validationError) return res.status(400).json({ error: validationError });

    const existing = await User.findOne({ username: username.toLowerCase() });
    if (existing) return res.status(409).json({ error: 'Username already taken' });

    const user = new User({ username, password });
    await user.save();

    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, username: user.username });
  } catch (err) {
    next(err);
  }
});

app.post('/api/login', authLimiter, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });

    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'Invalid username or password' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid username or password' });

    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username: user.username });
  } catch (err) {
    next(err);
  }
});

app.get('/api/messages', async (req, res, next) => {
  try {
    const messages = await Message.find({ deleted: false }).sort({ timestamp: -1 }).limit(50);
    res.json(messages.reverse());
  } catch (err) {
    next(err);
  }
});

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('Authentication required'));
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return next(new Error('Invalid or expired token'));
    socket.username = decoded.username;
    next();
  });
});

const messageWindows = new Map();

function isRateLimited(socketId, maxMessages = 5, windowMs = 10000) {
  const now = Date.now();
  const timestamps = (messageWindows.get(socketId) || []).filter(t => now - t < windowMs);

  if (timestamps.length >= maxMessages) {
    messageWindows.set(socketId, timestamps);
    return true;
  }

  timestamps.push(now);
  messageWindows.set(socketId, timestamps);
  return false;
}

const onlineUsers = new Map();

function broadcastOnlineUsers() {
  io.emit('onlineUsers', Array.from(onlineUsers.keys()));
}

io.on('connection', (socket) => {
  const { username } = socket;

  if (!onlineUsers.has(username)) {
    onlineUsers.set(username, new Set());
    socket.broadcast.emit('userJoined', { username, timestamp: Date.now() });
  }
  onlineUsers.get(username).add(socket.id);
  broadcastOnlineUsers();

  socket.on('sendMessage', async (text) => {
    try {
      if (typeof text !== 'string' || !text.trim()) return;

      if (isRateLimited(socket.id)) {
        socket.emit('errorMessage', { error: 'You are sending messages too fast. Please slow down.' });
        return;
      }

      const trimmedText = text.trim().slice(0, 1000);
      const message = new Message({ from: username, text: trimmedText });
      await message.save();

      io.emit('receiveMessage', {
        id: message._id,
        from: username,
        text: trimmedText,
        timestamp: message.timestamp
      });
    } catch (err) {
      console.error('Error saving message:', err.message);
      socket.emit('errorMessage', { error: 'Message could not be sent. Please try again.' });
    }
  });

  socket.on('deleteMessage', async (messageId) => {
    try {
      const message = await Message.findById(messageId);
      if (!message) return;

      if (message.from !== username) {
        socket.emit('errorMessage', { error: 'You can only delete your own messages.' });
        return;
      }

      const ageMs = Date.now() - new Date(message.timestamp).getTime();
      if (ageMs > 5 * 60 * 1000) {
        socket.emit('errorMessage', { error: 'Messages can only be deleted within 5 minutes of sending.' });
        return;
      }

      message.deleted = true;
      await message.save();
      io.emit('messageDeleted', { id: messageId });
    } catch (err) {
      console.error('Error deleting message:', err.message);
    }
  });

  socket.on('typing', () => socket.broadcast.emit('userTyping', { username }));
  socket.on('stopTyping', () => socket.broadcast.emit('userStopTyping', { username }));

  socket.on('disconnect', () => {
    messageWindows.delete(socket.id);

    const sockets = onlineUsers.get(username);
    if (sockets) {
      sockets.delete(socket.id);
      if (sockets.size === 0) {
        onlineUsers.delete(username);
        socket.broadcast.emit('userLeft', { username, timestamp: Date.now() });
      }
    }
    broadcastOnlineUsers();
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);

  if (err.name === 'ValidationError') {
    return res.status(400).json({ error: 'Invalid data provided' });
  }
  if (err.code === 11000) {
    return res.status(409).json({ error: 'That value is already in use' });
  }

  res.status(500).json({ error: 'Something went wrong on our end. Please try again.' });
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
