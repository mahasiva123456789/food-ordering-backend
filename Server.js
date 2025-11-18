import express from 'express';
import bodyParser from 'body-parser';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Security Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Body parser middleware with limits
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));


const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://Mahalakshmi:3T.8uqf84rhMmQq@cluster0.ajr0xpl.mongodb.net/Hello';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  retryWrites: true,
  w: 'majority'
})
.then(() => console.log("Connected to MongoDB successfully"))
.catch(err => console.error("MongoDB connection error:", err));


const itemSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: [true, 'Item name is required'],
    trim: true,
    maxlength: [100, 'Item name cannot exceed 100 characters']
  },
  price: { 
    type: Number, 
    required: [true, 'Item price is required'],
    min: [0, 'Price cannot be negative']
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters long'],
    maxlength: [30, 'Username cannot exceed 30 characters'],
    match: [/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers and underscores']
  },
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: { 
    type: String, 
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters long']
  },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  createdAt: { type: Date, default: Date.now }
});

const hotelSchema = new mongoose.Schema({
  hotelImage: { 
    type: String, 
    required: [true, 'Hotel image is required'],
    match: [/^https?:\/\/.+\.(jpg|jpeg|png|webp|gif)$/, 'Please provide a valid image URL']
  },
  hotelPlace: { 
    type: String, 
    required: [true, 'Hotel place is required'],
    trim: true,
    maxlength: [100, 'Hotel place cannot exceed 100 characters']
  },
  hotelRating: { 
    type: Number, 
    required: [true, 'Hotel rating is required'],
    min: [0, 'Rating cannot be less than 0'],
    max: [5, 'Rating cannot exceed 5']
  },
  hotelTime: { 
    type: String, 
    required: [true, 'Hotel time is required']
  },
  hotelPrice: { type: Number, min: [0, 'Price cannot be negative'] },
  description: { type: String, maxlength: [500, 'Description cannot exceed 500 characters'] },
  amenities: [String],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Models
const Item = mongoose.model('Item', itemSchema);
const User = mongoose.model('User', userSchema);
const Hotel = mongoose.model('Hotel', hotelSchema);

// Middleware to update timestamps
const updateTimestamp = function(next) {
  this.updatedAt = Date.now();
  next();
};

itemSchema.pre('save', updateTimestamp);
hotelSchema.pre('save', updateTimestamp);

// Input validation middleware
const validateItem = (req, res, next) => {
  const { name, price } = req.body;
  if (!name || !price) {
    return res.status(400).json({ success: false, message: 'Name and price are required' });
  }
  if (typeof price !== 'number' || price < 0) {
    return res.status(400).json({ success: false, message: 'Price must be a positive number' });
  }
  next();
};

const validateUser = (req, res, next) => {
  const { username, email, password } = req.body;
  const emailRegex = /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/;
  
  if (!username || !email || !password) {
    return res.status(400).json({ success: false, message: 'All fields are required' });
  }
  if (username.length < 3) {
    return res.status(400).json({ success: false, message: 'Username must be at least 3 characters long' });
  }
  if (!emailRegex.test(email)) {
    return res.status(400).json({ success: false, message: 'Please provide a valid email' });
  }
  if (password.length < 6) {
    return res.status(400).json({ success: false, message: 'Password must be at least 6 characters long' });
  }
  next();
};

// Authentication middleware (basic)
const authenticateUser = async (req, res, next) => {
  try {
    const { userId } = req.headers;
    
    if (!userId) {
      return res.status(401).json({ success: false, message: 'Authentication required' });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid user' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    res.status(500).json({ success: false, message: 'Authentication error', error: error.message });
  }
};

// Routes

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Server is running', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Item routes
app.post('/items', validateItem, async (req, res) => {
  try {
    const { name, price } = req.body;
    const newItem = new Item({ name, price });
    await newItem.save();
    res.status(201).json({ 
      success: true, 
      message: 'Item added successfully',
      data: newItem
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to add item', error: error.message });
  }
});

app.get('/items', async (req, res) => {
  try {
    const { page = 1, limit = 10, search } = req.query;
    const query = search ? { name: { $regex: search, $options: 'i' } } : {};
    
    const items = await Item.find(query)
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .sort({ createdAt: -1 });
    
    const total = await Item.countDocuments(query);
    
    res.json({
      success: true,
      data: items,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / limit),
        totalItems: total,
        itemsPerPage: parseInt(limit)
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch items', error: error.message });
  }
});

app.get('/items/:id', async (req, res) => {
  try {
    const item = await Item.findById(req.params.id);
    if (!item) {
      return res.status(404).json({ success: false, message: 'Item not found' });
    }
    res.json({ success: true, data: item });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch item', error: error.message });
  }
});

app.put('/items/:id', validateItem, async (req, res) => {
  try {
    const { name, price } = req.body;
    const updatedItem = await Item.findByIdAndUpdate(
      req.params.id,
      { name, price },
      { new: true, runValidators: true }
    );
    
    if (!updatedItem) {
      return res.status(404).json({ success: false, message: 'Item not found' });
    }
    
    res.json({ success: true, message: 'Item updated successfully', data: updatedItem });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to update item', error: error.message });
  }
});

app.delete('/items/:id', async (req, res) => {
  try {
    const deletedItem = await Item.findByIdAndDelete(req.params.id);
    if (!deletedItem) {
      return res.status(404).json({ success: false, message: 'Item not found' });
    }
    res.json({ success: true, message: 'Item deleted successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to delete item', error: error.message });
  }
});

app.delete('/items', async (req, res) => {
  try {
    const result = await Item.deleteMany({});
    res.json({ 
      success: true, 
      message: 'All items deleted successfully',
      deletedCount: result.deletedCount
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to delete all items', error: error.message });
  }
});

// Auth routes
app.post('/signup', validateUser, async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(409).json({ success: false, message: 'Username or email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();
    
    // Remove password from response
    const userResponse = { ...newUser.toObject() };
    delete userResponse.password;
    
    res.status(201).json({ 
      success: true, 
      message: 'User registered successfully',
      data: userResponse
    });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ success: false, message: 'Failed to register user', error: error.message });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password are required' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Remove password from response
    const userResponse = { ...user.toObject() };
    delete userResponse.password;

    res.json({ 
      success: true, 
      message: 'Login successful',
      data: userResponse
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error', error: error.message });
  }
});

// Hotel routes
app.get('/hotels', async (req, res) => {
  try {
    const { page = 1, limit = 10, place, minRating } = req.query;
    const query = {};
    
    if (place) query.hotelPlace = { $regex: place, $options: 'i' };
    if (minRating) query.hotelRating = { $gte: parseFloat(minRating) };
    
    const hotels = await Hotel.find(query)
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .sort({ hotelRating: -1, createdAt: -1 });
    
    const total = await Hotel.countDocuments(query);
    
    res.json({
      success: true,
      data: hotels,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / limit),
        totalItems: total,
        itemsPerPage: parseInt(limit)
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch hotels', error: error.message });
  }
});

app.post('/hotels', async (req, res) => {
  try {
    const { hotelImage, hotelPlace, hotelRating, hotelTime, hotelPrice, description, amenities } = req.body;
    const newHotel = new Hotel({ 
      hotelImage, 
      hotelPlace, 
      hotelRating, 
      hotelTime, 
      hotelPrice, 
      description, 
      amenities 
    });
    await newHotel.save();
    res.status(201).json({ 
      success: true, 
      message: 'Hotel added successfully',
      data: newHotel
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to add hotel', error: error.message });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ success: false, message: 'Something went wrong!' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

export default app;