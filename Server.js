import express from 'express';
import bodyParser from 'body-parser';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';

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

// Rate limiting - Enhanced with different limits for different routes
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts, please try again later.'
});

app.use('/api/', generalLimiter);
app.use('/api/login', authLimiter);
app.use('/api/signup', authLimiter);

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

// Enhanced schemas with additional fields
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
  category: { type: String, default: 'general' },
  description: { type: String, maxlength: 500 },
  inStock: { type: Boolean, default: true },
  image: { type: String },
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
  profile: {
    firstName: String,
    lastName: String,
    phone: String,
    address: String
  },
  isActive: { type: Boolean, default: true },
  lastLogin: { type: Date },
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
  contact: {
    phone: String,
    email: String,
    website: String
  },
  location: {
    address: String,
    city: String,
    coordinates: {
      lat: Number,
      lng: Number
    }
  },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// NEW: Order Schema for food ordering functionality
const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [{
    itemId: { type: mongoose.Schema.Types.ObjectId, ref: 'Item' },
    name: String,
    price: Number,
    quantity: { type: Number, default: 1 },
    total: Number
  }],
  totalAmount: { type: Number, required: true },
  status: { 
    type: String, 
    enum: ['pending', 'confirmed', 'preparing', 'out for delivery', 'delivered', 'cancelled'],
    default: 'pending'
  },
  deliveryAddress: {
    street: String,
    city: String,
    state: String,
    zipCode: String,
    country: String
  },
  paymentMethod: { type: String, enum: ['cash', 'card', 'online'], default: 'cash' },
  paymentStatus: { type: String, enum: ['pending', 'paid', 'failed'], default: 'pending' },
  specialInstructions: String,
  estimatedDelivery: Date,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Models
const Item = mongoose.model('Item', itemSchema);
const User = mongoose.model('User', userSchema);
const Hotel = mongoose.model('Hotel', hotelSchema);
const Order = mongoose.model('Order', orderSchema); // NEW: Order model

// Middleware to update timestamps
const updateTimestamp = function(next) {
  this.updatedAt = Date.now();
  next();
};

itemSchema.pre('save', updateTimestamp);
hotelSchema.pre('save', updateTimestamp);
orderSchema.pre('save', updateTimestamp);

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Admin authorization middleware
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Admin access required' });
  }
  next();
};

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

// Routes

// Health check endpoint with more details
app.get('/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Server is running', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// API Routes with versioning
app.use('/api/v1', generalLimiter);

// Item routes with authentication
app.post('/api/v1/items', authenticateToken, requireAdmin, validateItem, async (req, res) => {
  try {
    const { name, price, category, description, image } = req.body;
    const newItem = new Item({ 
      name, 
      price, 
      category, 
      description, 
      image 
    });
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

app.get('/api/v1/items', async (req, res) => {
  try {
    const { page = 1, limit = 10, search, category, minPrice, maxPrice, inStock } = req.query;
    const query = {};
    
    if (search) query.name = { $regex: search, $options: 'i' };
    if (category) query.category = category;
    if (minPrice || maxPrice) {
      query.price = {};
      if (minPrice) query.price.$gte = parseFloat(minPrice);
      if (maxPrice) query.price.$lte = parseFloat(maxPrice);
    }
    if (inStock !== undefined) query.inStock = inStock === 'true';
    
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

// Enhanced item routes with authentication
app.get('/api/v1/items/:id', async (req, res) => {
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

app.put('/api/v1/items/:id', authenticateToken, requireAdmin, validateItem, async (req, res) => {
  try {
    const { name, price, category, description, inStock, image } = req.body;
    const updatedItem = await Item.findByIdAndUpdate(
      req.params.id,
      { name, price, category, description, inStock, image },
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

app.delete('/api/v1/items/:id', authenticateToken, requireAdmin, async (req, res) => {
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

// Auth routes with JWT
app.post('/api/v1/signup', validateUser, async (req, res) => {
  try {
    const { username, email, password, profile } = req.body;

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(409).json({ success: false, message: 'Username or email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = new User({ 
      username, 
      email, 
      password: hashedPassword,
      profile 
    });
    await newUser.save();
    
    // Generate JWT token
    const token = jwt.sign(
      { userId: newUser._id, username: newUser.username, role: newUser.role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );
    
    // Remove password from response
    const userResponse = { ...newUser.toObject() };
    delete userResponse.password;
    
    res.status(201).json({ 
      success: true, 
      message: 'User registered successfully',
      data: userResponse,
      token
    });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ success: false, message: 'Failed to register user', error: error.message });
  }
});

app.post('/api/v1/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password are required' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    if (!user.isActive) {
      return res.status(401).json({ success: false, message: 'Account is deactivated' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    // Remove password from response
    const userResponse = { ...user.toObject() };
    delete userResponse.password;

    res.json({ 
      success: true, 
      message: 'Login successful',
      data: userResponse,
      token
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error', error: error.message });
  }
});

// NEW: Order routes for food ordering system
app.post('/api/v1/orders', authenticateToken, async (req, res) => {
  try {
    const { items, deliveryAddress, paymentMethod, specialInstructions } = req.body;
    
    // Calculate total amount
    let totalAmount = 0;
    const orderItems = await Promise.all(
      items.map(async (item) => {
        const itemDetails = await Item.findById(item.itemId);
        const itemTotal = itemDetails.price * item.quantity;
        totalAmount += itemTotal;
        
        return {
          itemId: item.itemId,
          name: itemDetails.name,
          price: itemDetails.price,
          quantity: item.quantity,
          total: itemTotal
        };
      })
    );

    const newOrder = new Order({
      userId: req.user.userId,
      items: orderItems,
      totalAmount,
      deliveryAddress,
      paymentMethod,
      specialInstructions,
      estimatedDelivery: new Date(Date.now() + 45 * 60 * 1000) // 45 minutes from now
    });

    await newOrder.save();
    res.status(201).json({
      success: true,
      message: 'Order placed successfully',
      data: newOrder
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to place order', error: error.message });
  }
});

app.get('/api/v1/orders', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 10, status } = req.query;
    const query = { userId: req.user.userId };
    
    if (status) query.status = status;
    
    const orders = await Order.find(query)
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .sort({ createdAt: -1 })
      .populate('userId', 'username email');
    
    const total = await Order.countDocuments(query);
    
    res.json({
      success: true,
      data: orders,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / limit),
        totalItems: total,
        itemsPerPage: parseInt(limit)
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch orders', error: error.message });
  }
});

app.get('/api/v1/orders/:id', authenticateToken, async (req, res) => {
  try {
    const order = await Order.findOne({ 
      _id: req.params.id, 
      userId: req.user.userId 
    }).populate('userId', 'username email');
    
    if (!order) {
      return res.status(404).json({ success: false, message: 'Order not found' });
    }
    
    res.json({ success: true, data: order });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch order', error: error.message });
  }
});

// Hotel routes with enhanced features
app.get('/api/v1/hotels', async (req, res) => {
  try {
    const { page = 1, limit = 10, place, minRating, maxPrice, amenities } = req.query;
    const query = { isActive: true };
    
    if (place) query.hotelPlace = { $regex: place, $options: 'i' };
    if (minRating) query.hotelRating = { $gte: parseFloat(minRating) };
    if (maxPrice) query.hotelPrice = { $lte: parseFloat(maxPrice) };
    if (amenities) query.amenities = { $in: amenities.split(',') };
    
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

app.post('/api/v1/hotels', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { 
      hotelImage, 
      hotelPlace, 
      hotelRating, 
      hotelTime, 
      hotelPrice, 
      description, 
      amenities,
      contact,
      location
    } = req.body;
    
    const newHotel = new Hotel({ 
      hotelImage, 
      hotelPlace, 
      hotelRating, 
      hotelTime, 
      hotelPrice, 
      description, 
      amenities,
      contact,
      location
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

// NEW: User profile routes
app.get('/api/v1/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    res.json({ success: true, data: user });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch profile', error: error.message });
  }
});

app.put('/api/v1/profile', authenticateToken, async (req, res) => {
  try {
    const { profile } = req.body;
    const updatedUser = await User.findByIdAndUpdate(
      req.user.userId,
      { profile },
      { new: true, runValidators: true }
    ).select('-password');
    
    res.json({ success: true, message: 'Profile updated successfully', data: updatedUser });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to update profile', error: error.message });
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