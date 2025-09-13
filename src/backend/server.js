require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const workspaceRoutes = require('./routes/workspaces');
const fileRoutes = require('./routes/files');
const adminRoutes = require('./routes/admin');
const auditRoutes = require('./routes/audit');

// Import middleware
const errorHandler = require('./middleware/errorHandler');
const logger = require('./middleware/logger');

const app = express();
const PORT = process.env.PORT || 5000;

// Ensure upload directory exists
const uploadDir = process.env.UPLOAD_DIR || './uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// CORS configuration
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://yourdomain.com'] 
    : ['http://localhost:3000', 'http://localhost:3001'],
  credentials: true,
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging middleware
app.use(logger);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/workspaces', workspaceRoutes);
app.use('/api/files', fileRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/audit', auditRoutes);

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Resource not found',
    message: `Cannot ${req.method} ${req.originalUrl}`
  });
});

// Global error handler
app.use(errorHandler);

// Graceful shutdown handling
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
    process.exit(0);
  });
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`🚀 Forensic Analysis Platform API running on port ${PORT}`);
  console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔒 Security features enabled`);
  
  if (process.env.NODE_ENV !== 'production') {
    console.log(`📋 API Documentation available at http://localhost:${PORT}/health`);
  }
});

module.exports = app;