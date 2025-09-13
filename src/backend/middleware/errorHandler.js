const { auditLog } = require('../utils/audit');

const errorHandler = (error, req, res, next) => {
  console.error('Error:', error);

  // Log error to audit trail
  if (req.user) {
    auditLog({
      userId: req.user.id,
      action: 'ERROR_OCCURRED',
      resourceType: 'system',
      details: JSON.stringify({
        error: error.message,
        stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
        url: req.originalUrl,
        method: req.method
      }),
      ipAddress: req.ip
    }).catch(() => {}); // Ignore audit log errors
  }

  // Handle specific error types
  if (error.name === 'ValidationError') {
    return res.status(400).json({
      error: 'Validation Error',
      message: error.message,
      details: error.details
    });
  }

  if (error.name === 'UnauthorizedError') {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Authentication failed'
    });
  }

  if (error.code === 'SQLITE_CONSTRAINT') {
    return res.status(400).json({
      error: 'Database Constraint Error',
      message: 'Operation violates database constraints'
    });
  }

  if (error.code === 'ENOENT') {
    return res.status(404).json({
      error: 'File Not Found',
      message: 'Requested file was not found'
    });
  }

  if (error.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({
      error: 'File Too Large',
      message: 'File exceeds maximum allowed size'
    });
  }

  // Default server error
  res.status(500).json({
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'production' 
      ? 'An unexpected error occurred'
      : error.message,
    ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
  });
};

module.exports = errorHandler;
