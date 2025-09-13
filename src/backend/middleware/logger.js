const { auditLog } = require('../utils/audit');

const logger = (req, res, next) => {
  const start = Date.now();
  
  // Log request
  const originalSend = res.send;
  res.send = function(data) {
    const duration = Date.now() - start;
    
    // Log API requests (but not health checks)
    if (req.originalUrl !== '/health' && req.originalUrl.startsWith('/api/')) {
      console.log(`${req.method} ${req.originalUrl} - ${res.statusCode} - ${duration}ms`);
      
      // Log sensitive operations
      if (['POST', 'PUT', 'DELETE'].includes(req.method) && req.user) {
        auditLog({
          userId: req.user.id,
          action: 'API_REQUEST',
          resourceType: 'endpoint',
          details: JSON.stringify({
            method: req.method,
            url: req.originalUrl,
            statusCode: res.statusCode,
            duration
          }),
          ipAddress: req.ip
        }).catch(() => {}); // Ignore audit log errors
      }
    }
    
    originalSend.call(this, data);
  };
  
  next();
};

module.exports = logger;