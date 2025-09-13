const jwt = require('jsonwebtoken');
const database = require('../database/connection');
const { auditLog } = require('../utils/audit');

// JWT Authentication Middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      error: 'Access token required',
      message: 'Please provide a valid access token'
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Get user from database to ensure they still exist and are approved
    const user = await database.get(
      'SELECT id, email, role, verified, admin_approved FROM users WHERE id = ?',
      [decoded.userId]
    );

    if (!user) {
      return res.status(401).json({
        error: 'Invalid token',
        message: 'User not found'
      });
    }

    if (!user.verified) {
      return res.status(403).json({
        error: 'Account not verified',
        message: 'Please verify your email address'
      });
    }

    if (!user.admin_approved) {
      return res.status(403).json({
        error: 'Account not approved',
        message: 'Your account is pending admin approval'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Token expired',
        message: 'Access token has expired'
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: 'Invalid token',
        message: 'Malformed access token'
      });
    }

    console.error('Token verification error:', error);
    return res.status(500).json({
      error: 'Authentication error',
      message: 'Failed to authenticate token'
    });
  }
};

// Role-based Authorization Middleware
const requireRole = (...roles) => {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'Please log in first'
      });
    }

    if (!roles.includes(req.user.role)) {
      await auditLog({
        userId: req.user.id,
        action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        resourceType: 'endpoint',
        details: JSON.stringify({
          endpoint: req.originalUrl,
          requiredRoles: roles,
          userRole: req.user.role
        }),
        ipAddress: req.ip
      });

      return res.status(403).json({
        error: 'Insufficient permissions',
        message: `Access denied. Required role: ${roles.join(' or ')}`
      });
    }

    next();
  };
};

// Workspace Access Middleware
const requireWorkspaceAccess = (accessLevel = 'read') => {
  return async (req, res, next) => {
    const workspaceId = req.params.workspaceId || req.body.workspaceId;
    
    if (!workspaceId) {
      return res.status(400).json({
        error: 'Workspace ID required',
        message: 'Workspace ID must be provided'
      });
    }

    try {
      // Check if user is workspace manager
      const workspace = await database.get(
        'SELECT id, manager_id FROM workspaces WHERE id = ?',
        [workspaceId]
      );

      if (!workspace) {
        return res.status(404).json({
          error: 'Workspace not found',
          message: 'The specified workspace does not exist'
        });
      }

      // Managers have full access to their workspaces
      if (workspace.manager_id === req.user.id) {
        req.userWorkspaceRole = 'manager';
        return next();
      }

      // Check workspace membership
      const membership = await database.get(`
        SELECT wm.*, u.role as user_role 
        FROM workspace_members wm
        JOIN users u ON u.id = wm.user_id
        WHERE wm.workspace_id = ? AND wm.user_id = ?
      `, [workspaceId, req.user.id]);

      if (!membership) {
        await auditLog({
          userId: req.user.id,
          action: 'UNAUTHORIZED_WORKSPACE_ACCESS',
          resourceType: 'workspace',
          resourceId: workspaceId,
          details: JSON.stringify({ accessLevel }),
          ipAddress: req.ip
        });

        return res.status(403).json({
          error: 'Access denied',
          message: 'You are not a member of this workspace'
        });
      }

      // Check if MFA is enabled for this workspace membership
      if (!membership.mfa_enabled) {
        return res.status(403).json({
          error: 'MFA required',
          message: 'Multi-factor authentication must be set up for workspace access'
        });
      }

      // Check access level
      if (accessLevel === 'write' && membership.access_level === 'read') {
        return res.status(403).json({
          error: 'Insufficient permissions',
          message: 'Write access required for this operation'
        });
      }

      req.userWorkspaceRole = 'member';
      req.workspaceAccess = membership.access_level;
      next();

    } catch (error) {
      console.error('Workspace access check error:', error);
      return res.status(500).json({
        error: 'Authorization error',
        message: 'Failed to verify workspace access'
      });
    }
  };
};

// MFA Workspace Session Middleware
const requireWorkspaceMFA = async (req, res, next) => {
  const workspaceId = req.params.workspaceId || req.body.workspaceId;
  
  if (!workspaceId) {
    return res.status(400).json({
      error: 'Workspace ID required'
    });
  }

  // Check if there's a valid MFA session for this workspace
  const mfaSession = req.headers['x-workspace-mfa-token'];
  
  if (!mfaSession) {
    return res.status(403).json({
      error: 'MFA verification required',
      message: 'Please verify MFA for workspace access'
    });
  }

  try {
    const decoded = jwt.verify(mfaSession, process.env.JWT_SECRET);
    
    if (decoded.workspaceId !== parseInt(workspaceId) || decoded.userId !== req.user.id) {
      return res.status(403).json({
        error: 'Invalid MFA session',
        message: 'MFA verification does not match current session'
      });
    }

    next();
  } catch (error) {
    return res.status(403).json({
      error: 'Invalid MFA session',
      message: 'MFA verification has expired or is invalid'
    });
  }
};

// Optional authentication (for public endpoints that can benefit from user context)
const optionalAuth = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await database.get(
        'SELECT id, email, role, verified, admin_approved FROM users WHERE id = ?',
        [decoded.userId]
      );

      if (user && user.verified && user.admin_approved) {
        req.user = user;
      }
    } catch (error) {
      // Ignore token errors for optional auth
    }
  }

  next();
};

// Rate limiting for sensitive operations
const sensitiveRateLimit = require('express-rate-limit')({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: {
    error: 'Too many sensitive operations',
    message: 'Please wait before trying again'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.user ? `${req.ip}-${req.user.id}` : req.ip;
  }
});

module.exports = {
  authenticateToken,
  requireRole,
  requireWorkspaceAccess,
  requireWorkspaceMFA,
  optionalAuth,
  sensitiveRateLimit
};