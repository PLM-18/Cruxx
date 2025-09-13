const express = require('express');
const { body, param, validationResult } = require('express-validator');

const database = require('../database/connection');
const { auditLog } = require('../utils/audit');
const { authenticateToken, requireRole } = require('../middleware/auth');

const router = express.Router();

// Get pending user approvals
router.get('/pending-approvals', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const { limit = 50, offset = 0 } = req.query;

    const pendingUsers = await database.all(`
      SELECT id, name, surname, email, role, created_at, verified
      FROM users
      WHERE admin_approved = FALSE AND verified = TRUE
      ORDER BY created_at ASC
      LIMIT ? OFFSET ?
    `, [parseInt(limit), parseInt(offset)]);

    // Get total count
    const { total } = await database.get(`
      SELECT COUNT(*) as total FROM users 
      WHERE admin_approved = FALSE AND verified = TRUE
    `);

    res.json({
      pendingUsers: pendingUsers,
      pagination: {
        limit: parseInt(limit),
        offset: parseInt(offset),
        total: total,
        hasMore: parseInt(offset) + pendingUsers.length < total
      }
    });

  } catch (error) {
    console.error('Get pending approvals error:', error);
    res.status(500).json({
      error: 'Failed to get pending approvals',
      message: 'Internal server error'
    });
  }
});

// Approve user
router.post('/approve-user/:userId', authenticateToken, requireRole('admin'), [
  param('userId').isInt().withMessage('Valid user ID required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { userId } = req.params;

    // Get user details
    const user = await database.get(`
      SELECT id, name, surname, email, role, verified, admin_approved
      FROM users WHERE id = ?
    `, [userId]);

    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'The specified user does not exist'
      });
    }

    if (user.admin_approved) {
      return res.status(400).json({
        error: 'User already approved',
        message: 'This user is already approved'
      });
    }

    if (!user.verified) {
      return res.status(400).json({
        error: 'User not verified',
        message: 'User must verify their email before approval'
      });
    }

    // Approve user
    await database.run('UPDATE users SET admin_approved = TRUE WHERE id = ?', [userId]);

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'USER_APPROVED',
      resourceType: 'user',
      resourceId: userId,
      details: JSON.stringify({
        approvedUserEmail: user.email,
        approvedUserRole: user.role
      }),
      ipAddress: req.ip
    });

    // Also log for the approved user
    await auditLog({
      userId: parseInt(userId),
      action: 'ACCOUNT_APPROVED',
      resourceType: 'user',
      resourceId: parseInt(userId),
      details: JSON.stringify({
        approvedBy: req.user.email
      }),
      ipAddress: req.ip
    });

    res.json({
      message: 'User approved successfully',
      user: {
        id: user.id,
        name: user.name,
        surname: user.surname,
        email: user.email,
        role: user.role,
        approved: true
      }
    });

  } catch (error) {
    console.error('Approve user error:', error);
    res.status(500).json({
      error: 'Failed to approve user',
      message: 'Internal server error'
    });
  }
});

// Reject user application
router.post('/reject-user/:userId', authenticateToken, requireRole('admin'), [
  param('userId').isInt().withMessage('Valid user ID required'),
  body('reason').optional().trim().isLength({ max: 500 }).withMessage('Reason must be under 500 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { userId } = req.params;
    const { reason } = req.body;

    // Get user details
    const user = await database.get(`
      SELECT id, name, surname, email, role, verified, admin_approved
      FROM users WHERE id = ?
    `, [userId]);

    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'The specified user does not exist'
      });
    }

    if (user.admin_approved) {
      return res.status(400).json({
        error: 'User already approved',
        message: 'Cannot reject an approved user'
      });
    }

    // Delete user account (rejection)
    await database.run('DELETE FROM users WHERE id = ?', [userId]);

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'USER_REJECTED',
      resourceType: 'user',
      resourceId: userId,
      details: JSON.stringify({
        rejectedUserEmail: user.email,
        rejectedUserRole: user.role,
        reason: reason || 'No reason provided'
      }),
      ipAddress: req.ip
    });

    res.json({
      message: 'User application rejected and account deleted',
      reason: reason || 'No reason provided'
    });

  } catch (error) {
    console.error('Reject user error:', error);
    res.status(500).json({
      error: 'Failed to reject user',
      message: 'Internal server error'
    });
  }
});

// Get all users (with filters)
router.get('/users', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const { 
      role, 
      verified, 
      approved, 
      search,
      limit = 50, 
      offset = 0,
      sortBy = 'created_at',
      sortOrder = 'DESC'
    } = req.query;

    let whereConditions = [];
    let params = [];

    // Build WHERE clause
    if (role && ['admin', 'manager', 'analyst'].includes(role)) {
      whereConditions.push('role = ?');
      params.push(role);
    }

    if (verified !== undefined) {
      whereConditions.push('verified = ?');
      params.push(verified === 'true');
    }

    if (approved !== undefined) {
      whereConditions.push('admin_approved = ?');
      params.push(approved === 'true');
    }

    if (search) {
      whereConditions.push('(name LIKE ? OR surname LIKE ? OR email LIKE ?)');
      const searchTerm = `%${search}%`;
      params.push(searchTerm, searchTerm, searchTerm);
    }

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

    // Validate sort parameters
    const allowedSortBy = ['name', 'surname', 'email', 'role', 'created_at'];
    const allowedSortOrder = ['ASC', 'DESC'];
    
    const validSortBy = allowedSortBy.includes(sortBy) ? sortBy : 'created_at';
    const validSortOrder = allowedSortOrder.includes(sortOrder.toUpperCase()) ? sortOrder.toUpperCase() : 'DESC';

    const users = await database.all(`
      SELECT id, name, surname, email, role, verified, admin_approved, created_at, updated_at
      FROM users
      ${whereClause}
      ORDER BY ${validSortBy} ${validSortOrder}
      LIMIT ? OFFSET ?
    `, [...params, parseInt(limit), parseInt(offset)]);

    // Get total count
    const { total } = await database.get(`
      SELECT COUNT(*) as total FROM users ${whereClause}
    `, params);

    res.json({
      users: users,
      pagination: {
        limit: parseInt(limit),
        offset: parseInt(offset),
        total: total,
        hasMore: parseInt(offset) + users.length < total
      },
      filters: {
        role,
        verified,
        approved,
        search
      }
    });

  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      error: 'Failed to get users',
      message: 'Internal server error'
    });
  }
});

// Update user role
router.put('/users/:userId/role', authenticateToken, requireRole('admin'), [
  param('userId').isInt().withMessage('Valid user ID required'),
  body('role').isIn(['analyst', 'manager']).withMessage('Role must be analyst or manager')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { userId } = req.params;
    const { role } = req.body;

    // Get current user details
    const user = await database.get(`
      SELECT id, name, surname, email, role as current_role
      FROM users WHERE id = ?
    `, [userId]);

    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'The specified user does not exist'
      });
    }

    // Prevent changing admin roles
    if (user.current_role === 'admin') {
      return res.status(403).json({
        error: 'Cannot modify admin role',
        message: 'Admin user roles cannot be changed'
      });
    }

    if (user.current_role === role) {
      return res.status(400).json({
        error: 'No change needed',
        message: 'User already has this role'
      });
    }

    // Update role
    await database.run('UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [role, userId]);

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'USER_ROLE_CHANGED',
      resourceType: 'user',
      resourceId: userId,
      details: JSON.stringify({
        userEmail: user.email,
        oldRole: user.current_role,
        newRole: role
      }),
      ipAddress: req.ip
    });

    // Also log for the affected user
    await auditLog({
      userId: parseInt(userId),
      action: 'ROLE_CHANGED',
      resourceType: 'user',
      resourceId: parseInt(userId),
      details: JSON.stringify({
        oldRole: user.current_role,
        newRole: role,
        changedBy: req.user.email
      }),
      ipAddress: req.ip
    });

    res.json({
      message: 'User role updated successfully',
      user: {
        id: user.id,
        email: user.email,
        oldRole: user.current_role,
        newRole: role
      }
    });

  } catch (error) {
    console.error('Update user role error:', error);
    res.status(500).json({
      error: 'Failed to update user role',
      message: 'Internal server error'
    });
  }
});

// Suspend user account
router.post('/users/:userId/suspend', authenticateToken, requireRole('admin'), [
  param('userId').isInt().withMessage('Valid user ID required'),
  body('reason').optional().trim().isLength({ max: 500 }).withMessage('Reason must be under 500 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { userId } = req.params;
    const { reason } = req.body;

    // Get user details
    const user = await database.get(`
      SELECT id, name, surname, email, role, admin_approved
      FROM users WHERE id = ?
    `, [userId]);

    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'The specified user does not exist'
      });
    }

    // Prevent suspending admin users
    if (user.role === 'admin') {
      return res.status(403).json({
        error: 'Cannot suspend admin',
        message: 'Admin users cannot be suspended'
      });
    }

    if (!user.admin_approved) {
      return res.status(400).json({
        error: 'User already suspended',
        message: 'User account is already suspended (not approved)'
      });
    }

    // Suspend user (set admin_approved to false)
    await database.run('UPDATE users SET admin_approved = FALSE WHERE id = ?', [userId]);

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'USER_SUSPENDED',
      resourceType: 'user',
      resourceId: userId,
      details: JSON.stringify({
        suspendedUserEmail: user.email,
        suspendedUserRole: user.role,
        reason: reason || 'No reason provided'
      }),
      ipAddress: req.ip
    });

    // Also log for the suspended user
    await auditLog({
      userId: parseInt(userId),
      action: 'ACCOUNT_SUSPENDED',
      resourceType: 'user',
      resourceId: parseInt(userId),
      details: JSON.stringify({
        suspendedBy: req.user.email,
        reason: reason || 'No reason provided'
      }),
      ipAddress: req.ip
    });

    res.json({
      message: 'User account suspended successfully',
      reason: reason || 'No reason provided'
    });

  } catch (error) {
    console.error('Suspend user error:', error);
    res.status(500).json({
      error: 'Failed to suspend user',
      message: 'Internal server error'
    });
  }
});

// Get system statistics
router.get('/statistics', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    // User statistics
    const userStats = await database.all(`
      SELECT 
        role,
        COUNT(*) as count,
        SUM(CASE WHEN verified = TRUE THEN 1 ELSE 0 END) as verified_count,
        SUM(CASE WHEN admin_approved = TRUE THEN 1 ELSE 0 END) as approved_count
      FROM users
      GROUP BY role
    `);

    // Workspace statistics
    const { workspace_count } = await database.get('SELECT COUNT(*) as workspace_count FROM workspaces');
    const { file_count } = await database.get('SELECT COUNT(*) as file_count FROM files');
    const { total_file_size } = await database.get('SELECT COALESCE(SUM(file_size), 0) as total_file_size FROM files');

    // Activity statistics (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const recentActivity = await database.all(`
      SELECT 
        action,
        COUNT(*) as count
      FROM audit_logs
      WHERE timestamp >= ?
      GROUP BY action
      ORDER BY count DESC
      LIMIT 10
    `, [thirtyDaysAgo.toISOString()]);

    // Monthly activity trend (last 12 months)
    const twelveMonthsAgo = new Date();
    twelveMonthsAgo.setMonth(twelveMonthsAgo.getMonth() - 12);

    const monthlyActivity = await database.all(`
      SELECT 
        strftime('%Y-%m', timestamp) as month,
        COUNT(*) as activity_count
      FROM audit_logs
      WHERE timestamp >= ?
      GROUP BY strftime('%Y-%m', timestamp)
      ORDER BY month ASC
    `, [twelveMonthsAgo.toISOString()]);

    res.json({
      users: {
        byRole: userStats,
        totalUsers: userStats.reduce((sum, stat) => sum + stat.count, 0),
        totalVerified: userStats.reduce((sum, stat) => sum + stat.verified_count, 0),
        totalApproved: userStats.reduce((sum, stat) => sum + stat.approved_count, 0)
      },
      workspaces: {
        total: workspace_count
      },
      files: {
        total: file_count,
        totalSize: total_file_size,
        averageSize: file_count > 0 ? Math.round(total_file_size / file_count) : 0
      },
      activity: {
        recent: recentActivity,
        monthlyTrend: monthlyActivity
      }
    });

  } catch (error) {
    console.error('Get statistics error:', error);
    res.status(500).json({
      error: 'Failed to get statistics',
      message: 'Internal server error'
    });
  }
});

// Get system audit logs
router.get('/audit-logs', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const { 
      action,
      resourceType,
      userId,
      startDate,
      endDate,
      limit = 100,
      offset = 0
    } = req.query;

    let whereConditions = [];
    let params = [];

    // Build WHERE clause
    if (action) {
      whereConditions.push('action = ?');
      params.push(action);
    }

    if (resourceType) {
      whereConditions.push('resource_type = ?');
      params.push(resourceType);
    }

    if (userId) {
      whereConditions.push('user_id = ?');
      params.push(parseInt(userId));
    }

    if (startDate) {
      whereConditions.push('timestamp >= ?');
      params.push(new Date(startDate).toISOString());
    }

    if (endDate) {
      whereConditions.push('timestamp <= ?');
      params.push(new Date(endDate).toISOString());
    }

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

    const auditLogs = await database.all(`
      SELECT al.*, u.email as user_email, u.name as user_name, u.surname as user_surname
      FROM audit_logs al
      LEFT JOIN users u ON u.id = al.user_id
      ${whereClause}
      ORDER BY al.timestamp DESC
      LIMIT ? OFFSET ?
    `, [...params, parseInt(limit), parseInt(offset)]);

    // Get total count
    const { total } = await database.get(`
      SELECT COUNT(*) as total FROM audit_logs ${whereClause}
    `, params);

    res.json({
      auditLogs: auditLogs.map(log => ({
        ...log,
        details: log.details ? JSON.parse(log.details) : null
      })),
      pagination: {
        limit: parseInt(limit),
        offset: parseInt(offset),
        total: total,
        hasMore: parseInt(offset) + auditLogs.length < total
      }
    });

  } catch (error) {
    console.error('Get audit logs error:', error);
    res.status(500).json({
      error: 'Failed to get audit logs',
      message: 'Internal server error'
    });
  }
});

// Delete user account permanently
router.delete('/users/:userId', authenticateToken, requireRole('admin'), [
  param('userId').isInt().withMessage('Valid user ID required'),
  body('confirmEmail').isEmail().withMessage('Valid confirmation email required'),
  body('reason').optional().trim().isLength({ max: 500 }).withMessage('Reason must be under 500 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { userId } = req.params;
    const { confirmEmail, reason } = req.body;

    // Get user details
    const user = await database.get(`
      SELECT id, name, surname, email, role
      FROM users WHERE id = ?
    `, [userId]);

    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'The specified user does not exist'
      });
    }

    // Prevent deleting admin users
    if (user.role === 'admin') {
      return res.status(403).json({
        error: 'Cannot delete admin',
        message: 'Admin users cannot be deleted'
      });
    }

    // Verify email confirmation
    if (user.email !== confirmEmail) {
      return res.status(400).json({
        error: 'Email confirmation mismatch',
        message: 'The confirmation email does not match the user email'
      });
    }

    // Check if user owns any workspaces
    const { workspace_count } = await database.get(
      'SELECT COUNT(*) as workspace_count FROM workspaces WHERE manager_id = ?',
      [userId]
    );

    if (workspace_count > 0) {
      return res.status(400).json({
        error: 'User has workspaces',
        message: 'Cannot delete user who manages workspaces. Transfer ownership first.'
      });
    }

    // Get file count for audit
    const { file_count } = await database.get(
      'SELECT COUNT(*) as file_count FROM files WHERE owner_id = ?',
      [userId]
    );

    // Delete user (cascading deletes will handle related records)
    await database.run('DELETE FROM users WHERE id = ?', [userId]);

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'USER_DELETED',
      resourceType: 'user',
      resourceId: userId,
      details: JSON.stringify({
        deletedUserEmail: user.email,
        deletedUserRole: user.role,
        fileCount: file_count,
        reason: reason || 'No reason provided'
      }),
      ipAddress: req.ip
    });

    res.json({
      message: 'User account deleted successfully',
      deletedUser: {
        email: user.email,
        role: user.role
      },
      deletedFiles: file_count,
      reason: reason || 'No reason provided'
    });

  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({
      error: 'Failed to delete user',
      message: 'Internal server error'
    });
  }
});

// System maintenance operations
router.post('/maintenance/cleanup-temp-files', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const fs = require('fs').promises;
    const path = require('path');

    const tempDir = path.join(process.env.UPLOAD_DIR || './uploads', 'temp');
    let cleanedCount = 0;
    let totalSize = 0;

    try {
      const files = await fs.readdir(tempDir);
      const oneHourAgo = Date.now() - (60 * 60 * 1000);

      for (const file of files) {
        const filePath = path.join(tempDir, file);
        const stats = await fs.stat(filePath);
        
        if (stats.mtime.getTime() < oneHourAgo) {
          totalSize += stats.size;
          await fs.unlink(filePath);
          cleanedCount++;
        }
      }
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'MAINTENANCE_CLEANUP_TEMP',
      resourceType: 'system',
      details: JSON.stringify({
        cleanedFiles: cleanedCount,
        totalSize: totalSize
      }),
      ipAddress: req.ip
    });

    res.json({
      message: 'Temporary files cleanup completed',
      cleanedFiles: cleanedCount,
      freedSpace: totalSize
    });

  } catch (error) {
    console.error('Cleanup temp files error:', error);
    res.status(500).json({
      error: 'Cleanup failed',
      message: 'Internal server error'
    });
  }
});

// System health check
router.get('/health', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const fs = require('fs').promises;
    const path = require('path');

    // Check database connectivity
    const dbCheck = await database.get('SELECT 1 as test');
    const dbHealthy = dbCheck && dbCheck.test === 1;

    // Check upload directory
    const uploadDir = process.env.UPLOAD_DIR || './uploads';
    let uploadDirHealthy = false;
    let uploadDirSpace = 0;

    try {
      await fs.access(uploadDir);
      const stats = await fs.stat(uploadDir);
      uploadDirHealthy = stats.isDirectory();
      
      // Get directory size (simplified)
      const files = await database.all('SELECT file_size FROM files WHERE file_size IS NOT NULL');
      uploadDirSpace = files.reduce((sum, file) => sum + file.file_size, 0);
    } catch (error) {
      console.warn('Upload directory check failed:', error);
    }

    // Check recent activity
    const oneDayAgo = new Date();
    oneDayAgo.setDate(oneDayAgo.getDate() - 1);
    
    const { recent_activity_count } = await database.get(`
      SELECT COUNT(*) as recent_activity_count 
      FROM audit_logs 
      WHERE timestamp >= ?
    `, [oneDayAgo.toISOString()]);

    // Get system uptime (approximate)
    const uptimeSeconds = process.uptime();

    const healthStatus = {
      status: dbHealthy && uploadDirHealthy ? 'healthy' : 'degraded',
      timestamp: new Date().toISOString(),
      checks: {
        database: {
          status: dbHealthy ? 'healthy' : 'error',
          message: dbHealthy ? 'Database connection successful' : 'Database connection failed'
        },
        uploadDirectory: {
          status: uploadDirHealthy ? 'healthy' : 'error',
          message: uploadDirHealthy ? 'Upload directory accessible' : 'Upload directory not accessible',
          usedSpace: uploadDirSpace
        },
        recentActivity: {
          count: recent_activity_count,
          message: `${recent_activity_count} activities in the last 24 hours`
        }
      },
      system: {
        uptime: Math.floor(uptimeSeconds),
        nodeVersion: process.version,
        platform: process.platform
      }
    };

    res.json(healthStatus);

  } catch (error) {
    console.error('Health check error:', error);
    res.status(500).json({
      status: 'error',
      timestamp: new Date().toISOString(),
      error: 'Health check failed',
      message: 'Internal server error'
    });
  }
});

module.exports = router;