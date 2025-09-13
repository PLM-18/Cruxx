const express = require('express');
const { body, param, validationResult } = require('express-validator');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const database = require('../database/connection');
const encryption = require('../utils/encryption');
const { auditLog } = require('../utils/audit');
const { authenticateToken, requireRole } = require('../middleware/auth');

const router = express.Router();

// Get current user profile
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await database.get(`
      SELECT id, name, surname, email, role, verified, admin_approved, created_at
      FROM users WHERE id = ?
    `, [req.user.id]);

    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'User profile not found'
      });
    }

    res.json({
      user: user
    });

  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      error: 'Failed to get profile',
      message: 'Internal server error'
    });
  }
});

// Update user profile
router.put('/profile', authenticateToken, [
  body('name').optional().trim().isLength({ min: 2, max: 100 }).withMessage('Name must be 2-100 characters'),
  body('surname').optional().trim().isLength({ min: 2, max: 100 }).withMessage('Surname must be 2-100 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { name, surname } = req.body;
    const updates = {};
    const params = [];
    
    if (name) {
      updates.name = name;
      params.push(name);
    }
    if (surname) {
      updates.surname = surname;
      params.push(surname);
    }

    if (params.length === 0) {
      return res.status(400).json({
        error: 'No updates provided',
        message: 'At least one field must be provided'
      });
    }

    // Build dynamic SQL
    const setClause = Object.keys(updates).map(key => `${key} = ?`).join(', ');
    params.push(req.user.id);

    await database.run(`
      UPDATE users SET ${setClause}, updated_at = CURRENT_TIMESTAMP 
      WHERE id = ?
    `, params);

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'PROFILE_UPDATED',
      resourceType: 'user',
      resourceId: req.user.id,
      details: JSON.stringify(updates),
      ipAddress: req.ip
    });

    res.json({
      message: 'Profile updated successfully',
      updates: updates
    });

  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({
      error: 'Failed to update profile',
      message: 'Internal server error'
    });
  }
});

// Change password
router.put('/password', authenticateToken, [
  body('currentPassword').notEmpty().withMessage('Current password required'),
  body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('New password must contain uppercase, lowercase, number and special character')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { currentPassword, newPassword } = req.body;

    // Get current password hash
    const user = await database.get('SELECT password_hash FROM users WHERE id = ?', [req.user.id]);
    
    if (!user) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    // Verify current password
    const isCurrentValid = await encryption.comparePassword(currentPassword, user.password_hash);
    
    if (!isCurrentValid) {
      await auditLog({
        userId: req.user.id,
        action: 'PASSWORD_CHANGE_FAILED',
        resourceType: 'user',
        details: JSON.stringify({ reason: 'invalid_current_password' }),
        ipAddress: req.ip
      });

      return res.status(400).json({
        error: 'Invalid current password',
        message: 'Current password is incorrect'
      });
    }

    // Hash new password
    const newPasswordHash = await encryption.hashPassword(newPassword);

    // Update password
    await database.run('UPDATE users SET password_hash = ? WHERE id = ?', [newPasswordHash, req.user.id]);

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'PASSWORD_CHANGED',
      resourceType: 'user',
      resourceId: req.user.id,
      ipAddress: req.ip
    });

    res.json({
      message: 'Password changed successfully'
    });

  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({
      error: 'Failed to change password',
      message: 'Internal server error'
    });
  }
});

// Setup MFA for workspace access
router.post('/setup-mfa/:workspaceId', authenticateToken, [
  param('workspaceId').isInt().withMessage('Valid workspace ID required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { workspaceId } = req.params;

    // Check if user is a member of this workspace
    const membership = await database.get(`
      SELECT wm.*, w.name as workspace_name, w.case_number
      FROM workspace_members wm
      JOIN workspaces w ON w.id = wm.workspace_id
      WHERE wm.workspace_id = ? AND wm.user_id = ?
    `, [workspaceId, req.user.id]);

    if (!membership) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You are not a member of this workspace'
      });
    }

    // Check if MFA is already enabled
    if (membership.mfa_enabled) {
      return res.status(400).json({
        error: 'MFA already enabled',
        message: 'Multi-factor authentication is already set up for this workspace'
      });
    }

    // Generate MFA secret
    const secret = speakeasy.generateSecret({
      name: `${req.user.email} - ${membership.workspace_name}`,
      issuer: process.env.APP_NAME || 'Forensic Analysis Platform',
      length: 32
    });

    // Generate QR code
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    // Store secret (temporarily, until verified)
    await database.run(`
      UPDATE workspace_members 
      SET mfa_secret = ? 
      WHERE workspace_id = ? AND user_id = ?
    `, [secret.base32, workspaceId, req.user.id]);

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'MFA_SETUP_INITIATED',
      resourceType: 'workspace',
      resourceId: workspaceId,
      details: JSON.stringify({ 
        workspaceName: membership.workspace_name,
        caseNumber: membership.case_number 
      }),
      ipAddress: req.ip
    });

    res.json({
      message: 'MFA setup initiated',
      secret: secret.base32,
      qrCode: qrCodeUrl,
      manualEntryKey: secret.base32,
      workspace: {
        id: workspaceId,
        name: membership.workspace_name,
        caseNumber: membership.case_number
      }
    });

  } catch (error) {
    console.error('MFA setup error:', error);
    res.status(500).json({
      error: 'MFA setup failed',
      message: 'Internal server error'
    });
  }
});

// Verify and enable MFA for workspace
router.post('/verify-mfa/:workspaceId', authenticateToken, [
  param('workspaceId').isInt().withMessage('Valid workspace ID required'),
  body('token').isLength({ min: 6, max: 6 }).isNumeric().withMessage('Valid MFA token required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { workspaceId } = req.params;
    const { token } = req.body;

    // Get membership with MFA secret
    const membership = await database.get(`
      SELECT wm.*, w.name as workspace_name
      FROM workspace_members wm
      JOIN workspaces w ON w.id = wm.workspace_id
      WHERE wm.workspace_id = ? AND wm.user_id = ? AND wm.mfa_secret IS NOT NULL
    `, [workspaceId, req.user.id]);

    if (!membership) {
      return res.status(404).json({
        error: 'MFA setup not found',
        message: 'MFA setup must be initiated first'
      });
    }

    if (membership.mfa_enabled) {
      return res.status(400).json({
        error: 'MFA already enabled',
        message: 'MFA is already enabled for this workspace'
      });
    }

    // Verify MFA token
    const verified = speakeasy.totp.verify({
      secret: membership.mfa_secret,
      encoding: 'base32',
      token: token,
      window: 2 // Allow some time drift during setup
    });

    if (!verified) {
      await auditLog({
        userId: req.user.id,
        action: 'MFA_VERIFICATION_FAILED',
        resourceType: 'workspace',
        resourceId: workspaceId,
        details: JSON.stringify({ reason: 'invalid_setup_token' }),
        ipAddress: req.ip
      });

      return res.status(400).json({
        error: 'Invalid MFA token',
        message: 'The provided MFA token is incorrect'
      });
    }

    // Enable MFA
    await database.run(`
      UPDATE workspace_members 
      SET mfa_enabled = TRUE 
      WHERE workspace_id = ? AND user_id = ?
    `, [workspaceId, req.user.id]);

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'MFA_ENABLED',
      resourceType: 'workspace',
      resourceId: workspaceId,
      details: JSON.stringify({ workspaceName: membership.workspace_name }),
      ipAddress: req.ip
    });

    res.json({
      message: 'MFA enabled successfully',
      mfaEnabled: true,
      workspace: {
        id: workspaceId,
        name: membership.workspace_name
      }
    });

  } catch (error) {
    console.error('MFA verification error:', error);
    res.status(500).json({
      error: 'MFA verification failed',
      message: 'Internal server error'
    });
  }
});

// Disable MFA for workspace (with confirmation)
router.delete('/mfa/:workspaceId', authenticateToken, [
  param('workspaceId').isInt().withMessage('Valid workspace ID required'),
  body('confirmationToken').isLength({ min: 6, max: 6 }).isNumeric().withMessage('Valid confirmation token required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { workspaceId } = req.params;
    const { confirmationToken } = req.body;

    // Get membership with MFA
    const membership = await database.get(`
      SELECT wm.*, w.name as workspace_name
      FROM workspace_members wm
      JOIN workspaces w ON w.id = wm.workspace_id
      WHERE wm.workspace_id = ? AND wm.user_id = ? AND wm.mfa_enabled = TRUE
    `, [workspaceId, req.user.id]);

    if (!membership) {
      return res.status(404).json({
        error: 'MFA not found',
        message: 'MFA is not enabled for this workspace'
      });
    }

    // Verify current MFA token before disabling
    const verified = speakeasy.totp.verify({
      secret: membership.mfa_secret,
      encoding: 'base32',
      token: confirmationToken,
      window: 1
    });

    if (!verified) {
      await auditLog({
        userId: req.user.id,
        action: 'MFA_DISABLE_FAILED',
        resourceType: 'workspace',
        resourceId: workspaceId,
        details: JSON.stringify({ reason: 'invalid_confirmation_token' }),
        ipAddress: req.ip
      });

      return res.status(400).json({
        error: 'Invalid confirmation token',
        message: 'MFA token verification failed'
      });
    }

    // Disable MFA
    await database.run(`
      UPDATE workspace_members 
      SET mfa_enabled = FALSE, mfa_secret = NULL 
      WHERE workspace_id = ? AND user_id = ?
    `, [workspaceId, req.user.id]);

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'MFA_DISABLED',
      resourceType: 'workspace',
      resourceId: workspaceId,
      details: JSON.stringify({ workspaceName: membership.workspace_name }),
      ipAddress: req.ip
    });

    res.json({
      message: 'MFA disabled successfully',
      mfaEnabled: false
    });

  } catch (error) {
    console.error('MFA disable error:', error);
    res.status(500).json({
      error: 'Failed to disable MFA',
      message: 'Internal server error'
    });
  }
});

// Get user's workspaces
router.get('/workspaces', authenticateToken, async (req, res) => {
  try {
    let workspaces;

    if (req.user.role === 'manager') {
      // Managers see their own workspaces
      workspaces = await database.all(`
        SELECT w.*, 
               (SELECT COUNT(*) FROM workspace_members wm WHERE wm.workspace_id = w.id) as member_count,
               (SELECT COUNT(*) FROM files f WHERE f.workspace_id = w.id) as file_count
        FROM workspaces w
        WHERE w.manager_id = ?
        ORDER BY w.created_at DESC
      `, [req.user.id]);
    } else {
      // Analysts see workspaces they're members of
      workspaces = await database.all(`
        SELECT w.*, wm.access_level, wm.mfa_enabled, wm.joined_at,
               u.name as manager_name, u.surname as manager_surname,
               (SELECT COUNT(*) FROM workspace_members wm2 WHERE wm2.workspace_id = w.id) as member_count,
               (SELECT COUNT(*) FROM files f WHERE f.workspace_id = w.id) as file_count
        FROM workspaces w
        JOIN workspace_members wm ON wm.workspace_id = w.id
        JOIN users u ON u.id = w.manager_id
        WHERE wm.user_id = ?
        ORDER BY w.created_at DESC
      `, [req.user.id]);
    }

    res.json({
      workspaces: workspaces
    });

  } catch (error) {
    console.error('Get workspaces error:', error);
    res.status(500).json({
      error: 'Failed to get workspaces',
      message: 'Internal server error'
    });
  }
});

// Get user activity summary
router.get('/activity', authenticateToken, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;

    const activities = await database.all(`
      SELECT action, resource_type, resource_id, details, timestamp, ip_address
      FROM audit_logs
      WHERE user_id = ?
      ORDER BY timestamp DESC
      LIMIT ? OFFSET ?
    `, [req.user.id, limit, offset]);

    // Get total count
    const { count } = await database.get(
      'SELECT COUNT(*) as count FROM audit_logs WHERE user_id = ?',
      [req.user.id]
    );

    res.json({
      activities: activities.map(activity => ({
        ...activity,
        details: activity.details ? JSON.parse(activity.details) : null
      })),
      pagination: {
        limit,
        offset,
        total: count
      }
    });

  } catch (error) {
    console.error('Get activity error:', error);
    res.status(500).json({
      error: 'Failed to get activity',
      message: 'Internal server error'
    });
  }
});

// Search users (for managers and admins)
router.get('/search', authenticateToken, requireRole('manager', 'admin'), [
  // Optional query parameters validation would go here
], async (req, res) => {
  try {
    const { q, role, verified, approved } = req.query;
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const offset = parseInt(req.query.offset) || 0;

    let whereClause = '1=1';
    let params = [];

    // Build search conditions
    if (q) {
      whereClause += ' AND (name LIKE ? OR surname LIKE ? OR email LIKE ?)';
      const searchTerm = `%${q}%`;
      params.push(searchTerm, searchTerm, searchTerm);
    }

    if (role) {
      whereClause += ' AND role = ?';
      params.push(role);
    }

    if (verified !== undefined) {
      whereClause += ' AND verified = ?';
      params.push(verified === 'true');
    }

    if (approved !== undefined) {
      whereClause += ' AND admin_approved = ?';
      params.push(approved === 'true');
    }

    // Exclude admin users from search (security)
    if (req.user.role !== 'admin') {
      whereClause += ' AND role != ?';
      params.push('admin');
    }

    const users = await database.all(`
      SELECT id, name, surname, email, role, verified, admin_approved, created_at
      FROM users
      WHERE ${whereClause}
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `, [...params, limit, offset]);

    res.json({
      users: users,
      pagination: {
        limit,
        offset,
        hasMore: users.length === limit
      }
    });

  } catch (error) {
    console.error('Search users error:', error);
    res.status(500).json({
      error: 'Failed to search users',
      message: 'Internal server error'
    });
  }
});

module.exports = router;