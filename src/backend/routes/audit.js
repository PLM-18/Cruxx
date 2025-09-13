const express = require('express');
const { query, validationResult } = require('express-validator');

const database = require('../database/connection');
const { authenticateToken, requireRole } = require('../middleware/auth');

const router = express.Router();

// Get user's own audit logs
router.get('/logs', authenticateToken, [
  query('limit').optional().isInt({ min: 1, max: 1000 }).withMessage('Limit must be between 1 and 1000'),
  query('offset').optional().isInt({ min: 0 }).withMessage('Offset must be non-negative'),
  query('action').optional().isString().withMessage('Action must be a string'),
  query('resourceType').optional().isString().withMessage('Resource type must be a string'),
  query('startDate').optional().isISO8601().withMessage('Start date must be valid ISO date'),
  query('endDate').optional().isISO8601().withMessage('End date must be valid ISO date')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { 
      limit = 50, 
      offset = 0, 
      action, 
      resourceType, 
      startDate, 
      endDate 
    } = req.query;

    let whereConditions = ['user_id = ?'];
    let params = [req.user.id];

    // Build WHERE clause
    if (action) {
      whereConditions.push('action = ?');
      params.push(action);
    }

    if (resourceType) {
      whereConditions.push('resource_type = ?');
      params.push(resourceType);
    }

    if (startDate) {
      whereConditions.push('timestamp >= ?');
      params.push(new Date(startDate).toISOString());
    }

    if (endDate) {
      whereConditions.push('timestamp <= ?');
      params.push(new Date(endDate).toISOString());
    }

    const whereClause = `WHERE ${whereConditions.join(' AND ')}`;

    const logs = await database.all(`
      SELECT id, action, resource_type, resource_id, details, ip_address, timestamp
      FROM audit_logs
      ${whereClause}
      ORDER BY timestamp DESC
      LIMIT ? OFFSET ?
    `, [...params, parseInt(limit), parseInt(offset)]);

    // Get total count for pagination
    const { total } = await database.get(`
      SELECT COUNT(*) as total FROM audit_logs ${whereClause}
    `, params);

    // Parse details JSON
    const processedLogs = logs.map(log => ({
      ...log,
      details: log.details ? JSON.parse(log.details) : null
    }));

    res.json({
      logs: processedLogs,
      pagination: {
        limit: parseInt(limit),
        offset: parseInt(offset),
        total: total,
        hasMore: parseInt(offset) + logs.length < total
      },
      filters: {
        action,
        resourceType,
        startDate,
        endDate
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

// Get workspace audit logs (Manager and members)
router.get('/workspace/:workspaceId', authenticateToken, [
  query('limit').optional().isInt({ min: 1, max: 1000 }).withMessage('Limit must be between 1 and 1000'),
  query('offset').optional().isInt({ min: 0 }).withMessage('Offset must be non-negative'),
  query('action').optional().isString().withMessage('Action must be a string'),
  query('userId').optional().isInt().withMessage('User ID must be integer')
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
    const { limit = 50, offset = 0, action, userId } = req.query;

    // Check workspace access
    const hasAccess = await database.get(`
      SELECT 1 FROM workspaces w
      WHERE w.id = ? AND w.manager_id = ?
      UNION
      SELECT 1 FROM workspace_members wm
      WHERE wm.workspace_id = ? AND wm.user_id = ?
    `, [workspaceId, req.user.id, workspaceId, req.user.id]);

    if (!hasAccess) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You do not have access to this workspace'
      });
    }

    let whereConditions = [
      '(resource_type = ? AND resource_id = ?)',
      'OR (action IN (?, ?, ?, ?) AND JSON_EXTRACT(details, "$.workspaceId") = ?)'
    ];
    let params = [
      'workspace', workspaceId,
      'FILE_UPLOADED', 'FILE_DOWNLOADED', 'FILE_DELETED', 'NOTE_CREATED', workspaceId
    ];

    // Additional filters
    if (action) {
      whereConditions = [`(${whereConditions.join(' ')}) AND action = ?`];
      params.push(action);
    }

    if (userId) {
      whereConditions.push('user_id = ?');
      params.push(parseInt(userId));
    }

    const whereClause = `WHERE ${whereConditions.join(' AND ')}`;

    const logs = await database.all(`
      SELECT al.id, al.action, al.resource_type, al.resource_id, al.details, 
             al.ip_address, al.timestamp,
             u.name as user_name, u.surname as user_surname, u.email as user_email, u.role as user_role
      FROM audit_logs al
      LEFT JOIN users u ON u.id = al.user_id
      ${whereClause}
      ORDER BY al.timestamp DESC
      LIMIT ? OFFSET ?
    `, [...params, parseInt(limit), parseInt(offset)]);

    // Get total count
    const { total } = await database.get(`
      SELECT COUNT(*) as total FROM audit_logs al ${whereClause}
    `, params);

    // Process logs
    const processedLogs = logs.map(log => ({
      id: log.id,
      action: log.action,
      resourceType: log.resource_type,
      resourceId: log.resource_id,
      details: log.details ? JSON.parse(log.details) : null,
      ipAddress: log.ip_address,
      timestamp: log.timestamp,
      user: log.user_name ? {
        name: log.user_name,
        surname: log.user_surname,
        email: log.user_email,
        role: log.user_role
      } : null
    }));

    res.json({
      workspaceId: parseInt(workspaceId),
      logs: processedLogs,
      pagination: {
        limit: parseInt(limit),
        offset: parseInt(offset),
        total: total,
        hasMore: parseInt(offset) + logs.length < total
      }
    });

  } catch (error) {
    console.error('Get workspace audit logs error:', error);
    res.status(500).json({
      error: 'Failed to get workspace audit logs',
      message: 'Internal server error'
    });
  }
});

// Get file access history (for file owners and workspace managers)
router.get('/file/:fileId', authenticateToken, async (req, res) => {
  try {
    const { fileId } = req.params;
    const { limit = 50, offset = 0 } = req.query;

    // Check if user has access to this file
    const fileAccess = await database.get(`
      SELECT f.id, f.original_name, w.manager_id, f.owner_id
      FROM files f
      JOIN workspaces w ON w.id = f.workspace_id
      WHERE f.id = ? AND (
        f.owner_id = ? OR 
        w.manager_id = ? OR
        EXISTS (
          SELECT 1 FROM workspace_members wm 
          WHERE wm.workspace_id = w.id AND wm.user_id = ?
        )
      )
    `, [fileId, req.user.id, req.user.id, req.user.id]);

    if (!fileAccess) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You do not have access to this file\'s audit logs'
      });
    }

    // Get file access logs
    const accessLogs = await database.all(`
      SELECT fal.operation, fal.timestamp, fal.success, fal.error_message, fal.ip_address,
             u.name as user_name, u.surname as user_surname, u.email as user_email, u.role as user_role
      FROM file_access_logs fal
      JOIN users u ON u.id = fal.user_id
      WHERE fal.file_id = ?
      ORDER BY fal.timestamp DESC
      LIMIT ? OFFSET ?
    `, [fileId, parseInt(limit), parseInt(offset)]);

    // Get total count
    const { total } = await database.get(
      'SELECT COUNT(*) as total FROM file_access_logs WHERE file_id = ?',
      [fileId]
    );

    res.json({
      file: {
        id: fileAccess.id,
        name: fileAccess.original_name
      },
      accessHistory: accessLogs,
      pagination: {
        limit: parseInt(limit),
        offset: parseInt(offset),
        total: total,
        hasMore: parseInt(offset) + accessLogs.length < total
      }
    });

  } catch (error) {
    console.error('Get file audit logs error:', error);
    res.status(500).json({
      error: 'Failed to get file audit logs',
      message: 'Internal server error'
    });
  }
});

// Get system statistics for current user
router.get('/statistics', authenticateToken, async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const daysAgo = new Date();
    daysAgo.setDate(daysAgo.getDate() - parseInt(days));

    // User's activity statistics
    const activityStats = await database.all(`
      SELECT action, COUNT(*) as count
      FROM audit_logs
      WHERE user_id = ? AND timestamp >= ?
      GROUP BY action
      ORDER BY count DESC
    `, [req.user.id, daysAgo.toISOString()]);

    // Daily activity trend
    const dailyActivity = await database.all(`
      SELECT DATE(timestamp) as date, COUNT(*) as count
      FROM audit_logs
      WHERE user_id = ? AND timestamp >= ?
      GROUP BY DATE(timestamp)
      ORDER BY date ASC
    `, [req.user.id, daysAgo.toISOString()]);

    // User's workspace participation
    let workspaceStats = [];
    if (req.user.role === 'manager') {
      workspaceStats = await database.all(`
        SELECT w.id, w.name, COUNT(al.id) as activity_count
        FROM workspaces w
        LEFT JOIN audit_logs al ON (
          (al.resource_type = 'workspace' AND al.resource_id = w.id) OR
          (al.action IN ('FILE_UPLOADED', 'FILE_DOWNLOADED', 'FILE_DELETED', 'NOTE_CREATED') 
           AND JSON_EXTRACT(al.details, '$.workspaceId') = w.id)
        ) AND al.timestamp >= ?
        WHERE w.manager_id = ?
        GROUP BY w.id, w.name
        ORDER BY activity_count DESC
      `, [daysAgo.toISOString(), req.user.id]);
    } else {
      workspaceStats = await database.all(`
        SELECT w.id, w.name, COUNT(al.id) as activity_count
        FROM workspace_members wm
        JOIN workspaces w ON w.id = wm.workspace_id
        LEFT JOIN audit_logs al ON (
          (al.resource_type = 'workspace' AND al.resource_id = w.id) OR
          (al.action IN ('FILE_UPLOADED', 'FILE_DOWNLOADED', 'FILE_DELETED', 'NOTE_CREATED') 
           AND JSON_EXTRACT(al.details, '$.workspaceId') = w.id)
        ) AND al.timestamp >= ?
        WHERE wm.user_id = ?
        GROUP BY w.id, w.name
        ORDER BY activity_count DESC
      `, [daysAgo.toISOString(), req.user.id]);
    }

    res.json({
      period: {
        days: parseInt(days),
        startDate: daysAgo.toISOString(),
        endDate: new Date().toISOString()
      },
      activity: {
        byAction: activityStats,
        dailyTrend: dailyActivity,
        totalActions: activityStats.reduce((sum, stat) => sum + stat.count, 0)
      },
      workspaces: workspaceStats
    });

  } catch (error) {
    console.error('Get audit statistics error:', error);
    res.status(500).json({
      error: 'Failed to get audit statistics',
      message: 'Internal server error'
    });
  }
});

// Export audit logs (for compliance)
router.get('/export', authenticateToken, requireRole('manager', 'admin'), [
  query('workspaceId').optional().isInt().withMessage('Workspace ID must be integer'),
  query('startDate').isISO8601().withMessage('Start date is required and must be valid'),
  query('endDate').isISO8601().withMessage('End date is required and must be valid'),
  query('format').optional().isIn(['json', 'csv']).withMessage('Format must be json or csv')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { workspaceId, startDate, endDate, format = 'json' } = req.query;

    let whereConditions = ['timestamp >= ?', 'timestamp <= ?'];
    let params = [new Date(startDate).toISOString(), new Date(endDate).toISOString()];

    // For non-admin users, restrict to their workspaces
    if (req.user.role !== 'admin') {
      if (workspaceId) {
        // Check access to specific workspace
        const hasAccess = await database.get(`
          SELECT 1 FROM workspaces WHERE id = ? AND manager_id = ?
        `, [workspaceId, req.user.id]);

        if (!hasAccess) {
          return res.status(403).json({
            error: 'Access denied',
            message: 'You do not have access to this workspace'
          });
        }

        whereConditions.push('(resource_type = ? AND resource_id = ?)');
        params.push('workspace', workspaceId);
      } else {
        // Restrict to user's workspaces only
        whereConditions.push(`(
          user_id = ? OR
          (resource_type = 'workspace' AND resource_id IN (
            SELECT id FROM workspaces WHERE manager_id = ?
          ))
        )`);
        params.push(req.user.id, req.user.id);
      }
    } else if (workspaceId) {
      whereConditions.push('(resource_type = ? AND resource_id = ?)');
      params.push('workspace', workspaceId);
    }

    const whereClause = `WHERE ${whereConditions.join(' AND ')}`;

    const logs = await database.all(`
      SELECT al.*, u.email as user_email, u.name as user_name, u.surname as user_surname
      FROM audit_logs al
      LEFT JOIN users u ON u.id = al.user_id
      ${whereClause}
      ORDER BY al.timestamp DESC
    `, params);

    // Process logs
    const processedLogs = logs.map(log => ({
      id: log.id,
      timestamp: log.timestamp,
      action: log.action,
      resourceType: log.resource_type,
      resourceId: log.resource_id,
      details: log.details ? JSON.parse(log.details) : null,
      ipAddress: log.ip_address,
      user: {
        email: log.user_email,
        name: log.user_name,
        surname: log.user_surname
      }
    }));

    const exportData = {
      metadata: {
        exportedAt: new Date().toISOString(),
        exportedBy: req.user.email,
        period: {
          startDate,
          endDate
        },
        workspaceId: workspaceId ? parseInt(workspaceId) : null,
        totalRecords: logs.length
      },
      logs: processedLogs
    };

    if (format === 'csv') {
      // Convert to CSV format
      const csvHeaders = ['Timestamp', 'Action', 'Resource Type', 'Resource ID', 'User Email', 'IP Address', 'Details'];
      const csvRows = [csvHeaders.join(',')];

      processedLogs.forEach(log => {
        const row = [
          log.timestamp,
          log.action,
          log.resourceType || '',
          log.resourceId || '',
          log.user.email || '',
          log.ipAddress || '',
          log.details ? JSON.stringify(log.details).replace(/"/g, '""') : ''
        ];
        csvRows.push(row.map(field => `"${field}"`).join(','));
      });

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="audit-logs-${startDate}-${endDate}.csv"`);
      res.send(csvRows.join('\n'));
    } else {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="audit-logs-${startDate}-${endDate}.json"`);
      res.json(exportData);
    }

    // Log the export activity
    const { auditLog } = require('../utils/audit');
    await auditLog({
      userId: req.user.id,
      action: 'AUDIT_LOGS_EXPORTED',
      resourceType: 'system',
      details: JSON.stringify({
        format,
        startDate,
        endDate,
        workspaceId,
        recordCount: logs.length
      }),
      ipAddress: req.ip
    });

  } catch (error) {
    console.error('Export audit logs error:', error);
    res.status(500).json({
      error: 'Failed to export audit logs',
      message: 'Internal server error'
    });
  }
});

module.exports = router;