const express = require('express');
const { body, param, validationResult } = require('express-validator');

const database = require('../database/connection');
const { auditLog } = require('../utils/audit');
const { 
  authenticateToken, 
  requireRole, 
  requireWorkspaceAccess,
  requireWorkspaceMFA 
} = require('../middleware/auth');

const router = express.Router();

// Create workspace (Manager only)
router.post('/', authenticateToken, requireRole('manager'), [
  body('name').trim().isLength({ min: 3, max: 255 }).withMessage('Name must be 3-255 characters'),
  body('description').optional().trim().isLength({ max: 1000 }).withMessage('Description must be under 1000 characters'),
  body('caseNumber').optional().trim().isLength({ max: 100 }).withMessage('Case number must be under 100 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { name, description, caseNumber } = req.body;

    // Check if case number already exists (if provided)
    if (caseNumber) {
      const existingCase = await database.get(
        'SELECT id FROM workspaces WHERE case_number = ?',
        [caseNumber]
      );
      if (existingCase) {
        return res.status(409).json({
          error: 'Case number already exists',
          message: 'A workspace with this case number already exists'
        });
      }
    }

    // Create workspace
    const result = await database.run(`
      INSERT INTO workspaces (name, description, manager_id, case_number)
      VALUES (?, ?, ?, ?)
    `, [name, description || null, req.user.id, caseNumber || null]);

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'WORKSPACE_CREATED',
      resourceType: 'workspace',
      resourceId: result.id,
      details: JSON.stringify({ name, caseNumber }),
      ipAddress: req.ip
    });

    res.status(201).json({
      message: 'Workspace created successfully',
      workspace: {
        id: result.id,
        name,
        description,
        caseNumber,
        managerId: req.user.id,
        createdAt: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('Create workspace error:', error);
    res.status(500).json({
      error: 'Failed to create workspace',
      message: 'Internal server error'
    });
  }
});

// Get workspace details
router.get('/:workspaceId', authenticateToken, requireWorkspaceAccess('read'), async (req, res) => {
  try {
    const { workspaceId } = req.params;

    const workspace = await database.get(`
      SELECT w.*, u.name as manager_name, u.surname as manager_surname, u.email as manager_email
      FROM workspaces w
      JOIN users u ON u.id = w.manager_id
      WHERE w.id = ?
    `, [workspaceId]);

    if (!workspace) {
      return res.status(404).json({
        error: 'Workspace not found',
        message: 'The specified workspace does not exist'
      });
    }

    // Get workspace members
    const members = await database.all(`
      SELECT u.id, u.name, u.surname, u.email, u.role,
             wm.access_level, wm.mfa_enabled, wm.joined_at,
             au.name as added_by_name, au.surname as added_by_surname
      FROM workspace_members wm
      JOIN users u ON u.id = wm.user_id
      JOIN users au ON au.id = wm.added_by
      WHERE wm.workspace_id = ?
      ORDER BY wm.joined_at ASC
    `, [workspaceId]);

    // Get file count and recent files
    const { file_count } = await database.get(
      'SELECT COUNT(*) as file_count FROM files WHERE workspace_id = ?',
      [workspaceId]
    );

    const recentFiles = await database.all(`
      SELECT f.id, f.name, f.original_name, f.file_type, f.file_size, f.uploaded_at,
             u.name as owner_name, u.surname as owner_surname
      FROM files f
      JOIN users u ON u.id = f.owner_id
      WHERE f.workspace_id = ?
      ORDER BY f.uploaded_at DESC
      LIMIT 5
    `, [workspaceId]);

    res.json({
      workspace: {
        ...workspace,
        memberCount: members.length,
        fileCount: file_count
      },
      members: members,
      recentFiles: recentFiles,
      userRole: req.userWorkspaceRole,
      userAccess: req.workspaceAccess
    });

  } catch (error) {
    console.error('Get workspace error:', error);
    res.status(500).json({
      error: 'Failed to get workspace',
      message: 'Internal server error'
    });
  }
});

// Update workspace (Manager only)
router.put('/:workspaceId', authenticateToken, requireWorkspaceAccess('write'), [
  body('name').optional().trim().isLength({ min: 3, max: 255 }).withMessage('Name must be 3-255 characters'),
  body('description').optional().trim().isLength({ max: 1000 }).withMessage('Description must be under 1000 characters'),
  body('caseNumber').optional().trim().isLength({ max: 100 }).withMessage('Case number must be under 100 characters')
], async (req, res) => {
  try {
    // Only managers can update workspace details
    if (req.userWorkspaceRole !== 'manager') {
      return res.status(403).json({
        error: 'Access denied',
        message: 'Only workspace managers can update workspace details'
      });
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { workspaceId } = req.params;
    const { name, description, caseNumber } = req.body;

    const updates = {};
    const params = [];

    if (name) {
      updates.name = name;
      params.push(name);
    }
    if (description !== undefined) {
      updates.description = description;
      params.push(description);
    }
    if (caseNumber !== undefined) {
      // Check if case number already exists (exclude current workspace)
      if (caseNumber) {
        const existingCase = await database.get(
          'SELECT id FROM workspaces WHERE case_number = ? AND id != ?',
          [caseNumber, workspaceId]
        );
        if (existingCase) {
          return res.status(409).json({
            error: 'Case number already exists',
            message: 'Another workspace already uses this case number'
          });
        }
      }
      updates.case_number = caseNumber;
      params.push(caseNumber);
    }

    if (params.length === 0) {
      return res.status(400).json({
        error: 'No updates provided',
        message: 'At least one field must be provided'
      });
    }

    // Build dynamic SQL
    const setClause = Object.keys(updates).map(key => `${key} = ?`).join(', ');
    params.push(workspaceId);

    await database.run(`
      UPDATE workspaces SET ${setClause}, updated_at = CURRENT_TIMESTAMP 
      WHERE id = ?
    `, params);

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'WORKSPACE_UPDATED',
      resourceType: 'workspace',
      resourceId: workspaceId,
      details: JSON.stringify(updates),
      ipAddress: req.ip
    });

    res.json({
      message: 'Workspace updated successfully',
      updates: updates
    });

  } catch (error) {
    console.error('Update workspace error:', error);
    res.status(500).json({
      error: 'Failed to update workspace',
      message: 'Internal server error'
    });
  }
});

// Add member to workspace (Manager only)
router.post('/:workspaceId/members', authenticateToken, requireWorkspaceAccess('write'), [
  body('userEmail').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('accessLevel').isIn(['read', 'write']).withMessage('Access level must be read or write')
], async (req, res) => {
  try {
    // Only managers can add members
    if (req.userWorkspaceRole !== 'manager') {
      return res.status(403).json({
        error: 'Access denied',
        message: 'Only workspace managers can add members'
      });
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { workspaceId } = req.params;
    const { userEmail, accessLevel } = req.body;

    // Find user by email
    const user = await database.get(`
      SELECT id, name, surname, email, role, verified, admin_approved
      FROM users WHERE email = ? AND verified = TRUE AND admin_approved = TRUE
    `, [userEmail]);

    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'No verified and approved user found with this email'
      });
    }

    // Check if user is already a member
    const existingMember = await database.get(
      'SELECT id FROM workspace_members WHERE workspace_id = ? AND user_id = ?',
      [workspaceId, user.id]
    );

    if (existingMember) {
      return res.status(409).json({
        error: 'User already member',
        message: 'User is already a member of this workspace'
      });
    }

    // Add member
    const result = await database.run(`
      INSERT INTO workspace_members (workspace_id, user_id, added_by, access_level)
      VALUES (?, ?, ?, ?)
    `, [workspaceId, user.id, req.user.id, accessLevel]);

    // Get workspace name for audit
    const workspace = await database.get('SELECT name FROM workspaces WHERE id = ?', [workspaceId]);

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'WORKSPACE_MEMBER_ADDED',
      resourceType: 'workspace',
      resourceId: workspaceId,
      details: JSON.stringify({
        workspaceName: workspace.name,
        memberEmail: userEmail,
        accessLevel
      }),
      ipAddress: req.ip
    });

    // Also log for the added user
    await auditLog({
      userId: user.id,
      action: 'ADDED_TO_WORKSPACE',
      resourceType: 'workspace',
      resourceId: workspaceId,
      details: JSON.stringify({
        workspaceName: workspace.name,
        addedBy: req.user.email,
        accessLevel
      }),
      ipAddress: req.ip
    });

    res.status(201).json({
      message: 'Member added successfully',
      member: {
        id: user.id,
        name: user.name,
        surname: user.surname,
        email: user.email,
        role: user.role,
        accessLevel: accessLevel,
        joinedAt: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('Add member error:', error);
    res.status(500).json({
      error: 'Failed to add member',
      message: 'Internal server error'
    });
  }
});

// Update member access level (Manager only)
router.put('/:workspaceId/members/:userId', authenticateToken, requireWorkspaceAccess('write'), [
  param('userId').isInt().withMessage('Valid user ID required'),
  body('accessLevel').isIn(['read', 'write']).withMessage('Access level must be read or write')
], async (req, res) => {
  try {
    // Only managers can update member access
    if (req.userWorkspaceRole !== 'manager') {
      return res.status(403).json({
        error: 'Access denied',
        message: 'Only workspace managers can update member access'
      });
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { workspaceId, userId } = req.params;
    const { accessLevel } = req.body;

    // Check if member exists
    const member = await database.get(`
      SELECT wm.*, u.email
      FROM workspace_members wm
      JOIN users u ON u.id = wm.user_id
      WHERE wm.workspace_id = ? AND wm.user_id = ?
    `, [workspaceId, userId]);

    if (!member) {
      return res.status(404).json({
        error: 'Member not found',
        message: 'User is not a member of this workspace'
      });
    }

    if (member.access_level === accessLevel) {
      return res.status(400).json({
        error: 'No change needed',
        message: 'User already has this access level'
      });
    }

    // Update access level
    await database.run(`
      UPDATE workspace_members 
      SET access_level = ? 
      WHERE workspace_id = ? AND user_id = ?
    `, [accessLevel, workspaceId, userId]);

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'WORKSPACE_ACCESS_UPDATED',
      resourceType: 'workspace',
      resourceId: workspaceId,
      details: JSON.stringify({
        memberEmail: member.email,
        oldAccess: member.access_level,
        newAccess: accessLevel
      }),
      ipAddress: req.ip
    });

    res.json({
      message: 'Member access updated successfully',
      accessLevel: accessLevel
    });

  } catch (error) {
    console.error('Update member access error:', error);
    res.status(500).json({
      error: 'Failed to update member access',
      message: 'Internal server error'
    });
  }
});

// Remove member from workspace (Manager only)
router.delete('/:workspaceId/members/:userId', authenticateToken, requireWorkspaceAccess('write'), [
  param('userId').isInt().withMessage('Valid user ID required')
], async (req, res) => {
  try {
    // Only managers can remove members
    if (req.userWorkspaceRole !== 'manager') {
      return res.status(403).json({
        error: 'Access denied',
        message: 'Only workspace managers can remove members'
      });
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { workspaceId, userId } = req.params;

    // Check if member exists
    const member = await database.get(`
      SELECT wm.*, u.email, u.name, u.surname
      FROM workspace_members wm
      JOIN users u ON u.id = wm.user_id
      WHERE wm.workspace_id = ? AND wm.user_id = ?
    `, [workspaceId, userId]);

    if (!member) {
      return res.status(404).json({
        error: 'Member not found',
        message: 'User is not a member of this workspace'
      });
    }

    // Remove member
    await database.run(`
      DELETE FROM workspace_members 
      WHERE workspace_id = ? AND user_id = ?
    `, [workspaceId, userId]);

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'WORKSPACE_MEMBER_REMOVED',
      resourceType: 'workspace',
      resourceId: workspaceId,
      details: JSON.stringify({
        memberEmail: member.email,
        memberName: `${member.name} ${member.surname}`,
        accessLevel: member.access_level
      }),
      ipAddress: req.ip
    });

    // Also log for the removed user
    await auditLog({
      userId: parseInt(userId),
      action: 'REMOVED_FROM_WORKSPACE',
      resourceType: 'workspace',
      resourceId: workspaceId,
      details: JSON.stringify({
        removedBy: req.user.email
      }),
      ipAddress: req.ip
    });

    res.json({
      message: 'Member removed successfully'
    });

  } catch (error) {
    console.error('Remove member error:', error);
    res.status(500).json({
      error: 'Failed to remove member',
      message: 'Internal server error'
    });
  }
});

// Get workspace notes
router.get('/:workspaceId/notes', authenticateToken, requireWorkspaceAccess('read'), async (req, res) => {
  try {
    const { workspaceId } = req.params;
    const { type, limit = 50, offset = 0 } = req.query;

    let whereClause = 'workspace_id = ?';
    let params = [workspaceId];

    if (type && ['general', 'urgent', 'evidence', 'observation'].includes(type)) {
      whereClause += ' AND note_type = ?';
      params.push(type);
    }

    const notes = await database.all(`
      SELECT n.*, u.name as author_name, u.surname as author_surname, u.email as author_email
      FROM notes n
      JOIN users u ON u.id = n.author_id
      WHERE ${whereClause}
      ORDER BY n.is_pinned DESC, n.created_at DESC
      LIMIT ? OFFSET ?
    `, [...params, parseInt(limit), parseInt(offset)]);

    res.json({
      notes: notes.map(note => ({
        ...note,
        tags: note.tags ? JSON.parse(note.tags) : []
      }))
    });

  } catch (error) {
    console.error('Get notes error:', error);
    res.status(500).json({
      error: 'Failed to get notes',
      message: 'Internal server error'
    });
  }
});

// Create workspace note
router.post('/:workspaceId/notes', authenticateToken, requireWorkspaceAccess('write'), [
  body('content').trim().isLength({ min: 1, max: 5000 }).withMessage('Content must be 1-5000 characters'),
  body('noteType').optional().isIn(['general', 'urgent', 'evidence', 'observation']).withMessage('Invalid note type'),
  body('tags').optional().isArray().withMessage('Tags must be an array'),
  body('isPinned').optional().isBoolean().withMessage('isPinned must be boolean')
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
    const { content, noteType = 'general', tags = [], isPinned = false } = req.body;

    // Create note
    const result = await database.run(`
      INSERT INTO notes (workspace_id, author_id, content, note_type, tags, is_pinned)
      VALUES (?, ?, ?, ?, ?, ?)
    `, [workspaceId, req.user.id, content, noteType, JSON.stringify(tags), isPinned]);

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'NOTE_CREATED',
      resourceType: 'note',
      resourceId: result.id,
      details: JSON.stringify({
        workspaceId,
        noteType,
        isPinned,
        contentLength: content.length
      }),
      ipAddress: req.ip
    });

    res.status(201).json({
      message: 'Note created successfully',
      note: {
        id: result.id,
        content,
        noteType,
        tags,
        isPinned,
        createdAt: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('Create note error:', error);
    res.status(500).json({
      error: 'Failed to create note',
      message: 'Internal server error'
    });
  }
});

// Update workspace note
router.put('/:workspaceId/notes/:noteId', authenticateToken, requireWorkspaceAccess('write'), [
  param('noteId').isInt().withMessage('Valid note ID required'),
  body('content').optional().trim().isLength({ min: 1, max: 5000 }).withMessage('Content must be 1-5000 characters'),
  body('noteType').optional().isIn(['general', 'urgent', 'evidence', 'observation']).withMessage('Invalid note type'),
  body('tags').optional().isArray().withMessage('Tags must be an array'),
  body('isPinned').optional().isBoolean().withMessage('isPinned must be boolean')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { workspaceId, noteId } = req.params;
    const { content, noteType, tags, isPinned } = req.body;

    // Check if note exists and user can edit it
    const note = await database.get(`
      SELECT * FROM notes 
      WHERE id = ? AND workspace_id = ? AND (author_id = ? OR ? IN (
        SELECT manager_id FROM workspaces WHERE id = ?
      ))
    `, [noteId, workspaceId, req.user.id, req.user.id, workspaceId]);

    if (!note) {
      return res.status(404).json({
        error: 'Note not found',
        message: 'Note not found or you do not have permission to edit it'
      });
    }

    const updates = {};
    const params = [];

    if (content !== undefined) {
      updates.content = content;
      params.push(content);
    }
    if (noteType !== undefined) {
      updates.note_type = noteType;
      params.push(noteType);
    }
    if (tags !== undefined) {
      updates.tags = JSON.stringify(tags);
      params.push(JSON.stringify(tags));
    }
    if (isPinned !== undefined) {
      updates.is_pinned = isPinned;
      params.push(isPinned);
    }

    if (params.length === 0) {
      return res.status(400).json({
        error: 'No updates provided',
        message: 'At least one field must be provided'
      });
    }

    // Build dynamic SQL
    const setClause = Object.keys(updates).map(key => `${key} = ?`).join(', ');
    params.push(noteId);

    await database.run(`
      UPDATE notes SET ${setClause}, updated_at = CURRENT_TIMESTAMP 
      WHERE id = ?
    `, params);

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'NOTE_UPDATED',
      resourceType: 'note',
      resourceId: noteId,
      details: JSON.stringify({ workspaceId, updates }),
      ipAddress: req.ip
    });

    res.json({
      message: 'Note updated successfully',
      updates: updates
    });

  } catch (error) {
    console.error('Update note error:', error);
    res.status(500).json({
      error: 'Failed to update note',
      message: 'Internal server error'
    });
  }
});

// Delete workspace note
router.delete('/:workspaceId/notes/:noteId', authenticateToken, requireWorkspaceAccess('write'), [
  param('noteId').isInt().withMessage('Valid note ID required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { workspaceId, noteId } = req.params;

    // Check if note exists and user can delete it
    const note = await database.get(`
      SELECT * FROM notes 
      WHERE id = ? AND workspace_id = ? AND (author_id = ? OR ? IN (
        SELECT manager_id FROM workspaces WHERE id = ?
      ))
    `, [noteId, workspaceId, req.user.id, req.user.id, workspaceId]);

    if (!note) {
      return res.status(404).json({
        error: 'Note not found',
        message: 'Note not found or you do not have permission to delete it'
      });
    }

    // Delete note
    await database.run('DELETE FROM notes WHERE id = ?', [noteId]);

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'NOTE_DELETED',
      resourceType: 'note',
      resourceId: noteId,
      details: JSON.stringify({
        workspaceId,
        noteType: note.note_type,
        contentLength: note.content.length
      }),
      ipAddress: req.ip
    });

    res.json({
      message: 'Note deleted successfully'
    });

  } catch (error) {
    console.error('Delete note error:', error);
    res.status(500).json({
      error: 'Failed to delete note',
      message: 'Internal server error'
    });
  }
});

// Delete workspace (Manager only)
router.delete('/:workspaceId', authenticateToken, requireWorkspaceAccess('write'), async (req, res) => {
  try {
    // Only managers can delete workspaces
    if (req.userWorkspaceRole !== 'manager') {
      return res.status(403).json({
        error: 'Access denied',
        message: 'Only workspace managers can delete workspaces'
      });
    }

    const { workspaceId } = req.params;

    // Get workspace details for audit
    const workspace = await database.get('SELECT * FROM workspaces WHERE id = ?', [workspaceId]);
    
    if (!workspace) {
      return res.status(404).json({
        error: 'Workspace not found'
      });
    }

    // Get file count for confirmation
    const { file_count } = await database.get(
      'SELECT COUNT(*) as file_count FROM files WHERE workspace_id = ?',
      [workspaceId]
    );

    const { member_count } = await database.get(
      'SELECT COUNT(*) as member_count FROM workspace_members WHERE workspace_id = ?',
      [workspaceId]
    );

    // Delete workspace (cascading deletes will handle related records)
    await database.run('DELETE FROM workspaces WHERE id = ?', [workspaceId]);

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'WORKSPACE_DELETED',
      resourceType: 'workspace',
      resourceId: workspaceId,
      details: JSON.stringify({
        workspaceName: workspace.name,
        caseNumber: workspace.case_number,
        fileCount: file_count,
        memberCount: member_count
      }),
      ipAddress: req.ip
    });

    res.json({
      message: 'Workspace deleted successfully',
      deletedFiles: file_count,
      removedMembers: member_count
    });

  } catch (error) {
    console.error('Delete workspace error:', error);
    res.status(500).json({
      error: 'Failed to delete workspace',
      message: 'Internal server error'
    });
  }
});

module.exports = router;