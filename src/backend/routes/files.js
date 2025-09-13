const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const { param, validationResult } = require('express-validator');
const mime = require('mime-types');

const database = require('../database/connection');
const encryption = require('../utils/encryption');
const { auditLog } = require('../utils/audit');
const { 
  authenticateToken, 
  requireWorkspaceAccess,
  requireWorkspaceMFA 
} = require('../middleware/auth');

const router = express.Router();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadDir = path.join(process.env.UPLOAD_DIR || './uploads', 'temp');
    await fs.mkdir(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Generate secure temporary filename
    const tempName = encryption.generateSecureFilename() + path.extname(file.originalname);
    cb(null, tempName);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = (process.env.ALLOWED_FILE_TYPES || 'pdf,doc,docx,txt,jpg,jpeg,png,zip,rar,7z,bin,hex,pcap')
    .split(',').map(type => type.trim().toLowerCase());
  
  const fileExt = path.extname(file.originalname).slice(1).toLowerCase();
  
  if (allowedTypes.includes(fileExt) || allowedTypes.includes('*')) {
    cb(null, true);
  } else {
    cb(new Error(`File type .${fileExt} is not allowed. Allowed types: ${allowedTypes.join(', ')}`), false);
  }
};

const upload = multer({
  storage: storage,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 50 * 1024 * 1024, // 50MB default
    files: 1
  },
  fileFilter: fileFilter
});

// Upload file to workspace
router.post('/upload/:workspaceId', 
  authenticateToken, 
  requireWorkspaceAccess('write'),
  requireWorkspaceMFA,
  upload.single('file'),
  async (req, res) => {
    let tempFilePath = null;
    let encryptedFilePath = null;

    try {
      if (!req.file) {
        return res.status(400).json({
          error: 'No file provided',
          message: 'Please select a file to upload'
        });
      }

      const { workspaceId } = req.params;
      tempFilePath = req.file.path;

      // Get user's public key for encryption
      const user = await database.get('SELECT public_key FROM users WHERE id = ?', [req.user.id]);
      if (!user || !user.public_key) {
        throw new Error('User encryption keys not found');
      }

      // Generate secure filename for encrypted storage
      const encryptedFileName = encryption.generateSecureFilename() + '.enc';
      const encryptedDir = path.join(process.env.UPLOAD_DIR || './uploads', 'encrypted');
      await fs.mkdir(encryptedDir, { recursive: true });
      encryptedFilePath = path.join(encryptedDir, encryptedFileName);

      // Encrypt file
      const { encryptedKeyData, checksum } = await encryption.encryptFile(
        tempFilePath,
        encryptedFilePath,
        user.public_key
      );

      // Get file metadata
      const fileStats = await fs.stat(tempFilePath);
      const mimeType = mime.lookup(req.file.originalname) || 'application/octet-stream';

      // Save file record to database
      const result = await database.run(`
        INSERT INTO files (name, original_name, file_path, file_type, file_size, 
                          checksum, workspace_id, owner_id, encryption_key, is_encrypted)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, TRUE)
      `, [
        encryptedFileName,
        req.file.originalname,
        encryptedFilePath,
        mimeType,
        fileStats.size,
        checksum,
        workspaceId,
        req.user.id,
        encryptedKeyData
      ]);

      // Log file access
      await database.run(`
        INSERT INTO file_access_logs (file_id, user_id, operation, ip_address, user_agent, success)
        VALUES (?, ?, 'upload', ?, ?, TRUE)
      `, [result.id, req.user.id, req.ip, req.get('User-Agent')]);

      // Audit log
      await auditLog({
        userId: req.user.id,
        action: 'FILE_UPLOADED',
        resourceType: 'file',
        resourceId: result.id,
        details: JSON.stringify({
          workspaceId,
          originalName: req.file.originalname,
          fileSize: fileStats.size,
          fileType: mimeType,
          checksum
        }),
        ipAddress: req.ip
      });

      // Clean up temp file
      await fs.unlink(tempFilePath);

      res.status(201).json({
        message: 'File uploaded successfully',
        file: {
          id: result.id,
          name: req.file.originalname,
          size: fileStats.size,
          type: mimeType,
          checksum: checksum,
          uploadedAt: new Date().toISOString()
        }
      });

    } catch (error) {
      console.error('File upload error:', error);

      // Clean up files on error
      try {
        if (tempFilePath) await fs.unlink(tempFilePath);
        if (encryptedFilePath) await fs.unlink(encryptedFilePath);
      } catch (cleanupError) {
        console.error('Cleanup error:', cleanupError);
      }

      // Log failed upload
      if (req.file) {
        await database.run(`
          INSERT INTO file_access_logs (file_id, user_id, operation, ip_address, user_agent, success, error_message)
          VALUES (NULL, ?, 'upload', ?, ?, FALSE, ?)
        `, [req.user.id, req.ip, req.get('User-Agent'), error.message]).catch(() => {});
      }

      if (error.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({
          error: 'File too large',
          message: `File size exceeds the maximum limit of ${Math.round((parseInt(process.env.MAX_FILE_SIZE) || 50000000) / 1024 / 1024)}MB`
        });
      }

      res.status(500).json({
        error: 'Upload failed',
        message: error.message || 'Internal server error'
      });
    }
  }
);

// Get files in workspace
router.get('/workspace/:workspaceId', 
  authenticateToken, 
  requireWorkspaceAccess('read'),
  async (req, res) => {
    try {
      const { workspaceId } = req.params;
      const { limit = 50, offset = 0, sortBy = 'uploaded_at', sortOrder = 'DESC' } = req.query;

      // Validate sort parameters
      const allowedSortBy = ['name', 'original_name', 'file_size', 'uploaded_at'];
      const allowedSortOrder = ['ASC', 'DESC'];
      
      const validSortBy = allowedSortBy.includes(sortBy) ? sortBy : 'uploaded_at';
      const validSortOrder = allowedSortOrder.includes(sortOrder.toUpperCase()) ? sortOrder.toUpperCase() : 'DESC';

      const files = await database.all(`
        SELECT f.id, f.name, f.original_name, f.file_type, f.file_size, f.checksum, 
               f.uploaded_at, f.is_encrypted,
               u.name as owner_name, u.surname as owner_surname, u.email as owner_email
        FROM files f
        JOIN users u ON u.id = f.owner_id
        WHERE f.workspace_id = ?
        ORDER BY f.${validSortBy} ${validSortOrder}
        LIMIT ? OFFSET ?
      `, [workspaceId, parseInt(limit), parseInt(offset)]);

      // Get total count
      const { total } = await database.get(
        'SELECT COUNT(*) as total FROM files WHERE workspace_id = ?',
        [workspaceId]
      );

      res.json({
        files: files,
        pagination: {
          limit: parseInt(limit),
          offset: parseInt(offset),
          total: total,
          hasMore: parseInt(offset) + files.length < total
        }
      });

    } catch (error) {
      console.error('Get files error:', error);
      res.status(500).json({
        error: 'Failed to get files',
        message: 'Internal server error'
      });
    }
  }
);

// Get file details
router.get('/:fileId', 
  authenticateToken,
  [param('fileId').isInt().withMessage('Valid file ID required')],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation failed',
          details: errors.array()
        });
      }

      const { fileId } = req.params;

      // Get file with workspace access check
      const file = await database.get(`
        SELECT f.*, w.id as workspace_id, w.name as workspace_name,
               u.name as owner_name, u.surname as owner_surname, u.email as owner_email
        FROM files f
        JOIN workspaces w ON w.id = f.workspace_id
        JOIN users u ON u.id = f.owner_id
        WHERE f.id = ?
      `, [fileId]);

      if (!file) {
        return res.status(404).json({
          error: 'File not found',
          message: 'The specified file does not exist'
        });
      }

      // Check workspace access
      const hasAccess = await database.get(`
        SELECT 1 FROM workspace_members wm
        WHERE wm.workspace_id = ? AND wm.user_id = ?
        UNION
        SELECT 1 FROM workspaces w
        WHERE w.id = ? AND w.manager_id = ?
      `, [file.workspace_id, req.user.id, file.workspace_id, req.user.id]);

      if (!hasAccess) {
        return res.status(403).json({
          error: 'Access denied',
          message: 'You do not have access to this file'
        });
      }

      // Get recent access logs for this file
      const accessLogs = await database.all(`
        SELECT fal.operation, fal.timestamp, fal.success, fal.ip_address,
               u.name as user_name, u.surname as user_surname, u.email as user_email
        FROM file_access_logs fal
        JOIN users u ON u.id = fal.user_id
        WHERE fal.file_id = ?
        ORDER BY fal.timestamp DESC
        LIMIT 10
      `, [fileId]);

      // Log file view
      await database.run(`
        INSERT INTO file_access_logs (file_id, user_id, operation, ip_address, user_agent, success)
        VALUES (?, ?, 'view', ?, ?, TRUE)
      `, [fileId, req.user.id, req.ip, req.get('User-Agent')]);

      res.json({
        file: {
          id: file.id,
          name: file.original_name,
          size: file.file_size,
          type: file.file_type,
          checksum: file.checksum,
          uploadedAt: file.uploaded_at,
          isEncrypted: file.is_encrypted,
          owner: {
            name: file.owner_name,
            surname: file.owner_surname,
            email: file.owner_email
          },
          workspace: {
            id: file.workspace_id,
            name: file.workspace_name
          }
        },
        accessHistory: accessLogs
      });

    } catch (error) {
      console.error('Get file details error:', error);
      res.status(500).json({
        error: 'Failed to get file details',
        message: 'Internal server error'
      });
    }
  }
);

// Download file
router.get('/:fileId/download', 
  authenticateToken,
  requireWorkspaceMFA,
  [param('fileId').isInt().withMessage('Valid file ID required')],
  async (req, res) => {
    let decryptedFilePath = null;

    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation failed',
          details: errors.array()
        });
      }

      const { fileId } = req.params;

      // Get file with workspace and user access check
      const file = await database.get(`
        SELECT f.*, w.manager_id, u.private_key
        FROM files f
        JOIN workspaces w ON w.id = f.workspace_id
        JOIN users u ON u.id = f.owner_id
        WHERE f.id = ? AND (
          w.manager_id = ? OR
          EXISTS (
            SELECT 1 FROM workspace_members wm 
            WHERE wm.workspace_id = w.id AND wm.user_id = ? AND wm.mfa_enabled = TRUE
          )
        )
      `, [fileId, req.user.id, req.user.id]);

      if (!file) {
        await database.run(`
          INSERT INTO file_access_logs (file_id, user_id, operation, ip_address, user_agent, success, error_message)
          VALUES (?, ?, 'download', ?, ?, FALSE, 'File not found or access denied')
        `, [fileId, req.user.id, req.ip, req.get('User-Agent')]);

        return res.status(404).json({
          error: 'File not found',
          message: 'File not found or you do not have access'
        });
      }

      // Check if file exists on disk
      try {
        await fs.access(file.file_path);
      } catch (error) {
        await database.run(`
          INSERT INTO file_access_logs (file_id, user_id, operation, ip_address, user_agent, success, error_message)
          VALUES (?, ?, 'download', ?, ?, FALSE, 'File not found on disk')
        `, [fileId, req.user.id, req.ip, req.get('User-Agent')]);

        return res.status(404).json({
          error: 'File not available',
          message: 'File is not available for download'
        });
      }

      if (file.is_encrypted) {
        // Create temporary directory for decryption
        const tempDir = path.join(process.env.UPLOAD_DIR || './uploads', 'temp');
        await fs.mkdir(tempDir, { recursive: true });
        
        decryptedFilePath = path.join(tempDir, `decrypted_${encryption.generateSecureFilename()}${path.extname(file.original_name)}`);

        // Decrypt file
        const actualChecksum = await encryption.decryptFile(
          file.file_path,
          decryptedFilePath,
          file.encryption_key,
          file.private_key
        );

        // Verify file integrity
        if (actualChecksum !== file.checksum) {
          throw new Error('File integrity check failed');
        }

        // Send decrypted file
        res.setHeader('Content-Disposition', `attachment; filename="${file.original_name}"`);
        res.setHeader('Content-Type', file.file_type || 'application/octet-stream');
        
        const fileStream = require('fs').createReadStream(decryptedFilePath);
        fileStream.pipe(res);

        // Clean up decrypted file after sending
        fileStream.on('end', async () => {
          try {
            await fs.unlink(decryptedFilePath);
          } catch (cleanupError) {
            console.error('Cleanup error:', cleanupError);
          }
        });

      } else {
        // Send unencrypted file directly
        res.setHeader('Content-Disposition', `attachment; filename="${file.original_name}"`);
        res.setHeader('Content-Type', file.file_type || 'application/octet-stream');
        
        const fileStream = require('fs').createReadStream(file.file_path);
        fileStream.pipe(res);
      }

      // Log successful download
      await database.run(`
        INSERT INTO file_access_logs (file_id, user_id, operation, ip_address, user_agent, success)
        VALUES (?, ?, 'download', ?, ?, TRUE)
      `, [fileId, req.user.id, req.ip, req.get('User-Agent')]);

      // Audit log
      await auditLog({
        userId: req.user.id,
        action: 'FILE_DOWNLOADED',
        resourceType: 'file',
        resourceId: fileId,
        details: JSON.stringify({
          fileName: file.original_name,
          fileSize: file.file_size,
          workspaceId: file.workspace_id
        }),
        ipAddress: req.ip
      });

    } catch (error) {
      console.error('File download error:', error);

      // Clean up decrypted file on error
      if (decryptedFilePath) {
        try {
          await fs.unlink(decryptedFilePath);
        } catch (cleanupError) {
          console.error('Cleanup error:', cleanupError);
        }
      }

      // Log failed download
      await database.run(`
        INSERT INTO file_access_logs (file_id, user_id, operation, ip_address, user_agent, success, error_message)
        VALUES (?, ?, 'download', ?, ?, FALSE, ?)
      `, [req.params.fileId, req.user.id, req.ip, req.get('User-Agent'), error.message]).catch(() => {});

      if (!res.headersSent) {
        res.status(500).json({
          error: 'Download failed',
          message: 'Failed to download file'
        });
      }
    }
  }
);

// Delete file
router.delete('/:fileId', 
  authenticateToken,
  requireWorkspaceMFA,
  [param('fileId').isInt().withMessage('Valid file ID required')],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation failed',
          details: errors.array()
        });
      }

      const { fileId } = req.params;

      // Get file with ownership/manager access check
      const file = await database.get(`
        SELECT f.*, w.manager_id, w.name as workspace_name
        FROM files f
        JOIN workspaces w ON w.id = f.workspace_id
        WHERE f.id = ? AND (f.owner_id = ? OR w.manager_id = ?)
      `, [fileId, req.user.id, req.user.id]);

      if (!file) {
        return res.status(404).json({
          error: 'File not found',
          message: 'File not found or you do not have permission to delete it'
        });
      }

      // Delete file from disk
      try {
        await fs.unlink(file.file_path);
      } catch (error) {
        console.warn('File not found on disk during deletion:', file.file_path);
      }

      // Delete file record from database
      await database.run('DELETE FROM files WHERE id = ?', [fileId]);

      // Log file deletion
      await database.run(`
        INSERT INTO file_access_logs (file_id, user_id, operation, ip_address, user_agent, success)
        VALUES (?, ?, 'delete', ?, ?, TRUE)
      `, [fileId, req.user.id, req.ip, req.get('User-Agent')]);

      // Audit log
      await auditLog({
        userId: req.user.id,
        action: 'FILE_DELETED',
        resourceType: 'file',
        resourceId: fileId,
        details: JSON.stringify({
          fileName: file.original_name,
          fileSize: file.file_size,
          workspaceId: file.workspace_id,
          workspaceName: file.workspace_name
        }),
        ipAddress: req.ip
      });

      res.json({
        message: 'File deleted successfully'
      });

    } catch (error) {
      console.error('File deletion error:', error);

      // Log failed deletion
      await database.run(`
        INSERT INTO file_access_logs (file_id, user_id, operation, ip_address, user_agent, success, error_message)
        VALUES (?, ?, 'delete', ?, ?, FALSE, ?)
      `, [req.params.fileId, req.user.id, req.ip, req.get('User-Agent'), error.message]).catch(() => {});

      res.status(500).json({
        error: 'Deletion failed',
        message: 'Failed to delete file'
      });
    }
  }
);

// Verify file integrity
router.post('/:fileId/verify', 
  authenticateToken,
  [param('fileId').isInt().withMessage('Valid file ID required')],
  async (req, res) => {
    let decryptedFilePath = null;

    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation failed',
          details: errors.array()
        });
      }

      const { fileId } = req.params;

      // Get file with access check
      const file = await database.get(`
        SELECT f.*, w.manager_id, u.private_key
        FROM files f
        JOIN workspaces w ON w.id = f.workspace_id
        JOIN users u ON u.id = f.owner_id
        WHERE f.id = ? AND (
          w.manager_id = ? OR
          EXISTS (
            SELECT 1 FROM workspace_members wm 
            WHERE wm.workspace_id = w.id AND wm.user_id = ?
          )
        )
      `, [fileId, req.user.id, req.user.id]);

      if (!file) {
        return res.status(404).json({
          error: 'File not found',
          message: 'File not found or access denied'
        });
      }

      let actualChecksum;

      if (file.is_encrypted) {
        // Create temporary file for verification
        const tempDir = path.join(process.env.UPLOAD_DIR || './uploads', 'temp');
        await fs.mkdir(tempDir, { recursive: true });
        
        decryptedFilePath = path.join(tempDir, `verify_${encryption.generateSecureFilename()}`);

        // Decrypt file for verification
        actualChecksum = await encryption.decryptFile(
          file.file_path,
          decryptedFilePath,
          file.encryption_key,
          file.private_key
        );

        // Clean up decrypted file
        await fs.unlink(decryptedFilePath);

      } else {
        // Calculate checksum of unencrypted file
        actualChecksum = await encryption.calculateChecksum(file.file_path);
      }

      const isValid = actualChecksum === file.checksum;

      // Audit log
      await auditLog({
        userId: req.user.id,
        action: 'FILE_INTEGRITY_VERIFIED',
        resourceType: 'file',
        resourceId: fileId,
        details: JSON.stringify({
          fileName: file.original_name,
          isValid,
          expectedChecksum: file.checksum,
          actualChecksum
        }),
        ipAddress: req.ip
      });

      res.json({
        message: 'File integrity verification completed',
        file: {
          id: fileId,
          name: file.original_name
        },
        verification: {
          isValid,
          expectedChecksum: file.checksum,
          actualChecksum,
          verifiedAt: new Date().toISOString()
        }
      });

    } catch (error) {
      console.error('File verification error:', error);

      // Clean up on error
      if (decryptedFilePath) {
        try {
          await fs.unlink(decryptedFilePath);
        } catch (cleanupError) {
          console.error('Cleanup error:', cleanupError);
        }
      }

      res.status(500).json({
        error: 'Verification failed',
        message: 'Failed to verify file integrity'
      });
    }
  }
);

// Get file access history
router.get('/:fileId/access-history', 
  authenticateToken,
  [param('fileId').isInt().withMessage('Valid file ID required')],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation failed',
          details: errors.array()
        });
      }

      const { fileId } = req.params;
      const { limit = 50, offset = 0 } = req.query;

      // Verify user has access to this file
      const file = await database.get(`
        SELECT f.id, f.original_name, w.id as workspace_id
        FROM files f
        JOIN workspaces w ON w.id = f.workspace_id
        WHERE f.id = ? AND (
          w.manager_id = ? OR
          EXISTS (
            SELECT 1 FROM workspace_members wm 
            WHERE wm.workspace_id = w.id AND wm.user_id = ?
          )
        )
      `, [fileId, req.user.id, req.user.id]);

      if (!file) {
        return res.status(404).json({
          error: 'File not found',
          message: 'File not found or access denied'
        });
      }

      // Get access history
      const accessHistory = await database.all(`
        SELECT fal.operation, fal.timestamp, fal.success, fal.error_message, fal.ip_address,
               u.name as user_name, u.surname as user_surname, u.email as user_email, u.role
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
          id: fileId,
          name: file.original_name
        },
        accessHistory: accessHistory,
        pagination: {
          limit: parseInt(limit),
          offset: parseInt(offset),
          total: total,
          hasMore: parseInt(offset) + accessHistory.length < total
        }
      });

    } catch (error) {
      console.error('Get access history error:', error);
      res.status(500).json({
        error: 'Failed to get access history',
        message: 'Internal server error'
      });
    }
  }
);

// Bulk file operations
router.post('/bulk-delete', 
  authenticateToken,
  requireWorkspaceMFA,
  [
    body('fileIds').isArray({ min: 1 }).withMessage('File IDs array required'),
    body('fileIds.*').isInt().withMessage('All file IDs must be integers')
  ],
  async (req, res) => {
    try {
      const validationErrors = validationResult(req);
      if (!validationErrors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation failed',
          details: validationErrors.array()
        });
      }

      const { fileIds } = req.body;

      // Get files with ownership/manager check
      const files = await database.all(`
        SELECT f.*, w.manager_id, w.name as workspace_name
        FROM files f
        JOIN workspaces w ON w.id = f.workspace_id
        WHERE f.id IN (${fileIds.map(() => '?').join(',')}) AND (f.owner_id = ? OR w.manager_id = ?)
      `, [...fileIds, req.user.id, req.user.id]);

      if (files.length !== fileIds.length) {
        return res.status(403).json({
          error: 'Access denied',
          message: 'You do not have permission to delete one or more files'
        });
      }

      const deletedFiles = [];
      const errors = [];

      // Process each file
      for (const file of files) {
        try {
          // Delete file from disk
          try {
            await fs.unlink(file.file_path);
          } catch (error) {
            console.warn('File not found on disk during bulk deletion:', file.file_path);
          }

          // Delete from database
          await database.run('DELETE FROM files WHERE id = ?', [file.id]);

          // Log deletion
          await database.run(`
            INSERT INTO file_access_logs (file_id, user_id, operation, ip_address, user_agent, success)
            VALUES (?, ?, 'delete', ?, ?, TRUE)
          `, [file.id, req.user.id, req.ip, req.get('User-Agent')]);

          deletedFiles.push({
            id: file.id,
            name: file.original_name
          });

        } catch (error) {
          console.error(`Error deleting file ${file.id}:`, error);
          errors.push({
            fileId: file.id,
            fileName: file.original_name,
            error: error.message
          });
        }
      }

      // Audit log
      await auditLog({
        userId: req.user.id,
        action: 'BULK_FILE_DELETE',
        resourceType: 'file',
        details: JSON.stringify({
          requestedCount: fileIds.length,
          deletedCount: deletedFiles.length,
          errorCount: errors.length,
          deletedFiles: deletedFiles.map(f => f.name)
        }),
        ipAddress: req.ip
      });

      res.json({
        message: `Bulk deletion completed. ${deletedFiles.length} files deleted.`,
        deleted: deletedFiles,
        errors: errors
      });

    } catch (error) {
      console.error('Bulk delete error:', error);
      res.status(500).json({
        error: 'Bulk deletion failed',
        message: 'Internal server error'
      });
    }
  }
);

module.exports = router;