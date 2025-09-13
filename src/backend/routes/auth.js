const express = require('express');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const database = require('../database/connection');
const encryption = require('../utils/encryption');
const emailService = require('../utils/email');
const { auditLog } = require('../utils/audit');
const { authenticateToken, sensitiveRateLimit } = require('../middleware/auth');

const router = express.Router();

// Validation middleware
const registerValidation = [
  body('name').trim().isLength({ min: 2, max: 100 }).withMessage('Name must be 2-100 characters'),
  body('surname').trim().isLength({ min: 2, max: 100 }).withMessage('Surname must be 2-100 characters'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain uppercase, lowercase, number and special character'),
  body('role').isIn(['analyst', 'manager']).withMessage('Role must be analyst or manager')
];

const loginValidation = [
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('password').notEmpty().withMessage('Password required')
];

// User Registration
router.post('/register', registerValidation, async (req, res) => {
  try {
    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { name, surname, email, password, role } = req.body;

    // Check if user already exists
    const existingUser = await database.get('SELECT id FROM users WHERE email = ?', [email]);
    if (existingUser) {
      return res.status(409).json({
        error: 'User already exists',
        message: 'An account with this email already exists'
      });
    }

    // Generate RSA key pair for encryption
    const { publicKey, privateKey } = encryption.generateKeyPair();

    // Hash password
    const passwordHash = await encryption.hashPassword(password);

    // Generate verification code
    const verificationCode = encryption.generateVerificationCode();
    const verificationExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    // Insert user
    const result = await database.run(`
      INSERT INTO users (name, surname, email, password_hash, role, verification_code, 
                        verification_expires, public_key, private_key)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [name, surname, email, passwordHash, role, verificationCode, 
        verificationExpires.toISOString(), publicKey, privateKey]);

    // Send verification email
    await emailService.sendVerificationCode(email, verificationCode);

    // Audit log
    await auditLog({
      userId: result.id,
      action: 'USER_REGISTERED',
      resourceType: 'user',
      resourceId: result.id,
      details: JSON.stringify({ role, email }),
      ipAddress: req.ip
    });

    res.status(201).json({
      message: 'Registration successful',
      userId: result.id,
      verificationRequired: true
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      error: 'Registration failed',
      message: 'Internal server error'
    });
  }
});

// Email Verification
router.post('/verify-email', [
  body('email').isEmail().normalizeEmail(),
  body('verificationCode').isLength({ min: 4, max: 4 }).isNumeric()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { email, verificationCode } = req.body;

    // Find user with verification code
    const user = await database.get(`
      SELECT id, verification_code, verification_expires, verified
      FROM users WHERE email = ?
    `, [email]);

    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'No account found with this email'
      });
    }

    if (user.verified) {
      return res.status(400).json({
        error: 'Already verified',
        message: 'Account is already verified'
      });
    }

    // Check verification code and expiration
    if (user.verification_code !== verificationCode) {
      await auditLog({
        userId: user.id,
        action: 'VERIFICATION_FAILED',
        resourceType: 'user',
        details: JSON.stringify({ reason: 'invalid_code' }),
        ipAddress: req.ip
      });

      return res.status(400).json({
        error: 'Invalid code',
        message: 'Verification code is incorrect'
      });
    }

    if (new Date() > new Date(user.verification_expires)) {
      return res.status(400).json({
        error: 'Code expired',
        message: 'Verification code has expired'
      });
    }

    // Verify user
    await database.run(`
      UPDATE users 
      SET verified = TRUE, verification_code = NULL, verification_expires = NULL
      WHERE id = ?
    `, [user.id]);

    // Audit log
    await auditLog({
      userId: user.id,
      action: 'EMAIL_VERIFIED',
      resourceType: 'user',
      details: JSON.stringify({ email }),
      ipAddress: req.ip
    });

    res.json({
      message: 'Email verified successfully',
      verified: true
    });

  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({
      error: 'Verification failed',
      message: 'Internal server error'
    });
  }
});

// Login Step 1 - Validate credentials and send login code
router.post('/login', sensitiveRateLimit, loginValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { email, password } = req.body;

    // Find user
    const user = await database.get(`
      SELECT id, email, password_hash, role, verified, admin_approved
      FROM users WHERE email = ?
    `, [email]);

    if (!user || !await encryption.comparePassword(password, user.password_hash)) {
      await auditLog({
        action: 'LOGIN_FAILED',
        resourceType: 'user',
        details: JSON.stringify({ email, reason: 'invalid_credentials' }),
        ipAddress: req.ip
      });

      return res.status(401).json({
        error: 'Invalid credentials',
        message: 'Email or password is incorrect'
      });
    }

    if (!user.verified) {
      return res.status(403).json({
        error: 'Account not verified',
        message: 'Please verify your email address first'
      });
    }

    if (!user.admin_approved) {
      return res.status(403).json({
        error: 'Account not approved',
        message: 'Your account is pending admin approval'
      });
    }

    // Generate login verification code
    const loginCode = encryption.generateVerificationCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Store verification code
    await database.run(`
      INSERT INTO verification_codes (user_id, code, code_type, expires_at)
      VALUES (?, ?, 'login_verification', ?)
    `, [user.id, loginCode, expiresAt.toISOString()]);

    // Send login code via email
    await emailService.sendLoginCode(email, loginCode);

    res.json({
      message: 'Login code sent',
      codeRequired: true,
      email: email
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      error: 'Login failed',
      message: 'Internal server error'
    });
  }
});

// Login Step 2 - Verify login code and generate tokens
router.post('/verify-login', [
  body('email').isEmail().normalizeEmail(),
  body('loginCode').isLength({ min: 4, max: 4 }).isNumeric()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { email, loginCode } = req.body;

    // Find user and verification code
    const verification = await database.get(`
      SELECT vc.*, u.id as user_id, u.email, u.role, u.name, u.surname
      FROM verification_codes vc
      JOIN users u ON u.id = vc.user_id
      WHERE u.email = ? AND vc.code = ? AND vc.code_type = 'login_verification' 
        AND vc.used = FALSE AND vc.expires_at > datetime('now')
    `, [email, loginCode]);

    if (!verification) {
      await auditLog({
        action: 'LOGIN_VERIFICATION_FAILED',
        resourceType: 'user',
        details: JSON.stringify({ email, reason: 'invalid_or_expired_code' }),
        ipAddress: req.ip
      });

      return res.status(400).json({
        error: 'Invalid or expired code',
        message: 'Login verification code is invalid or has expired'
      });
    }

    // Mark verification code as used
    await database.run('UPDATE verification_codes SET used = TRUE WHERE id = ?', [verification.id]);

    // Generate JWT tokens
    const payload = {
      userId: verification.user_id,
      email: verification.email,
      role: verification.role
    };

    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || '1h'
    });

    const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
      expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d'
    });

    // Audit log
    await auditLog({
      userId: verification.user_id,
      action: 'LOGIN_SUCCESS',
      resourceType: 'user',
      details: JSON.stringify({ email }),
      ipAddress: req.ip
    });

    res.json({
      message: 'Login successful',
      user: {
        id: verification.user_id,
        name: verification.name,
        surname: verification.surname,
        email: verification.email,
        role: verification.role
      },
      tokens: {
        access: accessToken,
        refresh: refreshToken
      }
    });

  } catch (error) {
    console.error('Login verification error:', error);
    res.status(500).json({
      error: 'Login verification failed',
      message: 'Internal server error'
    });
  }
});

// Refresh Token
router.post('/refresh', [
  body('refreshToken').notEmpty().withMessage('Refresh token required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { refreshToken } = req.body;

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    // Check if user still exists and is approved
    const user = await database.get(`
      SELECT id, email, role, verified, admin_approved
      FROM users WHERE id = ?
    `, [decoded.userId]);

    if (!user || !user.verified || !user.admin_approved) {
      return res.status(401).json({
        error: 'Invalid refresh token',
        message: 'User not found or account status changed'
      });
    }

    // Generate new access token
    const newAccessToken = jwt.sign({
      userId: user.id,
      email: user.email,
      role: user.role
    }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || '1h'
    });

    res.json({
      accessToken: newAccessToken
    });

  } catch (error) {
    if (error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: 'Invalid refresh token',
        message: 'Refresh token is invalid or expired'
      });
    }

    console.error('Token refresh error:', error);
    res.status(500).json({
      error: 'Token refresh failed',
      message: 'Internal server error'
    });
  }
});

// Workspace MFA Verification
router.post('/workspace-mfa', authenticateToken, [
  body('workspaceId').isInt().withMessage('Valid workspace ID required'),
  body('mfaToken').isLength({ min: 6, max: 6 }).isNumeric().withMessage('Valid MFA token required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { workspaceId, mfaToken } = req.body;

    // Get workspace membership with MFA secret
    const membership = await database.get(`
      SELECT wm.*, w.name as workspace_name
      FROM workspace_members wm
      JOIN workspaces w ON w.id = wm.workspace_id
      WHERE wm.workspace_id = ? AND wm.user_id = ? AND wm.mfa_enabled = TRUE
    `, [workspaceId, req.user.id]);

    if (!membership) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You are not a member of this workspace or MFA is not set up'
      });
    }

    // Verify MFA token
    const verified = speakeasy.totp.verify({
      secret: membership.mfa_secret,
      encoding: 'base32',
      token: mfaToken,
      window: parseInt(process.env.MFA_WINDOW) || 1
    });

    if (!verified) {
      await auditLog({
        userId: req.user.id,
        action: 'MFA_VERIFICATION_FAILED',
        resourceType: 'workspace',
        resourceId: workspaceId,
        details: JSON.stringify({ reason: 'invalid_token' }),
        ipAddress: req.ip
      });

      return res.status(400).json({
        error: 'Invalid MFA token',
        message: 'The provided MFA token is incorrect'
      });
    }

    // Generate workspace MFA session token (valid for 8 hours)
    const mfaSessionToken = jwt.sign({
      userId: req.user.id,
      workspaceId: workspaceId,
      type: 'workspace_mfa'
    }, process.env.JWT_SECRET, {
      expiresIn: '8h'
    });

    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'WORKSPACE_MFA_SUCCESS',
      resourceType: 'workspace',
      resourceId: workspaceId,
      details: JSON.stringify({ workspaceName: membership.workspace_name }),
      ipAddress: req.ip
    });

    res.json({
      message: 'MFA verification successful',
      mfaSessionToken: mfaSessionToken,
      workspace: {
        id: workspaceId,
        name: membership.workspace_name,
        accessLevel: membership.access_level
      }
    });

  } catch (error) {
    console.error('Workspace MFA error:', error);
    res.status(500).json({
      error: 'MFA verification failed',
      message: 'Internal server error'
    });
  }
});

// Logout
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    // Audit log
    await auditLog({
      userId: req.user.id,
      action: 'USER_LOGOUT',
      resourceType: 'user',
      details: JSON.stringify({ email: req.user.email }),
      ipAddress: req.ip
    });

    res.json({
      message: 'Logout successful'
    });

  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      error: 'Logout failed',
      message: 'Internal server error'
    });
  }
});

module.exports = router;