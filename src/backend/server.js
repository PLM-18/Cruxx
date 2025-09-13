const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const Joi = require('joi');
const multer = require('multer');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'your-32-char-encryption-key-here!';
console.log("ENCRYPTION_KEY", ENCRYPTION_KEY.toString('hex'));

// Security middleware
app.use(helmet());
app.use(cors({
    origin: ['http://localhost:5173', 'http://localhost:5174'],
    credentials: true
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});

const authLimiter = rateLimit({
    windowMs: 4 * 60 * 1000, // 4 minutes
    max: 9, // limit each IP to 9 requests per windowMs
    message: 'Too many authentication attempts, please try again later.'
});

app.use(limiter);
app.use('/login', authLimiter);
app.use('/register', authLimiter);

app.use(express.json());

// Ensure directories exist
const directories = ['uploads/evidence', 'uploads/images', 'uploads/documents', 'uploads/confidential'];
directories.forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

// Database setup
const db = new sqlite3.Database('forensiclink.db');

db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        surname TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'Analyst',
        approved BOOLEAN DEFAULT FALSE,
        mfa_enabled BOOLEAN DEFAULT FALSE,
        mfa_secret TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Workspaces table
    db.run(`CREATE TABLE IF NOT EXISTS workspaces (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        case_number TEXT UNIQUE,
        created_by INTEGER NOT NULL,
        status TEXT DEFAULT 'Active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users (id)
    )`);

    // Workspace members table
    db.run(`CREATE TABLE IF NOT EXISTS workspace_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        workspace_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        role TEXT DEFAULT 'Analyst',
        added_by INTEGER NOT NULL,
        added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (added_by) REFERENCES users (id),
        UNIQUE(workspace_id, user_id)
    )`);

    // Evidence table
    db.run(`CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        workspace_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        file_path TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        file_hash TEXT NOT NULL,
        mime_type TEXT NOT NULL,
        uploaded_by INTEGER NOT NULL,
        description TEXT,
        tags TEXT,
        status TEXT DEFAULT 'Active',
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
        FOREIGN KEY (uploaded_by) REFERENCES users (id)
    )`);

    // Audit logs table
    db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        workspace_id INTEGER,
        evidence_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT NOT NULL,
        user_agent TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
        FOREIGN KEY (evidence_id) REFERENCES evidence (id)
    )`);

    // Access logs table
    db.run(`CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        endpoint TEXT NOT NULL,
        method TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        user_agent TEXT,
        success BOOLEAN NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Create default admin user
    const adminEmail = 'admin@forensiclink.com';
    const adminPassword = 'forensiclink2024';

    db.get("SELECT id FROM users WHERE email = ?", [adminEmail], async (err, row) => {
        if (!row) {
            try {
                const hashedPassword = await bcrypt.hash(adminPassword, 12);
                db.run(
                    "INSERT INTO users (name, surname, email, password, role, approved) VALUES (?, ?, ?, ?, ?, ?)",
                    ['Admin', 'User', adminEmail, hashedPassword, 'Admin', true],
                    function(err) {
                        if (err) {
                            console.error('Error creating admin user:', err);
                        } else {
                            console.log('✅ Default admin user created successfully');
                            console.log('📧 Email:', adminEmail);
                            console.log('🔑 Password:', adminPassword);
                        }
                    }
                );
            } catch (error) {
                console.error('Error hashing admin password:', error);
            }
        }
    });
});

// Validation schemas
const registerSchema = Joi.object({
    name: Joi.string().min(2).max(50).required(),
    surname: Joi.string().min(2).max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(8).pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])')).required()
});

const loginSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
});

// Logging function
const logAccess = (userId, endpoint, action, ipAddress, userAgent, success) => {
    db.run(
        "INSERT INTO access_logs (user_id, endpoint, action, ip_address, user_agent, success) VALUES (?, ?, ?, ?, ?, ?)",
        [userId, endpoint, action, ipAddress, userAgent, success]
    );
};

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        logAccess(null, req.path, req.method, req.ip, req.get('User-Agent'), false);
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            logAccess(null, req.path, req.method, req.ip, req.get('User-Agent'), false);
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// MFA Status endpoint
app.get('/mfa-status', authenticateToken, (req, res) => {
    db.get(
        "SELECT mfa_enabled FROM users WHERE id = ?",
        [req.user.id],
        (err, user) => {
            if (err || !user) {
                return res.status(404).json({ error: 'User not found' });
            }

            logAccess(req.user.id, '/mfa-status', 'GET', req.ip, req.get('User-Agent'), true);
            res.json({
                mfaEnabled: Boolean(user.mfa_enabled)
            });
        }
    );
});
// Role authorization middleware
const authorizeRoles = (roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            logAccess(req.user.id, req.path, req.method, req.ip, req.get('User-Agent'), false);
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
};

// Audit logging function
function logAudit(userId, workspaceId, evidenceId, action, details, req) {
    db.run(
        "INSERT INTO audit_logs (user_id, workspace_id, evidence_id, action, details, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [userId, workspaceId, evidenceId, action, details, req.ip, req.get('User-Agent')],
        (err) => {
            if (err) console.error('Audit log error:', err);
        }
    );
}

// File encryption/decryption functions
const encrypt = (text) => {
    const iv = crypto.randomBytes(16);
    const enc_key_hex = Buffer.from(ENCRYPTION_KEY, "hex")
    const cipher = crypto.createCipheriv('aes-256-cbc', enc_key_hex,iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
};

const decrypt = (text) => {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = textParts.join(':');
    const enc_key_hex = Buffer.from(ENCRYPTION_KEY, "hex")
    const decipher = crypto.createDecipheriv('aes-256-cbc', enc_key_hex,iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
};

// Routes

// Registration endpoint
app.post('/register', [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])/),
    body('name').isLength({ min: 2, max: 50 }).trim(),
    body('surname').isLength({ min: 2, max: 50 }).trim()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { error, value } = registerSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ error: error.details[0].message });
        }

        const { name, surname, email, password } = value;

        // Check if user already exists
        db.get("SELECT id FROM users WHERE email = ?", [email], async (err, row) => {
            if (row) {
                return res.status(409).json({ error: 'User already exists' });
            }

            const hashedPassword = await bcrypt.hash(password, 12);

            db.run(
                "INSERT INTO users (name, surname, email, password, approved) VALUES (?, ?, ?, ?, ?)",
                [name, surname, email, hashedPassword, false],
                function (err) {
                    if (err) {
                        console.error('Registration error:', err);
                        return res.status(500).json({ error: 'Registration failed' });
                    }

                    console.log('✅ User registered successfully:', email);
                    logAccess(this.lastID, '/register', 'POST', req.ip, req.get('User-Agent'), true);
                    
                    res.status(201).json({
                        message: 'Registration successful! Your account is pending admin approval.',
                        userId: this.lastID,
                        success: true
                    });
                }
            );
        });
    } catch (error) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login endpoint
app.post('/login', [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;

        db.get(
            "SELECT id, name, surname, email, password, role, approved, mfa_enabled FROM users WHERE email = ?",
            [email],
            async (err, user) => {
                if (err) {
                    logAccess(null, '/login', 'POST', req.ip, req.get('User-Agent'), false);
                    return res.status(500).json({ error: 'Database error' });
                }
                
                if (!user) {
                    logAccess(null, '/login', 'POST', req.ip, req.get('User-Agent'), false);
                    return res.status(401).json({ error: 'Invalid credentials' });
                }

                if (!user.approved) {
                    logAccess(user.id, '/login', 'POST', req.ip, req.get('User-Agent'), false);
                    return res.status(403).json({ error: 'Account not approved yet' });
                }

                const validPassword = await bcrypt.compare(password, user.password);
                
                if (!validPassword) {
                    logAccess(user.id, '/login', 'POST', req.ip, req.get('User-Agent'), false);
                    return res.status(401).json({ error: 'Invalid credentials' });
                }

                const token = jwt.sign(
                    {
                        id: user.id,
                        email: user.email,
                        role: user.role,
                        mfaEnabled: user.mfa_enabled
                    },
                    JWT_SECRET,
                    { expiresIn: '1h' }
                );

                if (user.mfa_enabled) {
                    const tempToken = jwt.sign(
                        { id: user.id, email: user.email, temp: true },
                        JWT_SECRET,
                        { expiresIn: '10m' }
                    );

                    res.json({
                        requiresMFA: true,
                        tempToken: tempToken
                    });
                } else {
                    logAccess(user.id, '/login', 'POST', req.ip, req.get('User-Agent'), true);
                    res.json({
                        token: token,
                        user: {
                            id: user.id,
                            name: user.name,
                            surname: user.surname,
                            email: user.email,
                            role: user.role
                        }
                    });
                }
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// Admin management endpoints
app.get('/manage', authenticateToken, authorizeRoles(['Admin', 'Manager']), (req, res) => {
    db.all(
        "SELECT id, name, surname, email, role, approved, created_at FROM users ORDER BY created_at DESC",
        [],
        (err, users) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to fetch users' });
            }

            logAccess(req.user.id, '/manage', 'GET', req.ip, req.get('User-Agent'), true);
            res.json(users);
        }
    );
});

// Approve user
app.post('/manage/approve', authenticateToken, authorizeRoles(['Admin', 'Manager']), (req, res) => {
    const { userId } = req.body;

    db.run(
        "UPDATE users SET approved = TRUE WHERE id = ?",
        [userId],
        function (err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to approve user' });
            }

            logAccess(req.user.id, '/manage/approve', 'POST', req.ip, req.get('User-Agent'), true);
            res.json({ message: 'User approved successfully' });
        }
    );
});

// Revoke user
app.post('/manage/revoke', authenticateToken, authorizeRoles(['Admin']), (req, res) => {
    const { userId } = req.body;

    db.run(
        "UPDATE users SET approved = FALSE WHERE id = ?",
        [userId],
        function (err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to revoke user' });
            }

            logAccess(req.user.id, '/manage/revoke', 'POST', req.ip, req.get('User-Agent'), true);
            res.json({ message: 'User revoked successfully' });
        }
    );
});