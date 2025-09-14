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
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '78a4afd45665c9af0e0cf0d41c0c4f638de30e38558ddcd42bd78ec897db3aaf'; // Must be 32 characters for AES-256

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
    max: 29, // limit each IP to 9 requests per windowMs
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

    // User XP table
    db.run(`CREATE TABLE IF NOT EXISTS user_xp (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        total_xp INTEGER DEFAULT 0,
        level INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Achievements table
    db.run(`CREATE TABLE IF NOT EXISTS achievements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        xp_reward INTEGER NOT NULL,
        achievement_type TEXT NOT NULL,
        target_value INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // User achievements table
    db.run(`CREATE TABLE IF NOT EXISTS user_achievements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        achievement_id INTEGER NOT NULL,
        earned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (achievement_id) REFERENCES achievements (id),
        UNIQUE(user_id, achievement_id)
    )`);

    // XP transactions table
    db.run(`CREATE TABLE IF NOT EXISTS xp_transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        xp_amount INTEGER NOT NULL,
        source TEXT NOT NULL,
        description TEXT,
        evidence_id INTEGER,
        achievement_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (evidence_id) REFERENCES evidence (id),
        FOREIGN KEY (achievement_id) REFERENCES achievements (id)
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

    // Create default achievements
    const defaultAchievements = [
        {
            name: "First Upload",
            description: "Upload your first piece of evidence",
            xp_reward: 50,
            achievement_type: "first_upload",
            target_value: 1
        },
        {
            name: "Evidence Collector",
            description: "Upload 10 pieces of evidence",
            xp_reward: 200,
            achievement_type: "upload_count",
            target_value: 10
        },
        {
            name: "Digital Investigator",
            description: "Upload 50 pieces of evidence",
            xp_reward: 500,
            achievement_type: "upload_count",
            target_value: 50
        },
        {
            name: "Big File Handler",
            description: "Upload a file larger than 25MB",
            xp_reward: 100,
            achievement_type: "large_file",
            target_value: 26214400 // 25MB in bytes
        },
        {
            name: "Data Analyst",
            description: "Upload 100MB total of data",
            xp_reward: 300,
            achievement_type: "total_size",
            target_value: 104857600 // 100MB in bytes
        }
    ];

    // Check if achievements already exist, if not, create them
    db.get("SELECT COUNT(*) as count FROM achievements", [], (err, result) => {
        if (!err && result.count === 0) {
            defaultAchievements.forEach(achievement => {
                db.run(
                    "INSERT INTO achievements (name, description, xp_reward, achievement_type, target_value) VALUES (?, ?, ?, ?, ?)",
                    [achievement.name, achievement.description, achievement.xp_reward, achievement.achievement_type, achievement.target_value],
                    function(err) {
                        if (err) {
                            console.error('Error creating achievement:', err);
                        }
                    }
                );
            });
            console.log('✅ Default achievements created successfully');
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

// Password verification endpoint (for re-authentication checks)
app.post('/verify-credentials', [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ valid: false });
        }

        const { email, password } = req.body;

        db.get(
            "SELECT id, password, approved FROM users WHERE email = ?",
            [email],
            async (err, user) => {
                if (err) {
                    logAccess(null, '/verify-credentials', 'POST', req.ip, req.get('User-Agent'), false);
                    return res.status(500).json({ valid: false });
                }
                
                if (!user || !user.approved) {
                    logAccess(user?.id || null, '/verify-credentials', 'POST', req.ip, req.get('User-Agent'), false);
                    return res.json({ valid: false });
                }

                const validPassword = await bcrypt.compare(password, user.password);
                
                logAccess(user.id, '/verify-credentials', 'POST', req.ip, req.get('User-Agent'), validPassword);
                res.json({ valid: validPassword });
            }
        );
    } catch (error) {
        logAccess(null, '/verify-credentials', 'POST', req.ip, req.get('User-Agent'), false);
        res.json({ valid: false });
    }
});

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

// Gamification functions
const initializeUserXP = (userId, callback) => {
    db.run(
        "INSERT OR IGNORE INTO user_xp (user_id, total_xp, level) VALUES (?, 0, 1)",
        [userId],
        callback
    );
};

const calculateLevel = (totalXP) => {
    return Math.floor(totalXP / 1000) + 1;
};

const awardXP = (userId, xpAmount, source, description, evidenceId = null, achievementId = null, callback) => {
    db.run(
        "INSERT INTO xp_transactions (user_id, xp_amount, source, description, evidence_id, achievement_id) VALUES (?, ?, ?, ?, ?, ?)",
        [userId, xpAmount, source, description, evidenceId, achievementId],
        function(err) {
            if (err) return callback(err);

            db.run(
                "INSERT OR REPLACE INTO user_xp (user_id, total_xp, level, updated_at) SELECT ?, COALESCE((SELECT total_xp FROM user_xp WHERE user_id = ?), 0) + ?, ?, CURRENT_TIMESTAMP",
                [userId, userId, xpAmount, calculateLevel],
                function(updateErr) {
                    if (updateErr) return callback(updateErr);

                    db.get(
                        "SELECT total_xp FROM user_xp WHERE user_id = ?",
                        [userId],
                        (selectErr, row) => {
                            if (selectErr) return callback(selectErr);
                            const newLevel = calculateLevel(row.total_xp);
                            
                            db.run(
                                "UPDATE user_xp SET level = ? WHERE user_id = ?",
                                [newLevel, userId],
                                () => callback(null, { xpAwarded: xpAmount, newTotal: row.total_xp, newLevel })
                            );
                        }
                    );
                }
            );
        }
    );
};

const checkAchievements = (userId, callback) => {
    db.all(
        `SELECT 
            a.*,
            ua.id as user_achievement_id,
            (
                CASE 
                    WHEN a.achievement_type = 'upload_count' THEN (
                        SELECT COUNT(*) FROM evidence WHERE uploaded_by = ?
                    )
                    WHEN a.achievement_type = 'total_size' THEN (
                        SELECT COALESCE(SUM(file_size), 0) FROM evidence WHERE uploaded_by = ?
                    )
                    WHEN a.achievement_type = 'large_file' THEN (
                        SELECT MAX(file_size) FROM evidence WHERE uploaded_by = ?
                    )
                    WHEN a.achievement_type = 'first_upload' THEN (
                        SELECT COUNT(*) FROM evidence WHERE uploaded_by = ?
                    )
                    ELSE 0
                END
            ) as current_progress
        FROM achievements a 
        LEFT JOIN user_achievements ua ON a.id = ua.achievement_id AND ua.user_id = ?
        WHERE ua.id IS NULL`,
        [userId, userId, userId, userId, userId],
        (err, unearned) => {
            if (err) return callback(err);

            const newAchievements = [];
            let completed = 0;

            if (unearned.length === 0) {
                return callback(null, []);
            }

            unearned.forEach(achievement => {
                if (achievement.current_progress >= achievement.target_value) {
                    db.run(
                        "INSERT INTO user_achievements (user_id, achievement_id) VALUES (?, ?)",
                        [userId, achievement.id],
                        function(insertErr) {
                            if (insertErr) {
                                console.error('Error recording achievement:', insertErr);
                            } else {
                                awardXP(userId, achievement.xp_reward, 'achievement', `Achievement unlocked: ${achievement.name}`, null, achievement.id, (xpErr) => {
                                    if (xpErr) console.error('Error awarding achievement XP:', xpErr);
                                });
                                newAchievements.push(achievement);
                            }
                            
                            completed++;
                            if (completed === unearned.length) {
                                callback(null, newAchievements);
                            }
                        }
                    );
                } else {
                    completed++;
                    if (completed === unearned.length) {
                        callback(null, newAchievements);
                    }
                }
            });
        }
    );
};

const calculateFileXP = (fileSize) => {
    const baseXP = 10;
    const sizeMultiplier = 0.000001; // 1 XP per MB
    return Math.floor(baseXP + (fileSize * sizeMultiplier));
};

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
                    
                    // Initialize XP for new user
                    const userId = this.lastID;
                    initializeUserXP(userId, () => {
                        res.status(201).json({
                            message: 'Registration successful! Your account is pending admin approval.',
                            userId: userId,
                            success: true
                        });
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

// Assign role
app.post('/manage/role', authenticateToken, authorizeRoles(['Admin']), (req, res) => {
    const { userId, role } = req.body;

    if (!['Admin', 'Manager', 'Analyst'].includes(role)) {
        return res.status(400).json({ error: 'Invalid role' });
    }

    db.run(
        "UPDATE users SET role = ? WHERE id = ?",
        [role, userId],
        function (err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to assign role' });
            }

            logAccess(req.user.id, '/manage/role', 'POST', req.ip, req.get('User-Agent'), true);
            res.json({ message: 'Role assigned successfully' });
        }
    );
});

// Get available managers (Admin only)
app.get('/managers', authenticateToken, authorizeRoles(['Admin']), (req, res) => {
    db.all(
        "SELECT id, name, surname, email FROM users WHERE role = 'Manager' AND approved = 1 ORDER BY name, surname",
        [],
        (err, managers) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to fetch managers' });
            }
            res.json(managers || []);
        }
    );
});

// Create workspace (Admin only, with manager assignment)
app.post('/workspaces', authenticateToken, authorizeRoles(['Admin']), (req, res) => {
    const { name, description, case_number, assigned_manager } = req.body;

    if (!name || name.trim().length < 3) {
        return res.status(400).json({ error: 'Workspace name must be at least 3 characters' });
    }

    if (!assigned_manager) {
        return res.status(400).json({ error: 'Manager assignment is required' });
    }

    // Verify the assigned manager exists and has Manager role
    db.get("SELECT id, role FROM users WHERE id = ? AND approved = 1", [assigned_manager], (err, manager) => {
        if (err || !manager) {
            return res.status(404).json({ error: 'Manager not found or not approved' });
        }

        if (manager.role !== 'Manager') {
            return res.status(400).json({ error: 'Assigned user must have Manager role' });
        }

        db.run(
            "INSERT INTO workspaces (name, description, case_number, created_by) VALUES (?, ?, ?, ?)",
            [name.trim(), description || '', case_number || null, req.user.id],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.status(409).json({ error: 'Case number already exists' });
                    }
                    return res.status(500).json({ error: 'Failed to create workspace' });
                }

                // Add the assigned manager to the workspace with Manager role
                db.run(
                    "INSERT INTO workspace_members (workspace_id, user_id, role, added_by) VALUES (?, ?, ?, ?)",
                    [this.lastID, assigned_manager, 'Manager', req.user.id],
                    (err) => {
                        if (err) {
                            console.error('Error adding manager to workspace:', err);
                            return res.status(500).json({ error: 'Failed to assign manager to workspace' });
                        }

                        logAudit(req.user.id, this.lastID, null, 'CREATE_WORKSPACE', 
                               `Created workspace: ${name}, assigned manager ID: ${assigned_manager}`, req);
                        
                        res.status(201).json({
                            message: 'Workspace created and manager assigned successfully',
                            workspaceId: this.lastID,
                            name: name
                        });
                    }
                );
            }
        );
    });
});

// Get user's workspaces (with proper role-based access)
app.get('/workspaces', authenticateToken, (req, res) => {
    let query, params;

    if (req.user.role === 'Admin') {
        // Admins can see all workspaces
        query = `
            SELECT DISTINCT w.*, u.name as creator_name, u.surname as creator_surname,
                   'Admin' as user_role,
                   COUNT(e.id) as evidence_count,
                   m.name as manager_name, m.surname as manager_surname
            FROM workspaces w
            LEFT JOIN users u ON w.created_by = u.id
            LEFT JOIN evidence e ON w.id = e.workspace_id AND e.status = 'Active'
            LEFT JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.role = 'Manager'
            LEFT JOIN users m ON wm.user_id = m.id
            GROUP BY w.id
            ORDER BY w.updated_at DESC
        `;
        params = [];
    } else {
        // Managers and Analysts only see workspaces they're members of
        query = `
            SELECT DISTINCT w.*, u.name as creator_name, u.surname as creator_surname,
                   wm.role as user_role,
                   COUNT(e.id) as evidence_count,
                   m.name as manager_name, m.surname as manager_surname
            FROM workspaces w
            LEFT JOIN users u ON w.created_by = u.id
            LEFT JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
            LEFT JOIN evidence e ON w.id = e.workspace_id AND e.status = 'Active'
            LEFT JOIN workspace_members wm2 ON w.id = wm2.workspace_id AND wm2.role = 'Manager'
            LEFT JOIN users m ON wm2.user_id = m.id
            WHERE wm.user_id = ?
            GROUP BY w.id
            ORDER BY w.updated_at DESC
        `;
        params = [req.user.id, req.user.id];
    }

    db.all(query, params, (err, rows) => {
        if (err) {
            console.error('Error fetching workspaces:', err);
            return res.status(500).json({ error: 'Failed to fetch workspaces' });
        }

        res.json(rows || []);
    });
});

// Get workspace details
app.get('/workspaces/:id', authenticateToken, (req, res) => {
    const workspaceId = req.params.id;

    // Check if user has access to this workspace
    const accessQuery = `
        SELECT w.*, u.name as creator_name, u.surname as creator_surname,
               wm.role as user_role
        FROM workspaces w
        LEFT JOIN users u ON w.created_by = u.id
        LEFT JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
        WHERE w.id = ? AND (wm.user_id = ? OR ? = 'Admin')
    `;

    db.get(accessQuery, [req.user.id, workspaceId, req.user.id, req.user.role], (err, workspace) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (!workspace) {
            return res.status(404).json({ error: 'Workspace not found or access denied' });
        }

        // Get workspace members
        const membersQuery = `
            SELECT wm.*, u.name, u.surname, u.email, u.role as user_system_role
            FROM workspace_members wm
            JOIN users u ON wm.user_id = u.id
            WHERE wm.workspace_id = ?
            ORDER BY wm.added_at DESC
        `;

        db.all(membersQuery, [workspaceId], (err, members) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to fetch members' });
            }

            res.json({
                ...workspace,
                members: members || []
            });
        });
    });
});

// Add member to workspace (Manager or Admin only, with restrictions)
app.post('/workspaces/:id/members', authenticateToken, (req, res) => {
    const workspaceId = req.params.id;
    const { userId, role = 'Analyst' } = req.body;

    // Check user's permission to add members
    const checkQuery = `
        SELECT wm.role as workspace_role, w.created_by, u.role as system_role
        FROM workspaces w
        LEFT JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
        LEFT JOIN users u ON u.id = ?
        WHERE w.id = ?
    `;

    db.get(checkQuery, [req.user.id, req.user.id, workspaceId], (err, access) => {
        if (err || !access) {
            return res.status(404).json({ error: 'Workspace not found' });
        }

        // Determine if user can add members
        const canManage = access.system_role === 'Admin' || 
                         access.workspace_role === 'Manager';

        if (!canManage) {
            return res.status(403).json({ error: 'Only workspace managers can add members' });
        }

        // Managers can only add Analysts, not other Managers
        if (access.system_role !== 'Admin' && role === 'Manager') {
            return res.status(403).json({ error: 'Only Admins can assign Manager roles' });
        }

        // Check if user exists and is approved
        db.get("SELECT id, name, surname, email, role FROM users WHERE id = ? AND approved = 1", [userId], (err, user) => {
            if (err || !user) {
                return res.status(404).json({ error: 'User not found or not approved' });
            }

            // Add member to workspace
            db.run(
                "INSERT INTO workspace_members (workspace_id, user_id, role, added_by) VALUES (?, ?, ?, ?)",
                [workspaceId, userId, role, req.user.id],
                function(err) {
                    if (err) {
                        if (err.message.includes('UNIQUE constraint failed')) {
                            return res.status(409).json({ error: 'User is already a member of this workspace' });
                        }
                        return res.status(500).json({ error: 'Failed to add member' });
                    }

                    logAudit(req.user.id, workspaceId, null, 'ADD_MEMBER', 
                           `Added ${user.name} ${user.surname} as ${role}`, req);

                    res.json({
                        message: 'Member added successfully',
                        member: {
                            id: userId,
                            name: user.name,
                            surname: user.surname,
                            email: user.email,
                            role: role
                        }
                    });
                }
            );
        });
    });
});

// Get available users for adding to workspace (Manager and Admin)
app.get('/workspaces/:id/available-users', authenticateToken, (req, res) => {
    const workspaceId = req.params.id;

    // Check if user can manage this workspace
    const checkQuery = `
        SELECT wm.role as workspace_role, w.created_by, u.role as system_role
        FROM workspaces w
        LEFT JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
        LEFT JOIN users u ON u.id = ?
        WHERE w.id = ?
    `;

    db.get(checkQuery, [req.user.id, req.user.id, workspaceId], (err, access) => {
        if (err || !access) {
            return res.status(404).json({ error: 'Workspace not found' });
        }

        const canManage = access.system_role === 'Admin' || 
                         access.workspace_role === 'Manager';

        if (!canManage) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }

        // Get users not already in this workspace
        const availableUsersQuery = `
            SELECT u.id, u.name, u.surname, u.email, u.role
            FROM users u
            WHERE u.approved = 1 
            AND u.id NOT IN (
                SELECT wm.user_id 
                FROM workspace_members wm 
                WHERE wm.workspace_id = ?
            )
            AND u.id != ?
            ORDER BY u.name, u.surname
        `;

        db.all(availableUsersQuery, [workspaceId, req.user.id], (err, users) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to fetch available users' });
            }
            res.json(users || []);
        });
    });
});

// Remove member from workspace
app.delete('/workspaces/:id/members/:userId', authenticateToken, (req, res) => {
    const workspaceId = req.params.id;
    const userId = req.params.userId;

    // Check permissions (same as add member)
    const checkQuery = `
        SELECT wm.role, w.created_by
        FROM workspaces w
        LEFT JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
        WHERE w.id = ?
    `;

    db.get(checkQuery, [req.user.id, workspaceId], (err, access) => {
        if (err || !access) {
            return res.status(404).json({ error: 'Workspace not found' });
        }

        const canManage = access.created_by === req.user.id || 
        access.role === 'Admin' || access.workspace_role === 'Manager';

        if (!canManage) {
            return res.status(403).json({ error: 'Insufficient permissions to remove members' });
        }

        // Cannot remove workspace managers (only Admins can do that)
        db.get("SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?", 
            [workspaceId, userId], (err, member) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            if (!member) {
                return res.status(404).json({ error: 'Member not found in workspace' });
            }

            // Only Admins can remove Managers
            if (member.role === 'Manager' && access.system_role !== 'Admin') {
                return res.status(403).json({ error: 'Only Admins can remove workspace managers' });
            }

            db.run(
                "DELETE FROM workspace_members WHERE workspace_id = ? AND user_id = ?",
                [workspaceId, userId],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: 'Failed to remove member' });
                    }

                    if (this.changes === 0) {
                        return res.status(404).json({ error: 'Member not found in workspace' });
                    }

                    logAudit(req.user.id, workspaceId, null, 'REMOVE_MEMBER', `Removed member ID: ${userId}`, req);

                    res.json({ message: 'Member removed successfully' });
                }
            );
        });
    });
});

// Evidence Management Endpoints
                 
// Configure multer for evidence uploads
const evidenceStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, 'uploads', 'evidence'));
    },
    filename: (req, file, cb) => {
        const uniqueName = `${Date.now()}-${uuidv4()}${path.extname(file.originalname)}`;
        cb(null, uniqueName);
    }
});

const evidenceUpload = multer({
    storage: evidenceStorage,
    limits: {
        fileSize: 100 * 1024 * 1024, // 100MB limit
    },
    fileFilter: (req, file, cb) => {
        // Allow common evidence file types
        const allowedTypes = [
            'image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/tiff',
            'application/pdf', 'text/plain', 'text/csv',
            'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed',
            'video/mp4', 'video/avi', 'video/mov', 'audio/mp3', 'audio/wav'
        ];

        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('File type not allowed for evidence upload'), false);
        }
    }
});

// File encryption functions
function encryptFile(filePath, encryptionKey) {
    const algorithm = 'aes-256-cbc';
    const key = crypto.scryptSync(encryptionKey, 'salt', 32);
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipher(algorithm, key);
    const input = fs.createReadStream(filePath);
    const encryptedPath = `${filePath}.enc`;
    const output = fs.createWriteStream(encryptedPath);
    
    return new Promise((resolve, reject) => {
        output.write(iv);
        input.pipe(cipher).pipe(output);
        
        output.on('finish', () => {
            // Remove original file
            fs.unlinkSync(filePath);
            resolve(encryptedPath);
        });
        
        output.on('error', reject);
    });
}

function calculateFileHash(filePath) {
return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    
    stream.on('data', data => hash.update(data));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
});
}

// Upload evidence to workspace
app.post('/workspaces/:id/evidence', authenticateToken, evidenceUpload.single('file'), async (req, res) => {
const workspaceId = req.params.id;
const { description, tags } = req.body;

if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
}

try {
    // Check workspace access
    const accessQuery = `
        SELECT wm.role, w.created_by
        FROM workspaces w
        LEFT JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
        WHERE w.id = ? AND (wm.user_id = ? OR ? = 'Admin')
    `;

    db.get(accessQuery, [req.user.id, workspaceId, req.user.id, req.user.role], async (err, access) => {
        if (err || !access) {
            // Clean up uploaded file
            fs.unlinkSync(req.file.path);
            return res.status(404).json({ error: 'Workspace not found or access denied' });
        }

        try {
            // Calculate file hash before encryption
            const fileHash = await calculateFileHash(req.file.path);
            
            // Encrypt the file
            const encryptedPath = await encrypt(req.file.path);
            
            // Store evidence metadata in database
            db.run(
                `INSERT INTO evidence (workspace_id, filename, original_filename, file_path, file_size, 
                file_hash, mime_type, uploaded_by, description, tags) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    workspaceId,
                    req.file.filename,
                    req.file.originalname,
                    encryptedPath,
                    req.file.size,
                    fileHash,
                    req.file.mimetype,
                    req.user.id,
                    description || '',
                    tags || ''
                ],
                function(err) {
                    if (err) {
                        console.error('Database error:', err);
                        // Clean up encrypted file
                        fs.unlinkSync(encryptedPath);
                        return res.status(500).json({ error: 'Failed to save evidence metadata' });
                    }

                    logAudit(req.user.id, workspaceId, this.lastID, 'UPLOAD_EVIDENCE', 
                        `Uploaded: ${req.file.originalname}`, req);

                    const evidenceId = this.lastID;
                    
                    // Initialize user XP if not exists
                    initializeUserXP(req.user.id, () => {
                        // Calculate and award XP for file upload
                        const fileXP = calculateFileXP(req.file.size);
                        
                        awardXP(req.user.id, fileXP, 'file_upload', `File uploaded: ${req.file.originalname}`, evidenceId, null, (xpErr, xpResult) => {
                            if (xpErr) {
                                console.error('Error awarding XP:', xpErr);
                            }

                            // Check for new achievements
                            checkAchievements(req.user.id, (achievementErr, newAchievements) => {
                                if (achievementErr) {
                                    console.error('Error checking achievements:', achievementErr);
                                }

                                res.status(201).json({
                                    message: 'Evidence uploaded successfully',
                                    evidenceId: evidenceId,
                                    filename: req.file.originalname,
                                    fileHash: fileHash,
                                    size: req.file.size,
                                    xp: xpResult || null,
                                    newAchievements: newAchievements || []
                                });
                            });
                        });
                    });
                }
            );
        } catch (error) {
            console.error('File processing error:', error);
            // Clean up file if it exists
            if (fs.existsSync(req.file.path)) {
                fs.unlinkSync(req.file.path);
            }
            res.status(500).json({ error: 'Failed to process uploaded file' });
        }
    });
} catch (error) {
    console.error('Upload error:', error);
    // Clean up uploaded file
    if (req.file && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ error: 'Upload failed' });
}
});

// Get evidence for workspace
app.get('/workspaces/:id/evidence', authenticateToken, (req, res) => {
    const workspaceId = req.params.id;

    // Check workspace access
    const accessQuery = `
        SELECT wm.role, w.created_by
        FROM workspaces w
        LEFT JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
        WHERE w.id = ? AND (wm.user_id = ? OR ? = 'Admin')
    `;

    db.get(accessQuery, [req.user.id, workspaceId, req.user.id, req.user.role], (err, access) => {
        if (err || !access) {
            return res.status(404).json({ error: 'Workspace not found or access denied' });
        }

        // Get evidence list
        const evidenceQuery = `
            SELECT e.*, u.name as uploader_name, u.surname as uploader_surname
            FROM evidence e
            JOIN users u ON e.uploaded_by = u.id
            WHERE e.workspace_id = ? AND e.status = 'Active'
            ORDER BY e.uploaded_at DESC
        `;

        db.all(evidenceQuery, [workspaceId], (err, evidence) => {
            if (err) {
                console.error('Error fetching evidence:', err);
                return res.status(500).json({ error: 'Failed to fetch evidence' });
            }

            res.json(evidence || []);
        });
    });
});

// Legacy file handling endpoints
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const type = req.path.split('/')[1];
        cb(null, `uploads/${type}/`);
    },
    filename: (req, file, cb) => {
        cb(null, uuidv4() + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit
    }
});

// Permission checking function
const hasPermission = (userRole, fileType, action) => {
    const permissions = {
        Admin: {
            images: ['create', 'read', 'write', 'delete', 'list'],
            documents: ['create', 'read', 'write', 'delete', 'list'],
            confidential: ['create', 'read', 'write', 'delete', 'list']
        },
        Manager: {
            images: ['create', 'read', 'write', 'delete', 'list'],
            documents: ['create', 'read', 'write', 'delete', 'list'],
            confidential: ['create', 'read', 'write', 'list']
        },
        Analyst: {
            images: ['create', 'read', 'write', 'list'],
            documents: ['create', 'read', 'write', 'list'],
            confidential: ['read', 'list']
        }
    };

    return permissions[userRole] && permissions[userRole][fileType] && permissions[userRole][fileType].includes(action);
};

// Generic file handling endpoint
const handleFileEndpoint = (fileType) => {
    
    return async (req, res) => {

        let action;
        let filename = req.body.filename;
        
        if (req.body.action)
            action = req.body.action
        else
            action = req.query.action

        if (!hasPermission(req.user.role, fileType, action)) {
            logAccess(req.user.id, `/${fileType}`, req.method, req.ip, req.get('User-Agent'), false);
            return res.status(403).json({ error: 'Insufficient permissions for this action' });
        }

        try {
            switch (action) {
                case 'list':
                    db.all(
                        "SELECT id, original_name, created_at, created_by FROM files WHERE type = ?",
                        [fileType],
                        (err, files) => {
                            if (err) {
                                return res.status(500).json({ error: 'Failed to list files' });
                            }
                            logAccess(req.user.id, `/${fileType}`, req.method, req.ip, req.get('User-Agent'), true);
                            res.json(files);
                        }
                    );
                    break;

                case 'read':
                    let fileId
                    if(req.params.fileId)
                        fileId = req.params.fileId
                    else
                        fileId = req.body.fileId;
                    
                    logAccess(req.user.id, `/document`, req.method, req.ip, req.get('User-Agent'), true);
                    res.sendFile(path.resolve("uploads/evidence/" + filename));
                    
                    break;

                case 'create':
                    if (fileType === 'confidential') {
                        const { filename, content } = req.body;
                        const filePath = path.join('uploads/confidential', `${uuidv4()}.txt`);
                        const encryptedContent = encrypt(content);
                        
                        fs.writeFileSync(filePath, encryptedContent);

                        db.run(
                            "INSERT INTO files (filename, original_name, type, path, encrypted, created_by) VALUES (?, ?, ?, ?, ?, ?)",
                            [path.basename(filePath), filename, fileType, filePath, true, req.user.id],
                            function (err) {
                                if (err) {
                                    return res.status(500).json({ error: 'Failed to create file' });
                                }
                                logAccess(req.user.id, `/${fileType}`, req.method, req.ip, req.get('User-Agent'), true);
                                res.json({ message: 'File created successfully', fileId: this.lastID });
                            }
                        );
                    } else {
                        // Handle file upload for images/documents
                        upload.single('file')(req, res, (err) => {
                            if (err) {
                                return res.status(400).json({ error: 'File upload failed' });
                            }

                            if (!req.file) {
                                return res.status(400).json({ error: 'No file provided' });
                            }

                            db.run(
                                "INSERT INTO files (filename, original_name, type, path, created_by) VALUES (?, ?, ?, ?, ?)",
                                [req.file.filename, req.file.originalname, fileType, req.file.path, req.user.id],
                                function (err) {
                                    if (err) {
                                        return res.status(500).json({ error: 'Failed to save file info' });
                                    }
                                    logAccess(req.user.id, `/${fileType}`, req.method, req.ip, req.get('User-Agent'), true);
                                    res.json({ message: 'File uploaded successfully', fileId: this.lastID });
                                }
                            );
                        });
                    }
                    break;

                default:
                    res.status(400).json({ error: 'Invalid action' });
            }
        } catch (error) {
            logAccess(req.user.id, `/${fileType}`, req.method, req.ip, req.get('User-Agent'), false);
            res.status(500).json({ error: 'Operation failed' });
        }
    };
};

// File endpoints
app.all('/images', authenticateToken, handleFileEndpoint('images'));
app.all('/documents', authenticateToken, handleFileEndpoint('documents'));
app.all('/confidential', authenticateToken, handleFileEndpoint('confidential'));
app.all('/file', authenticateToken, handleFileEndpoint('file'));

// Gamification endpoints

// Get user profile with XP and achievements
app.get('/profile/gamification', authenticateToken, (req, res) => {
    // Initialize user XP if doesn't exist
    initializeUserXP(req.user.id, () => {
        // Get user XP and level
        db.get(
            "SELECT * FROM user_xp WHERE user_id = ?",
            [req.user.id],
            (err, xpData) => {
                if (err) {
                    return res.status(500).json({ error: 'Failed to fetch user XP data' });
                }

                // Get user achievements
                db.all(
                    `SELECT a.*, ua.earned_at 
                     FROM achievements a 
                     JOIN user_achievements ua ON a.id = ua.achievement_id 
                     WHERE ua.user_id = ? 
                     ORDER BY ua.earned_at DESC`,
                    [req.user.id],
                    (achievementErr, achievements) => {
                        if (achievementErr) {
                            return res.status(500).json({ error: 'Failed to fetch achievements' });
                        }

                        // Get user progress towards unearned achievements
                        db.all(
                            `SELECT 
                                a.*,
                                (
                                    CASE 
                                        WHEN a.achievement_type = 'upload_count' THEN (
                                            SELECT COUNT(*) FROM evidence WHERE uploaded_by = ?
                                        )
                                        WHEN a.achievement_type = 'total_size' THEN (
                                            SELECT COALESCE(SUM(file_size), 0) FROM evidence WHERE uploaded_by = ?
                                        )
                                        WHEN a.achievement_type = 'large_file' THEN (
                                            SELECT MAX(COALESCE(file_size, 0)) FROM evidence WHERE uploaded_by = ?
                                        )
                                        WHEN a.achievement_type = 'first_upload' THEN (
                                            SELECT COUNT(*) FROM evidence WHERE uploaded_by = ?
                                        )
                                        ELSE 0
                                    END
                                ) as current_progress
                             FROM achievements a 
                             WHERE a.id NOT IN (
                                 SELECT achievement_id FROM user_achievements WHERE user_id = ?
                             )`,
                            [req.user.id, req.user.id, req.user.id, req.user.id, req.user.id],
                            (progressErr, progressData) => {
                                if (progressErr) {
                                    return res.status(500).json({ error: 'Failed to fetch achievement progress' });
                                }

                                // Get recent XP transactions
                                db.all(
                                    "SELECT * FROM xp_transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 10",
                                    [req.user.id],
                                    (transactionErr, transactions) => {
                                        if (transactionErr) {
                                            return res.status(500).json({ error: 'Failed to fetch XP transactions' });
                                        }

                                        res.json({
                                            xp: xpData || { total_xp: 0, level: 1 },
                                            achievements: achievements || [],
                                            achievementProgress: progressData || [],
                                            recentTransactions: transactions || []
                                        });
                                    }
                                );
                            }
                        );
                    }
                );
            }
        );
    });
});

// Get leaderboard
app.get('/leaderboard', authenticateToken, (req, res) => {
    const limit = parseInt(req.query.limit) || 10;
    const offset = parseInt(req.query.offset) || 0;

    db.all(
        `SELECT 
            u.id, u.name, u.surname, u.email, u.role,
            COALESCE(ux.total_xp, 0) as total_xp, 
            COALESCE(ux.level, 1) as level,
            COUNT(ua.id) as achievement_count,
            COUNT(e.id) as evidence_count,
            COALESCE(SUM(e.file_size), 0) as total_upload_size
        FROM users u
        LEFT JOIN user_xp ux ON u.id = ux.user_id
        LEFT JOIN user_achievements ua ON u.id = ua.user_id
        LEFT JOIN evidence e ON u.id = e.uploaded_by
        WHERE u.approved = 1
        GROUP BY u.id
        ORDER BY total_xp DESC, achievement_count DESC
        LIMIT ? OFFSET ?`,
        [limit, offset],
        (err, leaderboard) => {
            if (err) {
                console.error('Leaderboard error:', err);
                return res.status(500).json({ error: 'Failed to fetch leaderboard' });
            }

            // Get user's current rank
            db.get(
                `SELECT COUNT(*) + 1 as user_rank 
                 FROM (
                     SELECT u.id, COALESCE(ux.total_xp, 0) as total_xp 
                     FROM users u 
                     LEFT JOIN user_xp ux ON u.id = ux.user_id 
                     WHERE u.approved = 1
                 ) ranked 
                 WHERE total_xp > COALESCE((SELECT total_xp FROM user_xp WHERE user_id = ?), 0)`,
                [req.user.id],
                (rankErr, rankResult) => {
                    if (rankErr) {
                        return res.status(500).json({ error: 'Failed to calculate user rank' });
                    }

                    res.json({
                        leaderboard: leaderboard || [],
                        userRank: rankResult?.user_rank || 1,
                        total: leaderboard?.length || 0
                    });
                }
            );
        }
    );
});

// Get all achievements
app.get('/achievements', authenticateToken, (req, res) => {
    db.all(
        "SELECT * FROM achievements ORDER BY xp_reward ASC",
        [],
        (err, achievements) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to fetch achievements' });
            }
            res.json(achievements || []);
        }
    );
});

// Get user's recent XP transactions
app.get('/xp-transactions', authenticateToken, (req, res) => {
    const limit = parseInt(req.query.limit) || 20;
    
    db.all(
        `SELECT xt.*, a.name as achievement_name, e.original_filename
         FROM xp_transactions xt
         LEFT JOIN achievements a ON xt.achievement_id = a.id
         LEFT JOIN evidence e ON xt.evidence_id = e.id
         WHERE xt.user_id = ?
         ORDER BY xt.created_at DESC
         LIMIT ?`,
        [req.user.id, limit],
        (err, transactions) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to fetch XP transactions' });
            }
            res.json(transactions || []);
        }
    );
});

// Analytics endpoint
app.get('/analytics', authenticateToken, authorizeRoles(['Admin', 'Manager']), (req, res) => {
    db.all(
        `SELECT 
    al.*,
    u.name,
    u.surname,
    u.email,
    u.role
    FROM access_logs al
    LEFT JOIN users u ON al.user_id = u.id
    ORDER BY al.timestamp DESC
    LIMIT 1000`,
        [],
        (err, logs) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to fetch analytics data' });
            }

            // Simple anomaly detection algorithm
            const anomalies = detectAnomalies(logs);

            logAccess(req.user.id, '/analytics', 'GET', req.ip, req.get('User-Agent'), true);

            res.json({
                logs: logs,
                anomalies: anomalies,
                statistics: generateStatistics(logs)
            });
        }
    );
});

// Simple rule-based anomaly detection
function detectAnomalies(logs) {
    const anomalies = [];
    const userActivity = {};
    const ipActivity = {};

    logs.forEach(log => {
        // Track failed login attempts
        if (log.endpoint === '/login' && !log.success) {
            const key = `${log.ip_address}_${log.user_id || 'unknown'}`;
            if (!userActivity[key]) {
                userActivity[key] = { failures: 0, timestamps: [] };
            }
            userActivity[key].failures++;
            userActivity[key].timestamps.push(new Date(log.timestamp));
        }

        // Track IP activity
        if (!ipActivity[log.ip_address]) {
            ipActivity[log.ip_address] = 0;
        }
        ipActivity[log.ip_address]++;
    });

    // Detect brute force attempts (>5 failed logins in 15 minutes)
    Object.keys(userActivity).forEach(key => {
        const activity = userActivity[key];
        if (activity.failures >= 5) {
            const timeSpan = Math.max(...activity.timestamps) - Math.min(...activity.timestamps);
            if (timeSpan <= 15 * 60 * 1000) { // 15 minutes in milliseconds
                anomalies.push({
                    type: 'Brute Force Attack',
                    severity: 'High',
                    description: `${activity.failures} failed login attempts from ${key.split('_')[0]} in 15 minutes`,
                    timestamp: Math.max(...activity.timestamps)
                });
            }
        }
    });

    return anomalies;
}

// Generate statistics
function generateStatistics(logs) {
    const stats = {
        totalRequests: logs.length,
        successfulRequests: logs.filter(log => log.success).length,
        failedRequests: logs.filter(log => !log.success).length,
        uniqueUsers: new Set(logs.map(log => log.user_id).filter(id => id)).size,
        uniqueIPs: new Set(logs.map(log => log.ip_address)).size,
        endpointStats: {},
        hourlyActivity: {}
    };

    return stats;
}

// Start server
app.listen(PORT, () => {
    console.log(`🚀 ForensicLink Server running on port ${PORT}`);
    console.log(`📧 Admin login: admin@forensiclink.com`);
    console.log(`🔑 Admin password: forensiclink2024`);
});