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