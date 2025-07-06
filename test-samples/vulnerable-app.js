// Vulnerable Node.js Application for SAST Testing
// This file contains intentional security vulnerabilities for testing purposes

const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const fs = require('fs');
const app = express();

// Hardcoded secrets (should be detected by SAST)
const API_KEY = "sk-1234567890abcdef1234567890abcdef";
const DB_PASSWORD = "admin123!@#";
const JWT_SECRET = "supersecretkey";

// SQL Injection vulnerability
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    // VULNERABLE: Direct string concatenation in SQL query
    const query = "SELECT * FROM users WHERE id = '" + userId + "'";
    connection.query(query, (error, results) => {
        if (error) throw error;
        res.json(results);
    });
});

// XSS vulnerability
app.get('/search', (req, res) => {
    const searchTerm = req.query.q;
    // VULNERABLE: Unescaped user input in HTML response
    res.send(`<h1>Search Results for: ${searchTerm}</h1>`);
});

// Command Injection vulnerability
app.post('/backup', (req, res) => {
    const filename = req.body.filename;
    // VULNERABLE: User input directly used in shell command
    const command = `tar -czf /backups/${filename}.tar.gz /data/`;
    require('child_process').exec(command, (error, stdout, stderr) => {
        if (error) {
            res.status(500).send('Backup failed');
        } else {
            res.send('Backup completed');
        }
    });
});

// Path Traversal vulnerability
app.get('/file/:filename', (req, res) => {
    const filename = req.params.filename;
    // VULNERABLE: No path validation
    const filePath = `/uploads/${filename}`;
    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.status(404).send('File not found');
        } else {
            res.send(data);
        }
    });
});

// Weak cryptography
function hashPassword(password) {
    // VULNERABLE: Using MD5 for password hashing
    return crypto.createHash('md5').update(password).digest('hex');
}

// Insecure random generation
function generateToken() {
    // VULNERABLE: Using Math.random() for security tokens
    return Math.random().toString(36).substring(2, 15);
}

// LDAP Injection vulnerability
app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    // VULNERABLE: User input directly in LDAP filter
    const filter = `(&(uid=${username})(password=${password}))`;
    // ... LDAP query execution
});

// NoSQL Injection vulnerability
app.post('/profile', (req, res) => {
    const userId = req.body.userId;
    // VULNERABLE: Direct object injection in MongoDB query
    const query = { _id: userId };
    db.collection('profiles').findOne(query, (err, result) => {
        res.json(result);
    });
});

// Information disclosure through error messages
app.get('/admin/:action', (req, res) => {
    try {
        // Some admin functionality
        if (req.params.action === 'debug') {
            throw new Error(`Database connection failed: ${DB_PASSWORD}`);
        }
    } catch (error) {
        // VULNERABLE: Exposing sensitive information in error messages
        res.status(500).send(`Error: ${error.message}`);
    }
});

// Insecure deserialization
app.post('/deserialize', (req, res) => {
    const data = req.body.data;
    // VULNERABLE: Deserializing untrusted data
    const obj = JSON.parse(data);
    eval(obj.code); // Even worse: code execution
    res.send('Data processed');
});

// Missing authentication
app.delete('/admin/users/:id', (req, res) => {
    // VULNERABLE: No authentication check for sensitive operation
    const userId = req.params.id;
    // Delete user logic
    res.send('User deleted');
});

// Weak session management
app.post('/session', (req, res) => {
    // VULNERABLE: Predictable session ID
    const sessionId = Date.now().toString();
    res.cookie('sessionId', sessionId);
    res.send('Session created');
});

// Open redirect vulnerability
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    // VULNERABLE: Unvalidated redirect
    res.redirect(url);
});

// XML External Entity (XXE) vulnerability
const xml2js = require('xml2js');
app.post('/xml', (req, res) => {
    const xmlData = req.body.xml;
    // VULNERABLE: XML parsing without disabling external entities
    xml2js.parseString(xmlData, { trim: true }, (err, result) => {
        res.json(result);
    });
});

// CSRF vulnerability
app.post('/transfer', (req, res) => {
    const amount = req.body.amount;
    const to = req.body.to;
    // VULNERABLE: No CSRF protection
    // Transfer money logic
    res.send('Transfer completed');
});

// Directory listing enabled
app.use('/uploads', express.static('uploads', { dotfiles: 'allow' }));

// Insecure HTTP headers
app.use((req, res, next) => {
    // VULNERABLE: Missing security headers
    next();
});

app.listen(3000, () => {
    console.log('Vulnerable app running on port 3000');
});