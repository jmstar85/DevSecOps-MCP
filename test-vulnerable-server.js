#!/usr/bin/env node

// Vulnerable Web Server for DAST Testing
const express = require('express');
// const mysql = require('mysql2'); // Comment out for testing
const app = express();
const port = 3001;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Hardcoded credentials (for testing only)
const DB_PASSWORD = "admin123!@#";
const API_KEY = "sk-1234567890abcdef1234567890abcdef";

console.log('🚨 WARNING: This is a VULNERABLE test server for DAST testing!');
console.log('🚨 DO NOT use in production!');

// Basic routes
app.get('/', (req, res) => {
    res.send(`
        <h1>Vulnerable Test Application</h1>
        <p>This server contains intentional vulnerabilities for DAST testing</p>
        <h2>Test Endpoints:</h2>
        <ul>
            <li><a href="/search?q=test">Search (XSS)</a></li>
            <li><a href="/user/1">User Profile (SQL Injection)</a></li>
            <li><a href="/file/../../etc/passwd">File Access (Path Traversal)</a></li>
            <li><a href="/redirect?url=http://evil.com">Redirect (Open Redirect)</a></li>
            <li><a href="/debug">Debug Info (Information Disclosure)</a></li>
        </ul>
        <h2>POST Endpoints:</h2>
        <form action="/login" method="post">
            <input name="username" placeholder="Username" required>
            <input name="password" type="password" placeholder="Password" required>
            <button type="submit">Login (LDAP Injection)</button>
        </form>
        <br>
        <form action="/backup" method="post">
            <input name="filename" placeholder="Filename" required>
            <button type="submit">Backup (Command Injection)</button>
        </form>
    `);
});

// XSS vulnerability
app.get('/search', (req, res) => {
    const searchTerm = req.query.q;
    // VULNERABLE: Unescaped user input in HTML response
    res.send(`<h1>Search Results for: ${searchTerm}</h1>`);
});

// SQL Injection vulnerability
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    // VULNERABLE: Direct string concatenation in SQL query
    const query = `SELECT * FROM users WHERE id = '${userId}'`;
    res.json({
        query: query,
        message: `Would execute: ${query}`,
        vulnerability: "SQL Injection possible"
    });
});

// Path Traversal vulnerability
app.get('/file/:filename', (req, res) => {
    const filename = req.params.filename;
    // VULNERABLE: No path validation
    const filePath = `/uploads/${filename}`;
    res.json({
        file: filePath,
        message: `Would read file: ${filePath}`,
        vulnerability: "Path Traversal possible"
    });
});

// Open Redirect vulnerability
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    // VULNERABLE: Unvalidated redirect
    if (url) {
        res.redirect(url);
    } else {
        res.send('Missing url parameter');
    }
});

// Information disclosure
app.get('/debug', (req, res) => {
    // VULNERABLE: Exposing sensitive information
    res.json({
        database_password: DB_PASSWORD,
        api_key: API_KEY,
        environment: process.env,
        vulnerability: "Information Disclosure"
    });
});

// LDAP Injection vulnerability
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // VULNERABLE: User input directly in LDAP filter
    const filter = `(&(uid=${username})(password=${password}))`;
    res.json({
        ldap_filter: filter,
        message: "LDAP authentication attempt",
        vulnerability: "LDAP Injection possible"
    });
});

// Command Injection vulnerability
app.post('/backup', (req, res) => {
    const { filename } = req.body;
    // VULNERABLE: User input directly used in shell command
    const command = `tar -czf /backups/${filename}.tar.gz /data/`;
    res.json({
        command: command,
        message: `Would execute: ${command}`,
        vulnerability: "Command Injection possible"
    });
});

// Missing authentication for admin functions
app.delete('/admin/users/:id', (req, res) => {
    // VULNERABLE: No authentication check for sensitive operation
    const userId = req.params.id;
    res.json({
        message: `User ${userId} would be deleted`,
        vulnerability: "Missing Authentication"
    });
});

// CSRF vulnerability
app.post('/transfer', (req, res) => {
    const { amount, to } = req.body;
    // VULNERABLE: No CSRF protection
    res.json({
        message: `Would transfer $${amount} to ${to}`,
        vulnerability: "CSRF possible"
    });
});

// Insecure headers
app.use((req, res, next) => {
    // VULNERABLE: Missing security headers
    // No X-Frame-Options, X-XSS-Protection, etc.
    next();
});

// Error handler that leaks information
app.use((error, req, res, next) => {
    // VULNERABLE: Exposing stack traces
    res.status(500).json({
        error: error.message,
        stack: error.stack,
        vulnerability: "Information Leakage in Errors"
    });
});

app.listen(port, '0.0.0.0', () => {
    console.log(`🚨 Vulnerable test server running at http://localhost:${port}`);
    console.log(`🔍 Ready for DAST testing with OWASP ZAP`);
});

module.exports = app;