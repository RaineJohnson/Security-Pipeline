/**
 * ===========================================================================
 * SAMPLE VULNERABLE APPLICATION — FOR TESTING ONLY
 * ===========================================================================
 * This file contains INTENTIONAL security vulnerabilities to demonstrate
 * what the security pipeline catches. Every issue here is flagged by at
 * least one scanner.
 *
 * DO NOT use any of this code in production.
 * ===========================================================================
 */

const express = require("express");
const crypto = require("crypto");
const mysql = require("mysql");
const { exec } = require("child_process");

const app = express();
app.use(express.json());

// ===========================================================================
// VULN 1: Hardcoded credentials
// CWE-798 | Caught by: Semgrep, Gitleaks
// Fix: Use process.env.DB_PASSWORD
// ===========================================================================
const db_password = "admin123!secure";
const api_key = "AKIAIOSFODNN7EXAMPLE";
const token_secret = "super-secret-jwt-signing-key-12345";

// ===========================================================================
// VULN 2: Hardcoded database connection
// CWE-798 | Caught by: Semgrep, Gitleaks
// Fix: process.env.DATABASE_URL
// ===========================================================================
const connection = mysql.createConnection({
  host: "prod-db.internal",
  user: "root",
  password: "r00tP4ssw0rd!",
  database: "customers",
});

// ===========================================================================
// VULN 3: Weak hash algorithm (MD5)
// CWE-328 | Caught by: Semgrep (weak-hash-algorithm)
// Fix: crypto.createHash('sha256')
// ===========================================================================
function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

// ===========================================================================
// VULN 4: Insecure random for token generation
// CWE-338 | Caught by: Semgrep (insecure-random-for-security)
// Fix: crypto.randomBytes(32).toString('hex')
// ===========================================================================
function generateToken() {
  return Math.random().toString(36).substring(2);
}

// ===========================================================================
// VULN 5: Command injection via user input
// CWE-78 | Caught by: Semgrep
// Fix: Use child_process.execFile with argument array
// ===========================================================================
app.get("/lookup", (req, res) => {
  const domain = req.query.domain;
  exec(`nslookup ${domain}`, (error, stdout) => {
    res.json({ result: stdout });
  });
});

// ===========================================================================
// VULN 6: SQL injection via string concatenation
// CWE-89 | Caught by: Semgrep
// Fix: connection.query("SELECT * FROM users WHERE id = ?", [userId])
// ===========================================================================
app.get("/user/:id", (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.params.id;
  connection.query(query, (err, results) => {
    res.json(results);
  });
});

// ===========================================================================
// VULN 7: XSS via reflected user input
// CWE-79 | Caught by: Semgrep (p/owasp-top-ten)
// Fix: Use a template engine with auto-escaping
// ===========================================================================
app.get("/search", (req, res) => {
  const term = req.query.q;
  res.send(`<h1>Search results for: ${term}</h1>`);
});

// ===========================================================================
// VULN 8: Wildcard CORS
// CWE-942 | Caught by: Semgrep (cors-wildcard)
// Fix: Restrict to specific origins
// ===========================================================================
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

// ===========================================================================
// VULN 9: Sensitive data in error messages
// CWE-209 | Caught by: Semgrep (p/security-audit)
// Fix: Log full errors server-side, return generic message to client
// ===========================================================================
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    query: req.query,
  });
});

app.listen(3000, () => console.log("Server running on port 3000"));
