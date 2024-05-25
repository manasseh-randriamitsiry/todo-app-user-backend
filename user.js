const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());

const PORT = process.env.PORT || 3002;
const SECRET_KEY = 'a736926ef15f1d1cb88c8f61b697549a2fc180c7e95b564192652bf885874a64'; // Ensure this is a strong secret key

app.use(bodyParser.json());

const userConnection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '123456789',
    database: 'user_db'
});

userConnection.connect(err => {
    if (err) {
        console.error('Error connecting to user database:', err);
        return;
    }
    console.log('Connected to user database');
});

// Signup
app.post('/signup', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    userConnection.query(
        'SELECT * FROM users WHERE username = ?',
        [username],
        (err, results) => {
            if (err) {
                console.error('Error checking existing user:', err);
                return res.status(500).json({ error: 'Database error' });
            }

            if (results.length > 0) {
                return res.status(400).json({ error: 'Username already exists' });
            }

            bcrypt.hash(password, 10, (err, hash) => {
                if (err) {
                    console.error('Error hashing password:', err);
                    return res.status(500).json({ error: 'Error hashing password' });
                }

                userConnection.query(
                    'INSERT INTO users (username, password) VALUES (?, ?)',
                    [username, hash],
                    (err, results) => {
                        if (err) {
                            console.error('Error inserting user into database:', err);
                            return res.status(500).json({ error: 'Error inserting user into database' });
                        }
                        // Generate JWT token
                        const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
                        res.status(201).json({ message: 'User created successfully', token });
                    }
                );
            });
        }
    );
});

// Login
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    userConnection.query(
        'SELECT * FROM users WHERE username = ?',
        [username],
        (err, results) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            if (results.length === 0) {
                return res.status(401).json({ error: 'Invalid username or password' });
            }

            const user = results[0];

            bcrypt.compare(password, user.password, (err, result) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                if (!result) {
                    return res.status(401).json({ error: 'Invalid username or password' });
                }

                const token = jwt.sign(
                    { username: user.username, userId: user.id },
                    SECRET_KEY,
                    { expiresIn: '1h' }
                );

                res.status(200).json({ token });
            });
        }
    );
});

// Maintain a list of revoked tokens
const revokedTokens = [];

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization;

    if (!token) {
        return res.status(403).json({ error: 'Token is required' });
    }

    // Check if token is revoked
    if (revokedTokens.includes(token)) {
        return res.status(401).json({ error: 'Token has been revoked' });
    }

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        req.user = decoded;
        next();
    });
};

// Logout route
app.post('/logout', (req, res) => {
    const token = req.headers.authorization;

    if (!token) {
        return res.status(400).json({ error: 'Token is required' });
    }

    // Add token to revoked tokens list
    revokedTokens.push(token);

    return res.status(200).json({ message: 'Logged out successfully' });
});

// Protected route example
app.get('/protected', verifyToken, (req, res) => {
    res.json({ message: 'This is a protected route' });
});

app.listen(PORT, 'www.todo.com', () => {
  console.log(`Server is running on http://www.todo.com:${PORT}`);
});
