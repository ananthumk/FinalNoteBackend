const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const jwt_secret_key = 'secret_key';

app.use(cors());
app.use(express.json());

const dbPath = path.join(__dirname, 'notes.db');
let db;

// Authentication Middleware
const authenticateToken = (request, response, next) => {
    const authHeader = request.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return response.status(401).json('Authentication required');
    }

    jwt.verify(token, jwt_secret_key, (err, user) => {
        if (err) {
            return response.status(403).json('Invalid Token');
        }
        request.user = user;
        next();
    });
};

// Initialize Database and Server
const initializeDbAndServer = async () => {
    db = await open({
        filename: dbPath,
        driver: sqlite3.Database,
    });
    app.listen(3000, () => {
        console.log(`Server Running at http://localhost:3000/`);
    });
};

initializeDbAndServer();

// User Routes
app.post('/signup', async (request, response) => {
    const { name, email, password } = request.body;
    const existingUser = await db.get(`SELECT * FROM user WHERE email = ?`, [email]);
    
    if (existingUser) {
        return response.status(400).json('Email already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.run(`INSERT INTO user(name, email, password) VALUES(?, ?, ?)`, 
        [name, email, hashedPassword]);
    
    response.status(201).json('User created successfully');
});

app.post('/login', async (request, response) => {
    const { email, password } = request.body;
    const userDetails = await db.get(`SELECT * FROM user WHERE email = ?`, [email]);
    
    if (!userDetails) {
        return response.status(400).json('Invalid email');
    }

    const validPassword = await bcrypt.compare(password, userDetails.password);
    if (!validPassword) {
        return response.status(400).json('Invalid password');
    }

    const token = jwt.sign({ userId: userDetails.id }, jwt_secret_key, { expiresIn: '30d' });
    response.json({ token });
});

// Notes Routes
app.get('/notes', authenticateToken, async (request, response) => {
    const { userId } = request.user;
    const notes = await db.all(`SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC`, [userId]);
    response.json(notes);
});

app.get('/notes/:id', authenticateToken, async (request, response) => {
    const { id } = request.params;
    const { userId } = request.user;
    
    const note = await db.get(`SELECT * FROM notes WHERE id = ? AND user_id = ?`, [id, userId]);
    
    if (!note) {
        return response.status(404).json('Note not found');
    }
    response.json(note);
});

app.post('/notes', authenticateToken, async (request, response) => {
    const { title, content, category } = request.body;
    const { userId } = request.user;

    await db.run(`INSERT INTO notes(title, content, category, user_id) VALUES(?, ?, ?, ?)`, 
        [title, content, category, userId]);
    
    response.status(201).json('Note created successfully');
});

app.put('/notes/:id', authenticateToken, async (request, response) => {
    const { title, content, category } = request.body;
    const { id } = request.params;
    const { userId } = request.user;

    await db.run(`UPDATE notes SET title = ?, content = ?, category = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE id = ? AND user_id = ?`, [title, content, category, id, userId]);
    
    response.json('Note updated successfully');
});

app.delete('/notes/:id', authenticateToken, async (request, response) => {
    const { id } = request.params;
    const { userId } = request.user;

    await db.run(`DELETE FROM notes WHERE id = ? AND user_id = ?`, [id, userId]);
    response.json('Note deleted successfully');
});

module.exports = app;