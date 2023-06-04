const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const app = express();

app.use(bodyParser.json());

// JWT secret key
const secretKey = process.env.SECRET_KEY;

// Middleware for authenticating JWT token
function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token verification failed' });
    }

    req.user = user;
    next();
  });
}



// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Check if the user exists in the database
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  // Check if the password is correct
  if (password !== user.password) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  // Generate JWT token
  const token = jwt.sign({ email: user.email }, secretKey);

  // Send the token in the response
  res.json({ token });
});

// Register route
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // Check if the user already exists in the database
  const existingUser = await prisma.user.findUnique({ where: { email } });

  if (existingUser) {
    return res.status(400).json({ error: 'User already exists' });
  }

  // Create a new user
  const newUser = await prisma.user.create({
    data: { email, password },
  });

  // Generate JWT token
  const token = jwt.sign({ email: newUser.email }, secretKey);

  // Send the token in the response
  res.json({ token });
});

// Protected route
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'Protected route accessed successfully!' });
});

// Start the server
app.listen(8080, () => {
  console.log('Server is running on http://localhost:8080');
});
