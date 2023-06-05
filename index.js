const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const app = express();

app.use(express.json());

// Secret key for JWT
const secretKey = process.env.SECRET_KEY;

// Register route
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if the user already exists
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create the user in the database
    const newUser = await prisma.user.create({
      data: {
        email,
        password: hashedPassword
      }
    });

    // Generate a JWT token
    const token = jwt.sign({ userId: newUser.id }, secretKey, { expiresIn: '1h' });

    // Send the token as a response
    res.json({ newUser, token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find the user in the database
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Compare the provided password with the stored hash
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    // Generate a JWT token
    const token = jwt.sign({ userId: user.id }, secretKey, { expiresIn: '1h' });

    // Send the token as a response
    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected route
app.get('/protected', (req, res) => {
  const token = req.headers.authorization;

  // Verify the token
  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Get the user ID from the decoded token
    const userId = decoded.userId;

    // Fetch user details from the database using the user ID
    prisma.user
      .findUnique({ where: { id: userId } })
      .then(user => {
        if (!user) {
          return res.status(404).json({ error: 'User not found' });
        }

        // Send protected data as a response
        res.json({ message: 'Protected data', user });
      })
      .catch(error => {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
      });
  });
});

// Start the server
app.listen(8080, () => {
  console.log('Server is running on http://localhost:8080');
});
