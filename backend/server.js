const express = require('express');
const bcrypt = require('bcryptjs');
const cors = require('cors'); // Import the cors middleware
const app = express();

// Load environment variables from .env file
require('dotenv').config();

// Use environment variable for port, default to 3000 if not set
const port = process.env.PORT || 3000;

// Middleware to parse JSON request bodies
app.use(express.json());

// Enable CORS (Allow requests from your Netlify frontend domain)
const allowedOrigins = [process.env.NETLIFY_DOMAIN]; // Replace with your Netlify URL
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);

    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  }
}));

// In-memory "database" for demonstration purposes
const users = [];

// Helper function to find a user by username
const findUser = (username) => {
  return users.find(user => user.username === username);
};

// Signup Route
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  if (findUser(username)) {
    return res.status(409).json({ message: 'Username already exists' });
  }

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10); // 10 is the salt rounds

    // Create a new user object
    const newUser = {
      username: username,
      password: hashedPassword,
    };

    // Store the user in the "database"
    users.push(newUser);

    console.log('User registered:', newUser.username);
    res.status(201).json({ message: 'User registered successfully' });

  } catch (error) {
    console.error('Error during signup:', error);
    res.status(500).json({ message: 'Signup failed' });
  }
});


// Login Route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  const user = findUser(username);

  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  try {
    // Compare the provided password with the stored hashed password
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
      res.status(200).json({ message: 'Login successful' });
    } else {
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ message: 'Login failed' });
  }
});


// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});