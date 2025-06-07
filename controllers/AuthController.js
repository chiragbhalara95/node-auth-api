const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const users = require('../users');

exports.signup = async (req, res) => {
  const { email, password } = req.body;

  if (users.find(user => user.email === email)) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ email, password: hashedPassword });

  res.status(201).json({ message: 'Signup successful' });
};

exports.login = async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(user => user.email === email);
  if (!user) return res.status(400).json({ message: 'User not found' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ message: 'Invalid credentials' });

  const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

  res.json({ message: 'Login successful', token });
};

exports.logout = (req, res) => {
  res.json({ message: 'Logged out (discard token on client)' });
};
