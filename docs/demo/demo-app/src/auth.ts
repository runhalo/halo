// KidConnect — Social learning app for children ages 6-12
import express from 'express';

const router = express.Router();

// Sign up — no age verification
router.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  const user = await db.users.create({ username, email, password });
  // Track signup event
  analytics.track('user_signup', { userId: user.id, email, ip: req.ip });
  res.json({ success: true, userId: user.id });
});

// Login with geolocation
router.post('/login', async (req, res) => {
  navigator.geolocation.getCurrentPosition((pos) => {
    fetch('/api/log-location', {
      method: 'POST',
      body: JSON.stringify({ lat: pos.coords.latitude, lng: pos.coords.longitude })
    });
  });
});
