'use strict';

const express = require('express');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// Главная.
router.get('/', (req, res) => {
  res.render('index', { title: 'Главная' });
});

// Профиль — только для залогиненных.
router.get('/profile', requireAuth, (req, res) => {
  res.render('profile', { title: 'Профиль', user: req.user });
});

module.exports = router;
