'use strict';

const express = require('express');
const User = require('../models/user');
const { validateRegistration } = require('../lib/validate');
const { requireGuest } = require('../middleware/auth');

const router = express.Router();

// --- Регистрация ---

router.get('/register', requireGuest, (req, res) => {
  res.render('register', { title: 'Регистрация', form: {} });
});

router.post('/register', requireGuest, async (req, res, next) => {
  try {
    const username = String(req.body.username || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const { password, confirm } = req.body;

    const errors = validateRegistration({ username, email, password, confirm });

    // Проверяем занятость логина/почты до вставки, чтобы дать понятную ошибку.
    if (!errors.length) {
      if (User.getByUsername(username)) errors.push('Это имя пользователя уже занято.');
      if (User.getByEmail(email)) errors.push('Этот email уже зарегистрирован.');
    }

    if (errors.length) {
      errors.forEach((e) => req.flash('error', e));
      return res.status(400).render('register', {
        title: 'Регистрация',
        form: { username, email },
      });
    }

    const user = await User.createUser({ username, email, password });

    // Сразу логиним нового пользователя, обновив сессию против фиксации.
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = user.id;
      req.flash('success', `Добро пожаловать, ${user.username}!`);
      res.redirect('/profile');
    });
  } catch (err) {
    // На случай гонки: UNIQUE-ограничение в БД.
    if (err && err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      req.flash('error', 'Имя пользователя или email уже заняты.');
      return res.status(400).render('register', { title: 'Регистрация', form: {} });
    }
    next(err);
  }
});

// --- Вход ---

router.get('/login', requireGuest, (req, res) => {
  res.render('login', { title: 'Вход', form: {} });
});

router.post('/login', requireGuest, async (req, res, next) => {
  try {
    const identifier = String(req.body.identifier || '').trim();
    const { password } = req.body;

    // Логин по имени пользователя или по email.
    const user = identifier.includes('@')
      ? User.getByEmail(identifier.toLowerCase())
      : User.getByUsername(identifier);

    // Одинаковое сообщение об ошибке, чтобы не раскрывать существование аккаунта.
    const ok = user && (await User.verifyPassword(user, password || ''));
    if (!ok) {
      req.flash('error', 'Неверный логин или пароль.');
      return res.status(401).render('login', { title: 'Вход', form: { identifier } });
    }

    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = user.id;
      req.flash('success', `С возвращением, ${user.username}!`);
      res.redirect('/profile');
    });
  } catch (err) {
    next(err);
  }
});

// --- Выход ---

router.post('/logout', (req, res, next) => {
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie('sid');
    res.redirect('/login');
  });
});

module.exports = router;
