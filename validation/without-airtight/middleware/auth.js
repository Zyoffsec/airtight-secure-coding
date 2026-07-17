'use strict';

const User = require('../models/user');

// Подгружает текущего пользователя из сессии в req.user и res.locals.currentUser,
// чтобы шаблоны и роуты всегда знали, кто залогинен.
function loadUser(req, res, next) {
  res.locals.currentUser = null;
  req.user = null;

  if (req.session && req.session.userId) {
    const user = User.getById(req.session.userId);
    if (user) {
      req.user = user;
      res.locals.currentUser = { id: user.id, username: user.username, email: user.email };
    } else {
      // Пользователь удалён — чистим протухшую сессию.
      req.session.userId = null;
    }
  }
  next();
}

// Пускает дальше только залогиненных.
function requireAuth(req, res, next) {
  if (req.user) return next();
  req.flash('error', 'Сначала войдите в аккаунт.');
  return res.redirect('/login');
}

// Пускает дальше только гостей (для страниц логина/регистрации).
function requireGuest(req, res, next) {
  if (!req.user) return next();
  return res.redirect('/profile');
}

module.exports = { loadUser, requireAuth, requireGuest };
