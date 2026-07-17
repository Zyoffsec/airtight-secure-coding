'use strict';

// Простая валидация без внешних зависимостей.

const USERNAME_RE = /^[a-zA-Z0-9_]{3,30}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateRegistration({ username, email, password, confirm }) {
  const errors = [];

  if (!username || !USERNAME_RE.test(username)) {
    errors.push('Имя пользователя: 3–30 символов, только буквы, цифры и «_».');
  }
  if (!email || !EMAIL_RE.test(email) || email.length > 254) {
    errors.push('Укажите корректный email.');
  }
  if (!password || password.length < 8) {
    errors.push('Пароль должен быть не короче 8 символов.');
  }
  if (password !== confirm) {
    errors.push('Пароли не совпадают.');
  }

  return errors;
}

module.exports = { validateRegistration, USERNAME_RE, EMAIL_RE };
