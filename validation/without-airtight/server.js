'use strict';

require('dotenv').config();

const path = require('path');
const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');

const { loadUser } = require('./middleware/auth');
const authRoutes = require('./routes/auth');
const pageRoutes = require('./routes/pages');

const app = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

// За реверс-прокси (nginx и т.п.) — доверяем первому прокси ради secure-cookie.
if (isProd) app.set('trust proxy', 1);

// Шаблоны EJS.
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Статика (CSS).
app.use('/static', express.static(path.join(__dirname, 'public')));

// Разбор форм.
app.use(express.urlencoded({ extended: false }));

// Сессии в cookie с подписью.
if (!process.env.SESSION_SECRET && isProd) {
  throw new Error('SESSION_SECRET обязателен в production. Задай его в .env');
}
app.use(
  session({
    name: 'sid',
    secret: process.env.SESSION_SECRET || 'dev-insecure-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: isProd,
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 дней
    },
  })
);

app.use(flash());

// Прокидываем flash-сообщения во все шаблоны.
app.use((req, res, next) => {
  res.locals.flash = {
    error: req.flash('error'),
    success: req.flash('success'),
  };
  next();
});

// Текущий пользователь -> req.user / res.locals.currentUser.
app.use(loadUser);

// Роуты.
app.use('/', pageRoutes);
app.use('/', authRoutes);

// 404.
app.use((req, res) => {
  res.status(404).render('error', {
    title: '404',
    status: 404,
    message: 'Страница не найдена.',
  });
});

// Обработчик ошибок.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).render('error', {
    title: 'Ошибка',
    status: 500,
    message: isProd ? 'Что-то пошло не так.' : String(err.stack || err),
  });
});

app.listen(PORT, () => {
  console.log(`Сервер запущен: http://localhost:${PORT}`);
});
