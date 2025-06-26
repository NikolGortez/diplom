// server/index.js
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '.env') });

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { Client } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// === 1. Настройка middleware ===
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:3002'],
  credentials: true,
}));
app.use(helmet());
app.use(express.json());
app.use(cookieParser());

// === 2. Подключение к базе и секрет ===
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET не установлен в .env');
  process.exit(1);
}

const db = new Client({ connectionString: process.env.DATABASE_URL });
db.connect()
  .then(() => console.log('✅ Connected to Postgres'))
  .catch(err => {
    console.error('❌ Ошибка подключения к Postgres:', err);
    process.exit(1);
  });

// === 3. Helper для аутентификации по JWT ===
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const tokenFromHeader = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : null;
  const token = tokenFromHeader || req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Token missing' });

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ error: 'Token invalid or expired' });
    req.user = payload;
    next();
  });
}

// === 4. Регистрация пользователя ===
app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Требуется: email, password' });
  }
  try {
    const exists = await db.query('SELECT 1 FROM users WHERE email=$1', [email]);
    if (exists.rows.length) {
      return res.status(409).json({ error: 'Пользователь уже существует' });
    }
    const hash = await bcrypt.hash(password, 10);
    const username = email;
    const display_name = email.split('@')[0];
    const { rows } = await db.query(
      `INSERT INTO users(username, display_name, email, password_hash)
       VALUES($1,$2,$3,$4)
       RETURNING id, username, display_name, email, created_at`,
      [username, display_name, email, hash]
    );
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error('Registration error:', e);
    res.status(500).json({ error: 'Ошибка сервера при регистрации' });
  }
});

// === 5. Логин пользователя ===
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Требуется: email, password' });
  }
  try {
    const { rows } = await db.query('SELECT * FROM users WHERE email=$1', [email]);
    const user = rows[0];
    if (!user) {
      return res.status(401).json({ error: 'Неверные учётные данные' });
    }
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Неверные учётные данные' });
    }
    const token = jwt.sign(
      { user_id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '8h' }
    );
    // Ставим HttpOnly-куку
    res.cookie('token', token, {
      httpOnly: true,
      sameSite: 'strict',
      secure: false,      // true если HTTPS
      path: '/',
      maxAge: 8 * 3600 * 1000
    });
    // Отдаем только данные юзера
    res.json({
      user: {
        id: user.id,
        email: user.email,
        display_name: user.display_name
      }
    });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Ошибка сервера при входе' });
  }
});

// === 6. Logout ===
app.post('/auth/logout', (req, res) => {
  res.clearCookie('token', { path: '/' });
  res.json({ ok: true });
});

// === 7. Проверка текущей сессии ===
app.get('/auth/me', authenticateToken, async (req, res) => {
  try {
    const { user_id } = req.user;
    const { rows } = await db.query(
      'SELECT id, username, display_name, email FROM users WHERE id=$1',
      [user_id]
    );
    if (!rows[0]) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(rows[0]);
  } catch (e) {
    console.error('Auth me error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// === 8. Эндпоинт статистики ===
app.get('/admin/stats', authenticateToken, async (req, res) => {
  try {
    const usersCount = (await db.query('SELECT COUNT(*) FROM users')).rows[0].count;
    const notesCount = (await db.query('SELECT COUNT(*) FROM notes')).rows[0].count;
    res.json({ usersCount, notesCount, uptime: process.uptime() });
  } catch (e) {
    console.error('Stats error:', e);
    res.status(500).json({ error: 'Ошибка получения статистики' });
  }
});

// === 9. Раздача фронтенда (prod) ===
app.use(express.static(path.join(__dirname, '../frontend/build')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/build/index.html'));
});

// === 10. Запуск сервера ===
const PORT = parseInt(process.env.PORT, 10) || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server listening on http://localhost:${PORT}`);
});
