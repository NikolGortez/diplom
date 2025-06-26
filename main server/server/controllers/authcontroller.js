const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { findUserByUsername, createUser } = require('../models/userModel');

const JWT_SECRET = 'my_very_secret_key';

exports.register = async (req, res) => {
    const { username, display_name, email, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username и password обязательны!' });
    }
    try {
        const existing = await findUserByUsername(username);
        if (existing) return res.status(409).json({ error: 'Пользователь уже существует' });

        const hash = await bcrypt.hash(password, 10);
        const newUser = await createUser({ username, display_name, email, password_hash: hash });
        res.status(201).json(newUser);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

exports.login = async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await findUserByUsername(username);
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ error: 'Неверные данные' });
        }

        const token = jwt.sign({ user_id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { id: user.id, username: user.username, display_name: user.display_name } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};
