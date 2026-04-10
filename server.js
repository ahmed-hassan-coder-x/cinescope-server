const express = require('express');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const SECRET = 'cinescope_secret_2025';

function md5(str) {
    return crypto.createHash('md5').update(str).digest('hex');
}

function isExpired(dateStr) {
    if (!dateStr || dateStr === 'NEVER') return false;
    return new Date(dateStr) < new Date();
}

app.post('/auth/login', (req, res) => {
    const { username, password, device_id } = req.body;

    if (!username || !password || !device_id) {
        return res.json({ status: 'error', code: 'MISSING_FIELDS' });
    }

    let data;
    try {
        data = JSON.parse(fs.readFileSync('./accounts.json', 'utf8'));
    } catch (e) {
        return res.json({ status: 'error', code: 'SERVER_ERROR' });
    }

    const acc = data.accounts.find(a =>
        a.username.toLowerCase() === username.trim().toLowerCase()
    );

    if (!acc) return res.json({ status: 'error', code: 'WRONG_CREDS' });

    const pwMd5 = md5(password.trim());
    const pwOk = acc.password === password.trim() || acc.password === pwMd5;
    if (!pwOk) return res.json({ status: 'error', code: 'WRONG_CREDS' });

    if (!acc.active) return res.json({ status: 'error', code: 'INACTIVE' });

    if (acc.device_id !== '*' && acc.device_id !== device_id) {
        return res.json({ status: 'error', code: 'DEVICE_BIND' });
    }

    if (isExpired(acc.expires)) {
        return res.json({ status: 'error', code: 'EXPIRED' });
    }

    const token = md5(username.toLowerCase() + device_id + SECRET);

    return res.json({
        status: 'ok',
        token: token,
        plan: acc.plan,
        expires: acc.expires
    });
});

app.post('/auth/verify', (req, res) => {
    const { username, token, device_id } = req.body;

    if (!username || !token || !device_id) {
        return res.json({ status: 'error', code: 'MISSING_FIELDS' });
    }

    const expected = md5(username.toLowerCase() + device_id + SECRET);
    if (token !== expected) {
        return res.json({ status: 'error', code: 'TAMPER' });
    }

    let data;
    try {
        data = JSON.parse(fs.readFileSync('./accounts.json', 'utf8'));
    } catch (e) {
        return res.json({ status: 'error', code: 'SERVER_ERROR' });
    }

    const acc = data.accounts.find(a =>
        a.username.toLowerCase() === username.trim().toLowerCase()
    );

    if (!acc) return res.json({ status: 'error', code: 'WRONG_CREDS' });
    if (!acc.active) return res.json({ status: 'error', code: 'INACTIVE' });
    if (isExpired(acc.expires)) return res.json({ status: 'error', code: 'EXPIRED' });

    return res.json({
        status: 'ok',
        plan: acc.plan,
        expires: acc.expires
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server running on port ' + PORT));
