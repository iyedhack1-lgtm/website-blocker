require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const db = require('./database');
const authenticateApiKey = require('./middleware/auth');
const apiLimiter = require('./middleware/rateLimiter');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// تطبيق Rate Limiting على المسارات
app.use('/api/', apiLimiter);

// دالة تنظيف وتنسيق اسم الدومين
function sanitizeDomain(domain) {
  if (!domain) return '';
  return domain.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].trim();
}

// 1. إضافة دومين إلى القائمة
app.post('/api/blocklist', authenticateApiKey, (req, res) => {
  const domain = sanitizeDomain(req.body.domain);
  if (!domain) return res.status(400).json({ error: 'اسم الدومين مطلوب' });

  db.run('INSERT INTO blocked_domains (domain) VALUES (?)', [domain], function (err) {
    if (err) {
      if (err.message.includes('UNIQUE constraint failed')) {
        return res.status(409).json({ error: 'الدومين موجود بالفعل في القائمة' });
      }
      return res.status(500).json({ error: err.message });
    }
    res.status(201).json({ message: 'تمت إضافة الدومين بنجاح', id: this.lastID, domain });
  });
});

// 2. إزالة دومين من القائمة
app.delete('/api/blocklist', authenticateApiKey, (req, res) => {
  const domain = sanitizeDomain(req.body.domain);
  if (!domain) return res.status(400).json({ error: 'اسم الدومين مطلوب' });

  db.run('DELETE FROM blocked_domains WHERE domain = ?', [domain], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'الدومين غير موجود' });
    res.json({ message: 'تمت إزالة الدومين بنجاح' });
  });
});

// 3. عرض جميع المواقع المحظورة
app.get('/api/blocklist', authenticateApiKey, (req, res) => {
  db.all('SELECT * FROM blocked_domains ORDER BY created_at DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ count: rows.length, blocked_domains: rows });
  });
});

// 4. التحقق هل الدومين محظور (يدعم النطاقات الفرعية)
app.get('/api/check', (req, res) => {
  const host = sanitizeDomain(req.query.domain);
  if (!host) return res.status(400).json({ error: 'معلمة domain مطلوبة' });

  db.all('SELECT domain FROM blocked_domains', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });

    const blockedList = rows.map(r => r.domain);
    const isBlocked = blockedList.some(blockedDomain => {
      return host === blockedDomain || host.endsWith('.' + blockedDomain);
    });

    res.json({ domain: host, isBlocked });
  });
});

// Middleware للتوجيه تلقائيًا في مواقعك الخاصة عند الحظر
app.use((req, res, next) => {
  const host = sanitizeDomain(req.headers.host);
  
  db.all('SELECT domain FROM blocked_domains', [], (err, rows) => {
    if (err) return next();

    const blockedList = rows.map(r => r.domain);
    const isBlocked = blockedList.some(blockedDomain => {
      return host === blockedDomain || host.endsWith('.' + blockedDomain);
    });

    if (isBlocked && req.path !== '/blocked') {
      return res.redirect('/blocked');
    }
    next();
  });
});

// صفحة توجيه الحظر
app.get('/blocked', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'blocked.html'));
});

// تشغيل السيرفر
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
