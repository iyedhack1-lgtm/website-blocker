const rateLimit = require('express-rate-limit');

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: 100, // حد أقصى 100 طلب لكل IP
  message: { error: 'تجاوزت الحد المسموح من الطلبات، يرجى المحاولة لاحقًا.' },
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = apiLimiter;
