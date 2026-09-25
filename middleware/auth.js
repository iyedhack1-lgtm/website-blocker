module.exports = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  const validApiKey = process.env.API_KEY || 'default-secret-key';

  if (!apiKey || apiKey !== validApiKey) {
    return res.status(401).json({ error: 'غير مصرح: API Key غير صحيح أو مفقود' });
  }
  next();
};

