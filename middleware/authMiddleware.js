const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

module.exports.protect = async (req, res, next) => {
  console.log('protect middleware çalıştı, Authorization:', req.headers.authorization);
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer ')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }
  if (!token) {
    console.log('Token yok!');
    return res.status(401).json({ message: 'Yetkisiz: Token yok' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET); // JWT_SECRET'ı .env dosyasından al
    let User;
    if (mongoose.models['User']) {
      User = mongoose.model('User');
    } else {
      User = mongoose.model('User', new mongoose.Schema({}, { strict: false }), 'users');
    }
    const user = await User.findById(decoded.id);
    if (!user) {
      console.log('Kullanıcı bulunamadı!');
      return res.status(401).json({ message: 'Kullanıcı bulunamadı' });
    }
    req.user = user;
    console.log('Kullanıcı bulundu:', user.username, 'Rol:', user.role);
    next();
  } catch (err) {
    console.log('Token geçersiz!');
    return res.status(401).json({ message: 'Yetkisiz: Token geçersiz' });
  }
}; 