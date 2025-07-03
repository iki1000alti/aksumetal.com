const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();
const Project = require('./models/projectModel');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const { protect } = require('./middleware/authMiddleware');
const User = require('./models/userModel');
const Log = require('./models/logModel');
const Settings = require('./models/siteSettingsModel');
const { body, validationResult } = require('express-validator');
const FileType = require('file-type');

const app = express();
const PORT = process.env.PORT || 5000;

// --- GEREKLİ CONFIGLER ---
const JWT_SECRET = process.env.JWT_SECRET; // Artık .env dosyasından okunuyor

// Middleware
const allowedOrigins = [
  'https://aksumetal.com',
  'http://localhost:5173', // Geliştirme için
];
app.use(cors({
  origin: function(origin, callback) {
    // allow requests with no origin (like mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      return callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(helmet());

// Rate limiting
const isDev = process.env.NODE_ENV !== 'production';
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: isDev ? 10000 : 100,
  message: 'Çok fazla istek gönderildi. Lütfen daha sonra tekrar deneyin.'
});
app.use(limiter);

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'aksumetal_uploads',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
    transformation: [{ width: 1200, height: 800, crop: "limit" }],
  },
});
const fileFilter = async (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
  // Önce MIME type kontrolü
  if (!allowedTypes.includes(file.mimetype)) {
    return cb(new Error('Sadece resim dosyaları yüklenebilir!'), false);
  }
  // Dosya içeriği kontrolü (file-type)
  if (file.buffer) {
    const type = await FileType.fromBuffer(file.buffer);
    if (!type || !allowedTypes.includes(type.mime)) {
      return cb(new Error('Sadece gerçek resim dosyaları yüklenebilir!'), false);
    }
  }
  cb(null, true);
};
const upload = multer({ 
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }
});

// MongoDB bağlantısı
mongoose.connect(
  process.env.MONGODB_URI,
  { useNewUrlParser: true, useUnifiedTopology: true }
)
.then(() => console.log('MongoDB bağlantısı başarılı!'))
.catch((err) => console.error('MongoDB bağlantı hatası:', err));

// Basit bir test endpoint'i
app.get('/', (req, res) => {
  res.send('Backend çalışssıyor!');
});

// Input sanitization fonksiyonu
function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  return input.trim().replace(/[<>]/g, '').substring(0, 1000);
}

// --- PROJE ENDPOINTLERİ ---
app.get('/user/projects', async (req, res) => {
  try {
    const { category } = req.query;
    let filter = {};
    if (category && category !== 'Tümü') {
      filter.category = category;
    }
    const projects = await Project.find(filter).sort({ createdAt: -1 });
    res.json(projects);
  } catch (error) {
    res.status(500).json({ message: 'Projeler getirilirken bir hata oluştu.' });
  }
});
// Tek proje getir
app.get('/user/projects/:id', async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ message: 'Proje bulunamadı' });
    res.json(project);
  } catch (error) {
    res.status(500).json({ message: 'Proje getirilirken bir hata oluştu.' });
  }
});
// Yeni proje ekle (çoklu resim destekli)
app.post(
  '/projects',
  protect,
  upload.array('images', 10),
  [
    body('title').isString().trim().isLength({ min: 3, max: 100 }).withMessage('Başlık 3-100 karakter olmalı.'),
    body('description').isString().trim().isLength({ min: 10, max: 1000 }).withMessage('Açıklama 10-1000 karakter olmalı.'),
    body('category').isString().trim().isLength({ min: 2, max: 50 }).withMessage('Kategori 2-50 karakter olmalı.')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { title, description, category, defaultImage, defaultImageIndex } = req.body;
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ message: 'En az bir resim ekleyin.' });
    }
    try {
      const imageUrls = req.files.map(file => file.path);
      let defaultImg = imageUrls[0];
      if (typeof defaultImageIndex !== 'undefined' && !isNaN(Number(defaultImageIndex)) && imageUrls[Number(defaultImageIndex)]) {
        defaultImg = imageUrls[Number(defaultImageIndex)];
      } else if (defaultImage && imageUrls.includes(defaultImage)) {
        defaultImg = defaultImage;
      }
      const newProject = await Project.create({
        title: sanitizeInput(title),
        description: sanitizeInput(description),
        category: sanitizeInput(category),
        imageUrls,
        defaultImage: defaultImg,
        imageUrl: defaultImg,
        createdBy: req.user.username,
      });
      await Log.create({ user: req.user.username, action: 'create_project', target: newProject._id.toString(), details: `Proje oluşturuldu: ${title}` });
      res.status(201).json(newProject);
    } catch (error) {
      res.status(500).json({ message: 'Proje eklenirken bir hata oluştu.' });
    }
  }
);
// Proje güncelle (çoklu resim destekli)
app.put(
  '/projects/:id',
  protect,
  upload.array('images', 10),
  [
    body('title').optional().isString().trim().isLength({ min: 3, max: 100 }).withMessage('Başlık 3-100 karakter olmalı.'),
    body('description').optional().isString().trim().isLength({ min: 10, max: 1000 }).withMessage('Açıklama 10-1000 karakter olmalı.'),
    body('category').optional().isString().trim().isLength({ min: 2, max: 50 }).withMessage('Kategori 2-50 karakter olmalı.')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    try {
      const { title, description, category, defaultImage } = req.body;
      let existingImages = req.body.existingImages;
      if (existingImages && !Array.isArray(existingImages)) {
        existingImages = [existingImages];
      }
      const project = await Project.findById(req.params.id);
      if (!project) return res.status(404).json({ message: 'Proje bulunamadı' });
      // Silinen eski resimleri Cloudinary'den kaldır
      if (Array.isArray(existingImages)) {
        const toDelete = (project.imageUrls || []).filter(url => !existingImages.includes(url));
        for (const url of toDelete) {
          const publicId = url.split('/').slice(-2).join('/').split('.')[0];
          try { await cloudinary.uploader.destroy(publicId); } catch (e) { /* ignore */ }
        }
      }
      let imageUrls = Array.isArray(existingImages) ? [...existingImages] : (project.imageUrls || []);
      if (req.files && req.files.length > 0) {
        const newImageUrls = req.files.map(file => file.path);
        imageUrls = imageUrls.concat(newImageUrls);
      }
      let defaultImg = defaultImage && imageUrls.includes(defaultImage) ? defaultImage : imageUrls[0];
      const updatedData = {
        title: title ? sanitizeInput(title) : project.title,
        description: description ? sanitizeInput(description) : project.description,
        category: category ? sanitizeInput(category) : project.category,
        imageUrls,
        defaultImage: defaultImg,
        imageUrl: defaultImg,
      };
      const updatedProject = await Project.findByIdAndUpdate(req.params.id, updatedData, { new: true });
      await Log.create({ user: req.user.username, action: 'update_project', target: req.params.id, details: `Proje güncellendi: ${updatedProject.title}` });
      res.json(updatedProject);
    } catch (error) {
      res.status(500).json({ message: 'Proje güncellenirken bir hata oluştu.' });
    }
  }
);
// Proje sil
app.delete('/projects/:id', protect, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ message: 'Proje bulunamadı' });
    await Project.deleteOne({ _id: req.params.id });
    await Log.create({ user: req.user.username, action: 'delete_project', target: req.params.id, details: `Proje silindi: ${project.title}` });
    res.json({ message: 'Proje başarıyla silindi' });
  } catch (error) {
    res.status(500).json({ message: 'Proje silinirken bir sunucu hatası oluştu.' });
  }
});
// Proje beğen (like)
app.post('/user/projects/:id/like', async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ message: 'Proje bulunamadı' });
    project.likes = (project.likes || 0) + 1;
    await project.save();
    res.json({ likes: project.likes });
  } catch (error) {
    res.status(500).json({ message: 'Beğeni artırılırken hata oluştu.' });
  }
});
// Proje beğenisini geri al (unlike)
app.post('/user/projects/:id/unlike', async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ message: 'Proje bulunamadı' });
    project.likes = Math.max((project.likes || 0) - 1, 0);
    await project.save();
    res.json({ likes: project.likes });
  } catch (error) {
    res.status(500).json({ message: 'Beğeni azaltılırken hata oluştu.' });
  }
});
// Tüm projelerin beğenisini sıfırla
app.post('/user/projects/clear-likes', async (req, res) => {
  try {
    await Project.updateMany({}, { $set: { likes: 0 } });
    res.json({ message: 'Tüm projelerin beğenileri sıfırlandı.' });
  } catch (error) {
    res.status(500).json({ message: 'Beğeniler sıfırlanırken hata oluştu.' });
  }
});
// --- LOGIN ENDPOINT ---
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ message: 'Geçersiz kullanıcı adı veya şifre' });
    const isPasswordCorrect = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordCorrect) return res.status(401).json({ message: 'Geçersiz kullanıcı adı veya şifre' });
    user.lastLogin = new Date();
    await user.save();
    await Log.create({ user: user.username, action: 'login', details: 'Giriş yaptı' });
    const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Sunucuda bir hata oluştu' });
  }
});
// --- SETTINGS ENDPOINTLERİ ---
app.get('/user/settings', async (req, res) => {
  try {
    let settings = await Settings.findOne();
    if (!settings) {
      settings = await Settings.create({ siteName: 'AKSU METAL' });
    }
    res.json(settings);
  } catch (error) {
    res.status(500).json({ message: 'Site ayarları getirilirken hata oluştu.' });
  }
});
app.get('/admin/settings', protect, async (req, res) => {
  try {
    let settings = await Settings.findOne();
    if (!settings) {
      settings = await Settings.create({ siteName: 'AKSU METAL' });
    }
    res.json(settings);
  } catch (error) {
    res.status(500).json({ message: 'Site ayarları getirilirken hata oluştu.' });
  }
});
app.put('/admin/settings', protect, async (req, res) => {
  console.log('PUT /admin/settings endpointi çağrıldı, req.user:', req.user);
  try {
    if (req.user.role !== 'superadmin') return res.status(403).json({ message: 'Yetki yok' });
    const { siteName, homepage, about, contact, footerText, logo, whatsapp, instagram, facebook } = req.body;
    let settings = await Settings.findOne();
    if (!settings) {
      settings = await Settings.create({ siteName, homepage, about, contact });
    } else {
      if (siteName !== undefined) settings.siteName = siteName;
      if (homepage !== undefined) settings.homepage = { ...settings.homepage, ...homepage };
      if (about !== undefined) settings.about = { ...settings.about, ...about };
      if (contact !== undefined) settings.contact = { ...settings.contact, ...contact };
      if (footerText !== undefined) settings.footerText = footerText;
      if (logo !== undefined) settings.logo = logo;
      if (whatsapp !== undefined) settings.whatsapp = whatsapp;
      if (instagram !== undefined) settings.instagram = instagram;
      if (facebook !== undefined) settings.facebook = facebook;
      await settings.save();
    }
    res.json(settings);
  } catch (error) {
    res.status(500).json({ message: 'Site ayarları güncellenirken hata oluştu.' });
  }
});
app.post('/admin/settings/slider-upload', protect, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'Dosya yüklenemedi' });
  res.json({ imageUrl: req.file.path });
});
// --- LOG ENDPOINTLERİ ---
app.get('/admin/logs', protect, async (req, res) => {
  try {
    if (req.user.role !== 'superadmin') return res.status(403).json({ message: 'Yetki yok' });
    const page = parseInt(req.query.page) || 1;
    const pageSize = parseInt(req.query.pageSize) || 10;
    const filter = {};
    if (req.query.date) {
      const start = new Date(req.query.date);
      const end = new Date(req.query.date);
      end.setDate(end.getDate() + 1);
      filter.createdAt = { $gte: start, $lt: end };
    }
    const total = await Log.countDocuments(filter);
    const logs = await Log.find(filter)
      .sort({ createdAt: -1 })
      .skip((page - 1) * pageSize)
      .limit(pageSize);
    res.json({ logs, total });
  } catch (error) {
    res.status(500).json({ message: 'Loglar getirilirken hata oluştu' });
  }
});
app.delete('/admin/logs', protect, async (req, res) => {
  try {
    if (req.user.role !== 'superadmin') return res.status(403).json({ message: 'Yetki yok' });
    await Log.deleteMany({});
    res.json({ message: 'Tüm loglar silindi' });
  } catch (error) {
    res.status(500).json({ message: 'Loglar silinirken hata oluştu' });
  }
});
// --- USERS ENDPOINTLERİ ---
app.get('/admin/users', protect, async (req, res) => {
  if (req.user.role !== 'superadmin') return res.status(403).json({ message: 'Yetki yok' });
  const users = await User.find();
  res.json(users);
});
app.post('/admin/users', protect, [
  body('username').isString().trim().isLength({ min: 3, max: 50 }),
  body('password').isString().isLength({ min: 6 }),
  body('role').isString().isIn(['admin', 'superadmin'])
], async (req, res) => {
  if (req.user.role !== 'superadmin') return res.status(403).json({ message: 'Yetki yok' });
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { username, password, role } = req.body;
  const existing = await User.findOne({ username });
  if (existing) return res.status(400).json({ message: 'Kullanıcı zaten var' });
  const passwordHash = await bcrypt.hash(password, 10);
  const user = await User.create({ username, passwordHash, role });
  res.status(201).json(user);
});
app.put('/admin/users/:id', protect, [
  body('username').optional().isString().trim().isLength({ min: 3, max: 50 }),
  body('email').optional().isEmail(),
  body('role').optional().isString().isIn(['admin', 'superadmin'])
], async (req, res) => {
  if (req.user.role !== 'superadmin') return res.status(403).json({ message: 'Yetki yok' });
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { username, email, role } = req.body;
  const user = await User.findByIdAndUpdate(req.params.id, { username, email, role }, { new: true });
  if (!user) return res.status(404).json({ message: 'Kullanıcı bulunamadı' });
  res.json(user);
});
app.delete('/admin/users/:id', protect, async (req, res) => {
  if (req.user.role !== 'superadmin') return res.status(403).json({ message: 'Yetki yok' });
  const user = await User.findByIdAndDelete(req.params.id);
  if (!user) return res.status(404).json({ message: 'Kullanıcı bulunamadı' });
  res.json({ message: 'Kullanıcı silindi' });
});
app.post('/admin/users/:id/reset-password', protect, [
  body('newPassword').isString().isLength({ min: 6 })
], async (req, res) => {
  if (req.user.role !== 'superadmin') return res.status(403).json({ message: 'Yetki yok' });
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { newPassword } = req.body;
  const passwordHash = await bcrypt.hash(newPassword, 10);
  const user = await User.findByIdAndUpdate(req.params.id, { passwordHash }, { new: true });
  if (!user) return res.status(404).json({ message: 'Kullanıcı bulunamadı' });
  res.json({ message: 'Şifre sıfırlandı' });
});
// --- ADMIN PROJE ENDPOINTLERİ ---
app.post(
  '/admin/projects',
  protect,
  upload.array('images', 10),
  [
    body('title').isString().trim().isLength({ min: 3, max: 100 }).withMessage('Başlık 3-100 karakter olmalı.'),
    body('description').isString().trim().isLength({ min: 10, max: 1000 }).withMessage('Açıklama 10-1000 karakter olmalı.'),
    body('category').isString().trim().isLength({ min: 2, max: 50 }).withMessage('Kategori 2-50 karakter olmalı.')
  ],
  async (req, res) => {
    if (req.user.role !== 'admin' && req.user.role !== 'superadmin') return res.status(403).json({ message: 'Yetki yok' });
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array().map(e => ({ msg: e.msg, param: e.param })) });
    }
    const { title, description, category, defaultImage, defaultImageIndex } = req.body;
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ message: 'En az bir resim ekleyin.' });
    }
    try {
      const imageUrls = req.files.map(file => file.path);
      let defaultImg = imageUrls[0];
      if (typeof defaultImageIndex !== 'undefined' && !isNaN(Number(defaultImageIndex)) && imageUrls[Number(defaultImageIndex)]) {
        defaultImg = imageUrls[Number(defaultImageIndex)];
      } else if (defaultImage && imageUrls.includes(defaultImage)) {
        defaultImg = defaultImage;
      }
      const newProject = await Project.create({
        title: sanitizeInput(title),
        description: sanitizeInput(description),
        category: sanitizeInput(category),
        imageUrls,
        defaultImage: defaultImg,
        imageUrl: defaultImg,
        createdBy: req.user.username,
      });
      await Log.create({ user: req.user.username, action: 'create_project', target: newProject._id.toString(), details: `Proje oluşturuldu: ${title}` });
      res.status(201).json(newProject);
    } catch (error) {
      res.status(500).json({ message: 'Proje eklenirken bir hata oluştu.' });
    }
  }
);
app.put(
  '/admin/projects/:id',
  protect,
  upload.array('images', 10),
  [
    body('title').optional().isString().trim().isLength({ min: 3, max: 100 }).withMessage('Başlık 3-100 karakter olmalı.'),
    body('description').optional().isString().trim().isLength({ min: 10, max: 1000 }).withMessage('Açıklama 10-1000 karakter olmalı.'),
    body('category').optional().isString().trim().isLength({ min: 2, max: 50 }).withMessage('Kategori 2-50 karakter olmalı.')
  ],
  async (req, res) => {
    if (req.user.role !== 'admin' && req.user.role !== 'superadmin') return res.status(403).json({ message: 'Yetki yok' });
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array().map(e => ({ msg: e.msg, param: e.param })) });
    }
    try {
      const { title, description, category, defaultImage } = req.body;
      let existingImages = req.body.existingImages;
      if (existingImages && !Array.isArray(existingImages)) {
        existingImages = [existingImages];
      }
      const project = await Project.findById(req.params.id);
      if (!project) return res.status(404).json({ message: 'Proje bulunamadı' });
      // Silinen eski resimleri Cloudinary'den kaldır
      if (Array.isArray(existingImages)) {
        const toDelete = (project.imageUrls || []).filter(url => !existingImages.includes(url));
        for (const url of toDelete) {
          const publicId = url.split('/').slice(-2).join('/').split('.')[0];
          try { await cloudinary.uploader.destroy(publicId); } catch (e) { /* ignore */ }
        }
      }
      let imageUrls = Array.isArray(existingImages) ? [...existingImages] : (project.imageUrls || []);
      if (req.files && req.files.length > 0) {
        const newImageUrls = req.files.map(file => file.path);
        imageUrls = imageUrls.concat(newImageUrls);
      }
      let defaultImg = defaultImage && imageUrls.includes(defaultImage) ? defaultImage : imageUrls[0];
      const updatedData = {
        title: title ? sanitizeInput(title) : project.title,
        description: description ? sanitizeInput(description) : project.description,
        category: category ? sanitizeInput(category) : project.category,
        imageUrls,
        defaultImage: defaultImg,
        imageUrl: defaultImg,
      };
      const updatedProject = await Project.findByIdAndUpdate(req.params.id, updatedData, { new: true });
      await Log.create({ user: req.user.username, action: 'update_project', target: req.params.id, details: `Proje güncellendi: ${updatedProject.title}` });
      res.json(updatedProject);
    } catch (error) {
      res.status(500).json({ message: 'Proje güncellenirken bir hata oluştu.' });
    }
  }
);
app.delete('/admin/projects/:id', protect, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'superadmin') return res.status(403).json({ message: 'Yetki yok' });
  try {
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ message: 'Proje bulunamadı' });
    await Project.deleteOne({ _id: req.params.id });
    await Log.create({ user: req.user.username, action: 'delete_project', target: req.params.id, details: `Proje silindi: ${project.title}` });
    res.json({ message: 'Proje başarıyla silindi' });
  } catch (error) {
    res.status(500).json({ message: 'Proje silinirken bir sunucu hatası oluştu.' });
  }
});
// --- HATA YAKALAMA ---
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ message: 'Dosya boyutu çok büyük. Maksimum 5MB olmalı.' });
    }
    if (error.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({ message: 'Beklenmeyen dosya alanı.' });
    }
  }
  if (error.message === 'Sadece resim dosyaları yüklenebilir!') {
    return res.status(400).json({ message: error.message });
  }
  console.error('Sunucu hatası:', error);
  res.status(500).json({ message: 'Sunucuda bir hata oluştu' });
});

app.listen(PORT, () => {
  console.log(`Sunucu ${PORT} portunda çalışıyor`);
});