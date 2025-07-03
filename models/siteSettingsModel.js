const mongoose = require('mongoose');

const settingsSchema = new mongoose.Schema({
  siteName: { type: String, default: 'AKSU METAL' },
  homepage: { type: Object, default: {} },
  about: { type: Object, default: {} },
  contact: { type: Object, default: {} },
  footerText: { type: String },
  logo: { type: String },
  whatsapp: { type: String },
  instagram: { type: String },
  facebook: { type: String }
});

module.exports = mongoose.model('Settings', settingsSchema); 