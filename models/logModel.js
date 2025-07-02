const mongoose = require('mongoose');

const logSchema = new mongoose.Schema({
  user: String,
  action: String,
  target: String,
  details: String,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Log', logSchema); 