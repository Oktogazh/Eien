var mongoose = require('mongoose');

mongoose.model('User', new mongoose.Schema({
    email: String,
    passwordHash: String,
    ResetPassword: {
      data: String,
      default: ''
    },
    subscriptionActive: {
      type: Boolean,
      default: false},
    customerId: String,
    subscriptionId: String
}, {timestamps: true}));
