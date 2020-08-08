var mongoose = require('mongoose');

mongoose.model('User', new mongoose.Schema({
    email: String,
    passwordHash: String,
    ResetPassword: String,
    ResetPasswordExpire: Date,
    subscriptionActive: {type: Boolean, default: false},
    customerId: String,
    subscriptionId: String},
    {timestamps: true}
));
