var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var passportLocalMongoose = require('passport-local-mongoose');


var user = new Schema({
    email: String,
    passwordHash: String,
    ResetPassword: String,
    ResetPasswordExpire: Date,
    subscriptionActive: {
      type: Boolean,
      default: false
    },
    languages: [{
      name: String,
      dialect: String,
      begins: Boolean,
      started: Date,
      level: {
        type: Number,
        default: 0
      }
    }],
    customerId: String,
    subscriptionId: String
}, {timestamps: true});

user.plugin(passportLocalMongoose, {
    usernameField: 'email'
});

var User = mongoose.model('User', user)
module.exports = User;
