var createError = require('http-errors');
var express = require('express');
var favicon = require('serve-favicon');
var path = require('path');
var flash = require('connect-flash');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var mongoose = require('mongoose');
require('./models');
var bcrypt = require('bcrypt');
var expressSession = require('express-session');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var localMongoose = require('passport-local-mongoose');
var dotenv = require('dotenv');
var async = require('async');
var nodemailer = require('nodemailer');
var crypto = require('crypto');
dotenv.config();

// Set your secret key. Remember to switch to your live secret key in production!
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

mongoose.connect('mongodb://localhost:27017/mydb', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true
});

var app = express();

var User = mongoose.model('User');

// some settings
app.set('case sensitive routing', true);
app.set('views', path.join(__dirname, 'views'));
app.set('trust proxy', 1);
app.set('view engine', 'ejs');


// Use body-parser to retrieve the raw body as a buffer
const bodyParser = require('body-parser');

// Match the raw body to content type application/json
app.post('/webhooks', bodyParser.raw({type: 'application/json'}), (request, response) => {
  const sig = request.headers['stripe-signature'];

  let event;

  try {
    event = stripe.webhooks.constructEvent(request.body, sig, process.env.ENDPOINT_SECRET);
  } catch (err) {
    return response.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle the checkout.session.completed event
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;

    //Fulfill the purchase...
    User.findOne({
      email: session.customer_email
    }, function(err, user) {
      if (user) {
        user.subscriptionActive = true;
        user.subscriptionId = session.subscription;
        user.customerId = session.customer;
        user.save();
      }
    });
  }

  // Handle the customer.subscription.deleted construct event
  if (event.type === 'customer.subscription.deleted') {
    const endingSubscription = event.data.object;

    //End the subscription...
    console.log(endingSubscription);
    User.findOne({
      subscriptionId: endingSubscription.id
    }, function(err, user) {
      if (user) {
        user.subscriptionActive = false;
        user.subscriptionId = null;
        user.save();
      }
    });
  }

  // Return a response to acknowledge receipt of the event
  response.json({received: true});
});

app.use(favicon(path.join(__dirname, 'public/css', 'favicon.ico')));
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser(process.env.EXPRESS_SESSION_SECRET));
app.use(express.static(path.join(__dirname, 'public')));
app.use("/traouegezh", express.static(path.join(__dirname, "/media/public")));
app.use(expressSession({
    secret: process.env.EXPRESS_SESSION_SECRET,
    saveUninitialized: true,
    resave: true,
    cookie: {maxAge: 31556952000000,
      secure: false
    },
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// use authenticate method of model in LocalStrategy
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get('/', function(req, res, next) {
  let message = req.flash('error');
  let already = req.flash('alreadyAnAccount');
  req.user? res.redirect('/penn') : res.render('login', {
    title: "Eienn",
    already: already,
    messagePassword: message,
  });
});

app.post('/login',
  passport.authenticate('local', {
    successRedirect : '/penn',
    failureRedirect: '/',
    failureFlash : { type: 'error', message: 'Password' } }),
);

//Registration
app.get('/nevez', function(req, res, next) {
  req.user? res.redirect('/penn') : res.render('signup', {title: "Eienn"});
});

app.post('/signup', function(req, res, next) {
  User.exists({email: req.body.email}, function(err, booleanValue) {
    if (err) {
      next(err);
    } else {
      if (booleanValue == true) {
        return res.req.flash('alreadyAnAccount', 'this address is already used') && res.redirect('/');
      } else {
        User.register(new User({email: req.body.email}), req.body.password, function(err) {
          if (err) {
            return next(err);
          } else {
            User.findOne({email: req.body.email}, function(err, user) {
              if (err) return next(err);
              else if (user) {
                req.logIn(user, function(err){
                  if (err) return next(err);
                  else return res.redirect('/penn');
                });
              }
            })
          }
        })
      }
    }
  })
});

//Forgot password
app.get('/ger-kuzh', function(req, res, next) {
  res.render('forgot', {title: "Mot de passe oublié - Eienn", errorMessage: req.flash('error')});
});

//Handles the form submitted in forgot.ejs, send and reset email
app.post('/ger-kuzh', function (req, res, next) {
  async.waterfall([
    function(done) {
      crypto.randomBytes(36, function(err, buf){
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done){
      User.findOne({email: req.body.email}, function(err, user) {
        if (!user) {
          req.flash('error', process.env.APP_HOST);
          res.redirect('/ger-kuzh')
        } else {
          user.ResetPassword = token;
          user.ResetPasswordExpire = Date.now() + 3600000;  //one hour

          user.save(function(err) {
            done(err, token, user);
          });
        }
      });
    },
    function(token, user, done) {
      var sntpTransport = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
          user: process.env.EMAIL_ADDRESS,
          pass: process.env.EMAIL_PASSWORD
        }
      });
      var mailOptions = {
        to: user.email,
        from: process.env.EMAIL_ADDRESS,
        subject: 'Réinitialiser mon mot de passe',
        text: 'Vous recevez ce mail car vous, ou une autre personne,' +
        'a demandé une réinitialisation du mot de passe de votre compte Eienn.' +
        '\nSi vous n\'êtes pas à l\'origine de cette procédure,' +
        'contentez vous d\'ignorer ce message.' +
        'Si vous avez bien demandé une réinitialisation de votre mot de passe,' +
        'veuillez suivre ce lien pour compléter la procédure: \n \n' +
        process.env.APP_HOST + '/ger-kuzh/nevez/' + token + '\n \n'
      };
      sntpTransport.sendMail(mailOptions, function(err){
        console.log('reset password email sent');
        req.flash('success', 'Un email vient d\'être envoyé à' + user.email + 'pour finaliser la procédure');
        done(err, 'done');
      });
    }
  ], function(err) {
    if (err) return next(err);
    res.redirect('/ger-kuzh');
  });
});

//Reset the password
app.get('/ger-kuzh/nevez/:token', function(req, res, next) {
  User.findOne({ResetPassword : req.params.token, ResetPasswordExpire: { $gt: Date.now() } }, function(err, user) {
    if (!user) {
    req.flash('message', 'Token Expired or Invalid');
    return res.redirect('/ger-kuzh');
  }
  res.render('reset', {title: "Réinitialisation du mot de passe - Eienn", ResetPassword: req.params.token, message: req.flash('message'), host: process.env.APP_HOST });
  })
});

app.post('/ger-kuzh/nevez/:token', function(req, res, next) {
  async.waterfall([
    function(done) {
      User.findOne({ResetPassword: req.params.token, ResetPasswordExpire: { $gt: Date.now() } }, function(err, user) {
        if (!user) {
          req.flash('message', 'invalid token');
          return res.redirect('back');
        }
        if (req.body.password === req.body.confirm) {
          user.setPassword(req.body.password, function(err){
            user.ResetPassword = undefined;
            user.ResetPasswordExpire = undefined;

            user.save(function(err) {
              req.logIn(user, function(err) {
                done(err, user);
              });
            });
          })
        } else {
          req.flash ('message', 'not the same passwords');
          res.redirect(`/ger-kuzh/nevez/${req.params.token}`);
        }
      });
    }
  ],function(err) {
    req.flash('password', req.body.password);
    res.redirect('/penn');
  })
});

app.get('/deski%C3%B1/:folder/:file', function(req, res, next) {
  var folder = req.params.folder;
  var file = req.params.file;
  var filePath = folder + '/' + file;
  var email = req.user? req.user.email : null;
  if (req.user && req.user.subscriptionActive === true) {
    var options = {
      root: path.join(__dirname, 'media'),
    };
    User.findOne({
      email: email
    }, function(err, user) {
        if (err) return next(err);
        user.learning.folder = folder;
        user.learning.file = file;
        user.save();
    });
    res.sendFile('methods/' + filePath + '.wav', options, function(err) {
      if (err) return next(err);
    });

  } else {
    res.status(403).end("N\'oc\'h ket aotreet da vont pelloc'h!");
  }
});


app.get('/penn', function(req, res, next) {
  let title = 'Eienn';
  let userEmail = req.user? req.user.email : null;
  let subscriptionActive = req.user? req.user.subscriptionActive : false;
  let newPassword = req.flash('password') || null;
  let learningSource = req.user? req.user.learning.folder : null;
  let file = req.user? req.user.learning.file : null;
  res.render('main/main', {
    title: title,
    email: userEmail,
    active: subscriptionActive,
    newPassword: newPassword,
    learningSource: learningSource,
    file: file,
  });
});

app.get('/logout', function(req, res, next) {
  req.logOut();
  res.redirect('/');
});

app.get('/bretonffr', function(req, res, next) {
  let userEmail = req.user? req.user.email : null
  res.render('demos/demobrffr', {title: "Demo Dreton - Eienn", email: userEmail});
});

app.get('/ouzhpenn', function(req, res, next) {
  let userEmail = req.user? req.user.email : null
  res.render('newLanguage', {title: 'New Language', email: userEmail})
});

app.get('/stal', function(req, res, next) {
  const session = stripe.checkout.sessions.create({
    customer_email: req.user.email,
    payment_method_types: ['card'],
    line_items: [{
      price: process.env.STRIPE_PRICE,
      quantity: 1,
    }],
    mode: 'subscription',
    success_url: process.env.APP_HOST + '/penn?session_id={CHECKOUT_SESSION_ID}',
    cancel_url: process.env.APP_HOST + '/stal',
  }, function(err, session) {
    if (err) return next(err);
    res.render('billing', {STRIPE_PUBLIC_KEY: process.env.STRIPE_PUBLIC_KEY,
      title: 'Magasin',
      sessionId: session.id,
      subscriptionActive: req.user.subscriptionActive,
      email: req.user.email,
      subscriptionId: req.user.subscriptionId
    })
  });
});

app.post('/unsubscribe', function(req, res, next) {
  stripe.subscriptions.del(req.user.subscriptionId);
  res.redirect('/stal');
});


// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

console.log("connected to: " + process.env.APP_HOST);

module.exports = app;
