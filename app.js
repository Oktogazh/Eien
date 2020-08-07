var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var mongoose = require('mongoose');
require('./models');
var bcrypt = require('bcrypt');
var expressSession = require('express-session');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var dotenv = require('dotenv');
dotenv.config();

var User = mongoose.model('User');

// Set your secret key. Remember to switch to your live secret key in production!
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);


mongoose.connect('mongodb://localhost:27017/mydb', { useNewUrlParser: true, useUnifiedTopology: true });

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.set('trust proxy', 1)

// create a path to serve static files
app.use("/traouegezh", express.static(path.join(__dirname, "assets")));

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
    console.log(session);
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

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(expressSession({
    secret: process.env.EXPRESS_SESSION_SECRET,
    saveUninitialized: true,
    resave: true,
    cookie: {maxAge: 31556952000000,
      secure: true
    },
}));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
}, function(email, password, next) {
  User.findOne({
    email: email
  }, function(err, user) {
    if (err) return next(err);
    if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
      return next({message: 'Email or password incorrect!'})
    }
    next(null, user);
  })
}));

passport.use('signup-local', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
}, function(email, password, next) {
  User.findOne({
    email: email
  }, function (err, user) {
    if (err) return next(err);
    if (user) return next({message: "This address has already an account related to it!"});
    let newUser = new User({
      email: email,
      passwordHash: bcrypt.hashSync(password, 10)
    });
    newUser.save(function(err) {
      next(err, newUser);
    });
  });
}));

passport.serializeUser(function(user, next) {
  next(null, user._id);
});

passport.deserializeUser(function(id, next) {
  User.findById(id, function(err, user){
    next(err, user);
  });
});

app.get('/', function(req, res, next) {
  req.user? res.redirect('/penn') : res.render('index', {title: "Eien"});
});

app.post('/signup',
  passport.authenticate('signup-local', { failureRedirect: '/' }),
  function(req, res) {
    res.redirect('/penn');
  }
);

app.get('/login', function(req, res, next) {
  res.render('login', {title: "Connexion - Eien"});
});

app.get('/ger-kuzh', function(req, res, next) {
  res.render('forgot', {title: "Mot de passe oublié - Eien"});
});


app.get('/penn', function(req, res, next) {
  let userEmail = req.user? req.user.email : null;
  res.render('main/main', {title: "Accueil", email: userEmail})
  console.log(userEmail);
});

app.post('/login',
  passport.authenticate('local', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/penn');
  }
);

app.post('/ger-kuzh', function (req, res) {
   const email = req.body.email
   User
       .findOne({
           where: {email: email},//checking if the email address sent by client is present in the db(valid)
       })
       .then(function (user) {
           if (!user) {
               return throwFailed(res, 'No user found with that email address.')
           }
           ResetPassword
               .findOne({
                   where: {userId: user.id, status: 0},
               }).then(function (resetPassword) {
               if (resetPassword)
                   resetPassword.destroy({
                       where: {
                           id: resetPassword.id
                       }
                   })
               token = crypto.randomBytes(32).toString('hex')//creating the token to be sent to the forgot password form (react)
               bcrypt.hash(token, null, null, function (err, hash) {//hashing the password to store in the db node.js
                   ResetPassword.create({
                       userId: user.id,
                       resetPasswordToken: hash,
                       expire: moment.utc().add(config.tokenExpiry, 'seconds'),
                   }).then(function (item) {
                       if (!item)
                           return throwFailed(res, 'Oops problem in creating new password record')
                       let mailOptions = {
                           from: '"<jyothi pitta>" jyothi.pitta@ktree.us',
                           to: user.email,
                           subject: 'Reset your account password',
                           html: '<h4><b>Reset Password</b></h4>' +
                           '<p>To reset your password, complete this form:</p>' +
                           '<a href=' + config.clientUrl + 'reset/' + user.id + '/' + token + '">' + config.clientUrl + 'reset/' + user.id + '/' + token + '</a>' +
                           '<br><br>' +
                           '<p>--Team</p>'
                       }
                       let mailSent = sendMail(mailOptions)//sending mail to the user where he can reset password.User id and the token generated are sent as params in a link
                       if (mailSent) {
                           return res.json({success: true, message: 'Check your mail to reset your password.'})
                       } else {
                           return throwFailed(error, 'Unable to send email.');
                       }
                   })
               })
           });
       })
});

app.get('/logout', function(req, res, next) {
  req.logout();
  res.redirect('/');
});

app.get('/bretonffr', function(req, res, next) {
  let userEmail = req.user? req.user.email : null
  res.render('demos/demobrffr', {title: "Demo Dreton - Eien", email: userEmail})
  console.log(userEmail);
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
    success_url: 'https://' + process.env.APP_HOST + '/penn?session_id={CHECKOUT_SESSION_ID}',
    cancel_url: 'https://' + process.env.APP_HOST + '/stal',
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
