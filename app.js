/////// app.js

//imports
const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const { format } = require("path");
require('dotenv').config()
const bcrypt = require('bcryptjs')

//database integration
const mongoDb = process.env.DB_URI;
const Schema = mongoose.Schema;
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
  })
);

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

passport.use(
  new LocalStrategy((username, password, done) => {
    User.findOne({username: username}, (err, user) => {
      if (err) {
        return done(err)
      } if (!user) {
        return done(null, false, {message: 'Incorrect username'});
      } bcrypt.compare(password, user.password, (err, res) => {
        if (res) {
          // passwords match! log user in
          return done(null, user)
        } else {
          // passwords do not match!
          return done(null, false, { message: "Incorrect password" })
        }
      })
    })
  })
)

passport.serializeUser(function(user, done) {
  done(null, user.id);
})

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.use(function(req, res, next) {
  res.locals.currentUser = req.user;
  next();
})

app.get("/", (req, res) => {
  res.render("index", {user:req.user});
});
app.get('/sign-up-form', (req, res) => res.render('sign-up-form'));

app.post('/sign-up-form', (req, res, next) => {
  
  bcrypt.hash(req.body.password, 10, function (err, hash) {
    if (err) next(err);
    const user = new User ({
      username:req.body.username,
      password:hash
    }).save(err => {
      if (err) {
        return next(err)
      }
      res.redirect('/') 
    })
  })

/*  const user = new User({
    username: req.body.username,
    password: pw
  }).save(err => {
    if (err) {
      return next(err)
    }
    res.redirect('/')
  })*/
})

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/"
  })
);

app.get("/log-out", (req, res, next) => {
  try {
    req.logout(err => err ? next(err): res.redirect('/'))
  } catch (err) {
    return next(err)
  }
})

app.listen(3000, () => console.log("app listening on port 3000!"));