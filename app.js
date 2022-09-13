const express = require('express');
const cors = require('cors');
const ejs = require('ejs');
const bcrypt = require('bcrypt');
const passport = require('passport');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const User = require('./models/user.model');
require('./config/database');
require('./config/passport');
require('dotenv').config();

const saltRounds = 10;

const app = express();

// middlewares
app.set('view engine', 'ejs');
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.set('trust proxy', 1);
app.use(
    session({
        secret: 'keyboard cat',
        resave: false,
        saveUninitialized: true,
        store: MongoStore.create({
            mongoUrl: process.env.MONGO_URL,
            collectionName: 'sessions',
        }),
    })
);

app.use(passport.initialize());
app.use(passport.session());

// home route
app.get('/', (req, res) => {
    res.render('index');
});
const isLoggedIn = (req, res, next) => {
    if (req.isAuthenticated()) {
        res.redirect('/profile');
    }
    next();
};
// login route: get
app.get('/login', isLoggedIn, (req, res) => {
    res.render('login');
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));

app.get(
    '/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login', successRedirect: '/profile' }),
    (req, res) => {
        // Successful authentication, redirect home.
        res.redirect('/');
    }
);

const checkAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
};

// isAuthenticated route: profile protected
app.get('/profile', checkAuthenticated, (req, res) => {
    res.render('profile', { username: req.user.username });
});

// logout route
app.get('/logout', (req, res) => {
    try {
        req.logout((err) => {
            if (err) {
                return next(err);
            }
            res.redirect('/');
        });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// export
module.exports = app;
