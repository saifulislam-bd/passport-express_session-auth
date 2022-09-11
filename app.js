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

app.set('trust proxy', 1); // trust first proxy
app.use(
    session({
        secret: 'keyboard cat',
        resave: false,
        saveUninitialized: true,
        store: MongoStore.create({
            mongoUrl: process.env.MONGO_URL,
            collectionName: 'sessions',
        }),
        // cookie: { secure: true },
    }),
);

app.use(passport.initialize());
app.use(passport.session());

// home route
app.get('/', (req, res) => {
    res.render('index');
});

// register route: get
app.get('/register', (req, res) => {
    res.render('register');
});

// register route: post
app.post('/register', async (req, res) => {
    try {
        const user = await User.findOne({
            username: req.body.username,
        });
        if (user) {
            res.status(400).send('User is already registered');
        }
        bcrypt.hash(req.body.password, saltRounds, async (err, hash) => {
            const newUser = new User({
                username: req.body.username,
                password: hash,
            });
            await newUser.save();
            res.redirect('/login');
        });
    } catch (error) {
        res.status(500).send('User not created');
    }
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

// login route: post
app.post(
    '/login',
    passport.authenticate('local', { failureRedirect: '/login', successRedirect: '/profile' }),
);

const checkAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
};

// isAuthenticated route: profile protected
app.get('/profile', checkAuthenticated, (req, res) => {
    res.render('profile');
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
