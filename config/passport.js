require('dotenv').config();
const passport = require('passport');
const bcrypt = require('bcrypt');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/user.model');

passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: 'http://localhost:4000/auth/google/callback',
        },
        (accessToken, refreshToken, profile, cb) => {
            User.findOne({ googleId: profile.id }, (err, user) => {
                if (err) return cb(err, null);
                // not a user: create a new user
                if (!user) {
                    const newUser = new User({
                        googleId: profile.id,
                        username: profile.displayName,
                    });
                    newUser.save();
                    return cb(null, newUser);
                }
                // if user is already exist return user
                return cb(null, user);
            });
        },
    )
);
// create session id
// whenever we login it creates a new session id
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// find session info using session id
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (error) {
        done(error, false);
    }
});
