const express = require('express');
const router = express.Router();
const passport = require('passport');
const bcrypt = require('bcryptjs');

const User = require('../models/User');

router.get('/login', (req, res) => {
    res.render('login');
});

router.post('login', (req, res, next) => {
    passport.authenticate('local',
    {
        successRedirct: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req, res, next);
});

router.get('/register', (req, res) => {
    res.render('register');
});

router.post('/register', (req, res) => {
    const { username, password, password2 } = req.body;
    let errors = [];

    if(!username || !password || !password2) {
        errors.push({ msg: 'Please fill in all fields'});
    }

    if(password!== password2) {
        errors.push({ msg: 'Passwords do not match'});
    }

    if(password.length < 6) {
        errors.push({ msg: 'Password must be at least 6 characters'});
    }

    if(errors.length > 0) {
        res.render('register', {
            errors,
            username,
            password,
            password2
        });
    } else {
        User.findOne({ username: username })
            .then(user => {
                if(user) {
                    errors.push({ msg: 'Username already exists'});
                    res.render('register', {
                        errors,
                        username,
                        password,
                        password2
                    });
                } else {
                    const newUser = new User({
                        username,
                        password
                    });

                    bcrypt.genSalt(10, (err, salt) => {
                        bcrypt.hash(newUser.password, salt, (err, hash) => {
                            if (err) throw err;
                            newUser.password = hash;
                            newUser
                                .save()
                                .then(user => {
                                    req.flash('success_msg', 'You are now registered and can log in');
                                    res.redirect('/users/login');
                                })
                                .catch(err => console.log(err));
                        })
                    })
                }
            })

    }
});

router.get('/logout', (req, res) => {
    req.logout();
    req.flash('success_msg', 'You are now logged out');
    res.redirect('/users/login');
});

module.exports = router;