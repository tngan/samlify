var express = require('express');
var router = express.Router();
var passport = require('passport');
var fs = require('fs');
var utility = require('../../../index').Utility;

router.get('/', function(req, res, next) {
    if(req.isAuthenticated()){
        res.render('index', {
            title: 'idp - management console',
            user: req.user
        });
    }else{
        res.redirect('/login');
    }
});

router.get('/login',function(req,res,next){
    if(req.isAuthenticated()){
        res.redirect('/');
    }else{
        res.render('login', {
            title: 'idp - Login',
            messages: req.flash('info')
        });
    }
});

router.get('/login/external.esaml', function(req, res, next) {
    var method = req.query.METHOD,
    target = req.query.TARGET;
    if(method && target){
        res.render('login', {
            title: 'idp - SSO External Login',
            web: 'es2-IdP External Login',
            method: method,
            target: target
        });
    } else {
        res.redirect('/login');
    }
});

router.get('/logout',function(req,res,next){
    req.logout();
    res.redirect('/login');
});

router.post('/login', function(req, res, next) {
    passport.authenticate('local-login', function(err, user, info) {
        if (err) { return next(err); }
        if (!user) { return res.redirect('/login'); }
        req.logIn(user, function(err) {
            if(req.body.method == 'post'){
                return res.render('actions',JSON.parse(utility.base64Decode(req.body.target)));
            } else if(req.body.method == 'get'){
                return res.redirect(utility.base64Decode(req.body.target));
            }
            return res.redirect('/');
        });
    })(req, res, next);
});

module.exports = router;
