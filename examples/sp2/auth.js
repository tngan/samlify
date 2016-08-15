var LocalStrategy = require('passport-local').Strategy;
var passport = require('passport');
var bcrypt = require('bcryptjs');
var uuid = require('node-uuid');
var epn = {
  'admin@sp2.com' : {
    assoHash: '$2a$10$/0lqAmz.r6trTurxW3qMJuFHyicUWsV3GKF94KcgN42eVR8y5c25S'
  }
};

function findEmailFromDummyDb(email,password,callback){
  if(epn[sysEmail]){
    bcrypt.compare(password,epn[sysEmail].assoHash,function(err,res){
      if(err || !res){
        callback(new Error('Authentication failure'));
      } else {
        callback(null,{
          email: sysEmail
        });
      }
    });
  } else {
    callback(new Error('Authentication failure'));
  }
}

function findEmailFromDummyDb(sysEmail, password, callback){
  if(epn[sysEmail]){
    bcrypt.compare(password,epn[sysEmail].assoHash,function(err,res){
      if(err || !res){
        callback(new Error('Authentication failure'));
      } else {
        callback(null,{
          email: sysEmail
        });
      }
    });
  } else {
    callback(new Error('Authentication failure'));
  }
}

module.exports = function(passport) {

  passport.use('local-login', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
  }, function(req, spEmail, password, done) {
    findEmailFromDummyDb(spEmail,password,function(err,user){
      if(err) {
        req.flash('info','Invalid email or password');
        done(null, false, {
          messages: 'Invalid email or password'
        });
      } else {
        done(null, {
          email: user.email,
          logoutNameID: user.email,
          sessionIndex: uuid.v4()
        });
      }
    });
  }));

  passport.use('sso-login', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
  }, function(email, password, done) {
    if(Object.keys(epn).indexOf(email)!=-1){
      done(null,{
        email: email,
        logoutNameID: email
      });
    } else {
      done(null, false, {
        messages: 'Invalid email'
      });
    }
  }));

  passport.serializeUser(function(user, done) {
    done(null, {
      email: user.email,
      logoutNameID: user.email
    });
  });

  passport.deserializeUser(function(user, done) {
    if(Object.keys(epn).indexOf(user.email)!=-1){
      done(null,{
        email: user.email,
        logoutNameID: user.email
      });
    }else{
      done(null, false, {
        messages: 'Fail to do deserializeUser'
      });
    }
  });

};
