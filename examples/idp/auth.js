var LocalStrategy = require('passport-local').Strategy;
var passport = require('passport');
var bcrypt = require('bcryptjs');
// store in database
var epn = {
  'admin@idp.com': {
    assoHash: '$2a$10$/0lqAmz.r6trTurxW3qMJuFHyicUWsV3GKF94KcgN42eVR8y5c25S'
  }
};

function findEmailFromDummyDb(sysEmail, password, callback) {
  if (epn[sysEmail]) {
    bcrypt.compare(password, epn[sysEmail].assoHash, function (err, res) {
      if (err || !res) {
        callback(new Error('Authentication failure'));
      } else {
        callback(null, {
          sysEmail: sysEmail
        });
      }
    });
  } else {
    callback(new Error('Authentication failure'));
  }
}

module.exports = function (passport) {
  passport.use('local-login', new LocalStrategy({
    usernameField: 'email'
  }, function (idpEmail, password, done) {
    // do email mapping
    findEmailFromDummyDb(idpEmail, password, function (err, user) {
      if (err) {
        done(null, false, {
          messages: err.toString()
        });
      } else {
        done(null, {
          sysEmail: user.sysEmail
        });
      }
    });
  }));

  passport.serializeUser(function (user, done) {
    done(null, {
      sysEmail: user.sysEmail
    });
  });

  passport.deserializeUser(function (user, done) {
    if (Object.keys(epn).indexOf(user.sysEmail) != -1) {
      done(null, {
        sysEmail: user.sysEmail
      });
    } else {
      return done(null, false, {
        messages: 'Fail to do deserializeUser'
      });
    }
  });

};
