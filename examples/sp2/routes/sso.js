var express = require('express');
var router = express.Router();

var sp = require('../../../build/index').ServiceProvider({
  privateKeyFile: '../key/sp/privkey.pem',
  privateKeyFilePass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
  encPrivateKeyFile: '../key/sp/encryptKey.pem',
  encPrivateKeyFilePass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
  requestSignatureAlgorithm: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
  metadata: '../metadata/metadata_sp2.xml'
});

var idp = require('../../../build/index').IdentityProvider({
  isAssertionEncrypted: true,
  metadata: '../metadata/metadata_idp2.xml'
});

router.get('/metadata', function (req, res, next) {
  res.header('Content-Type', 'text/xml').send(sp.getMetadata());
});

router.get('/spinitsso-post', function (req, res) {
  const request = sp.sendLoginRequest(idp, 'post');
  res.render('actions', request);
});

router.get('/spinitsso-redirect', function (req, res) {
  const url = sp.sendLoginRequest(idp, 'redirect');
  res.redirect(url);
});

router.post('/acs', function (req, res, next) {
  sp.parseLoginResponse(idp, 'post', req)
  .then(parseResult => {
    if (parseResult.extract.nameid) {
      res.render('login', {
        title: 'Processing',
        isSSOLogin: true,
        email: parseResult.extract.nameid
      });
    } else {
      res.redirect('/login');
    }
  })
  .catch(err => {
    res.render('error', {
      message: err.message
    });
  });
});

function slo (req, res, binding, relayState) {
  sp.parseLogoutRequest(idp, binding, req)
    .then(parseResult => {
      req.logout();
      const url = sp.sendLogoutResponse(idp, parseResult, 'redirect', relayState);
      res.redirect(url);
    })
    .catch(err => {
      res.render('error', {
        message: err.message
      });
    });
}

router.post('/slo', function (req, res) {
  slo(req, res, 'post', req.body.RelayState)
});

router.get('/slo', function (req, res) {
  slo(req, res, 'redirect', req.query.RelayState)
});

module.exports = router;
