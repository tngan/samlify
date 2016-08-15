// Polyfill
if (!Object.assign) {
  Object.defineProperty(Object, 'assign', {
    enumerable: false,
    configurable: true,
    writable: true,
    value: function(target) {
      'use strict';
      if (target === undefined || target === null) {
        throw new TypeError('Cannot convert first argument to object');
      }

      var to = Object(target);
      for (var i = 1; i < arguments.length; i++) {
        var nextSource = arguments[i];
        if (nextSource === undefined || nextSource === null) {
          continue;
        }
        nextSource = Object(nextSource);

        var keysArray = Object.keys(nextSource);
        for (var nextIndex = 0, len = keysArray.length; nextIndex < len; nextIndex++) {
          var nextKey = keysArray[nextIndex];
          var desc = Object.getOwnPropertyDescriptor(nextSource, nextKey);
          if (desc !== undefined && desc.enumerable) {
            to[nextKey] = nextSource[nextKey];
          }
        }
      }
      return to;
    }
  });
}

var express = require('express');
var router = express.Router();
var utility = require('../../../index').Utility;
var ServiceProvider = require('../../../index').ServiceProvider;
var IdentityProvider = require('../../../index').IdentityProvider;

var SPMetadata = '../metadata/metadata_sp1.xml';
var SPMetadataForOnelogin = '../metadata/metadata_sp1_onelogin.xml';

var basicSPConfig = {
  privateKeyFile: '../key/sp/privkey.pem',
  privateKeyFilePass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
  requestSignatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
};

var sp = ServiceProvider(basicSPConfig,SPMetadata);
var idp = IdentityProvider({ isAssertionEncrypted: true },'../metadata/metadata_idp1.xml');

// Simple integration to OneLogin
var oneLoginIdP = IdentityProvider('../metadata/onelogin_metadata_486670.xml');
var olsp = ServiceProvider(SPMetadataForOnelogin);

///
/// metadata is publicly released, can access at /sso/metadata
///
router.get('/metadata',function(req, res, next){
  res.header('Content-Type','text/xml').send(sp.getMetadata());
});

router.get('/spinitsso-post',function(req,res){
  var which = req.query.id || '';
  var toIdP, fromSP;
  switch(which){
    case 'onelogin': {
      fromSP = olsp;
      toIdP = oneLoginIdP;
      break;
    }
    default: {
      fromSP = sp;
      toIdP = idp;
      break;
    }
  }
  console.log(fromSP.entityMeta.isAuthnRequestSigned(),toIdP.entityMeta.isWantAuthnRequestsSigned());
  fromSP.sendLoginRequest(toIdP,'post',function(request){
    res.render('actions',request);
  });
});

router.get('/spinitsso-redirect',function(req,res){
  sp.sendLoginRequest(idp,'redirect',function(url){
    res.redirect(url);
  });
});

router.post('/acs/:idp?',function(req,res,next){
  var _idp, _sp;
  if(req.params.idp === 'onelogin'){
    _idp = oneLoginIdP;
    _sp = olsp;
  } else {
    _idp = idp;
    _sp = sp;
  }
  _sp.parseLoginResponse(_idp,'post',req,function(parseResult){
    if(parseResult.extract.nameid){
      res.render('login',{
        title: 'Processing',
        isSSOLogin: true,
        email: parseResult.extract.nameid
      });
    } else {
      req.flash('info','Unexpected error');
      res.redirect('/login');
    }
  });
});

router.post('/slo',function(req,res){
  sp.parseLogoutRequest(idp,'post',req,function(parseResult){
    // Check before logout
    req.logout();
    sp.sendLogoutResponse(idp,parseResult,'redirect',req.body.RelayState,function(url){
      res.redirect(url);
    });
  });
});

router.get('/slo',function(req,res){
  sp.parseLogoutResponse(idp,'redirect',req,function(parseResult){
    // Check before logout
    req.logout();
    sp.sendLogoutResponse(idp,parseResult,'redirect',req.query.RelayState,function(url){
      res.redirect(url);
    });
  });
});

module.exports = router;
