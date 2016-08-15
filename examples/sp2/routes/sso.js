var express = require('express');
var router = express.Router();

var sp = require('../../../index').ServiceProvider({
  privateKeyFile: '../key/sp/privkey.pem',
  privateKeyFilePass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
  requestSignatureAlgorithm: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
},'../metadata/metadata_sp2.xml');

var idp = require('../../../index').IdentityProvider({
  isAssertionEncrypted: true
},'../metadata/metadata_idp2.xml');

router.get('/metadata',function(req, res, next){
  res.header('Content-Type','text/xml').send(sp.getMetadata());
});

router.get('/spinitsso-post',function(req,res){
  sp.sendLoginRequest(idp,'post',function(request){
    res.render('actions',request);
  });
});

router.get('/spinitsso-redirect',function(req,res){
  sp.sendLoginRequest(idp,'redirect',function(url){
    res.redirect(url);
  });
});

router.post('/acs',function(req,res,next){
  sp.parseLoginResponse(idp,'post',req,function(parseResult){
    if(parseResult.extract.nameid){
      res.render('login',{
        title: 'Processing',
        isSSOLogin: true,
        email: parseResult.extract.nameid
      });
    } else {
      res.redirect('/login');
    }
  });
});

router.post('/slo',function(req,res){
  sp.parseLogoutRequest(idp,'post',req,function(parseResult){
    req.logout();
    sp.sendLogoutResponse(idp,parseResult,'redirect',req.body.relayState,function(url){
      res.redirect(url);
    });
  });
});

router.get('/slo',function(req,res){
  sp.parseLogoutResponse(idp,'redirect',req,function(parseResult){
    req.logout();
    sp.sendLogoutResponse(idp,parseResult,'redirect',req.body.relayState,function(url){
      res.redirect(url);
    });
  });
});

module.exports = router;
