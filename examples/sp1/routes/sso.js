var express = require('express');
var router = express.Router();
var utility = require('../../../index').Utility;

var sp = require('../../../index').ServiceProvider({
    privateKeyFile: '../key/sp/privkey.pem',
    privateKeyFilePass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
    requestSignatureAlgorithm: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
},'../metadata/metadata_sp1.xml');
/// Declare the idp
var idp = require('../../../index').IdentityProvider('../metadata/metadata_idp1.xml');

///
/// metadata is publicly released, can access at /sso/metadata
///
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
