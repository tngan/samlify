var express = require('express');
var uuid = require('uuid');
var router = express.Router();
var fs = require('fs');
var utility = require('../../../build/index').Utility;
var SamlLib = require('../../../build/index').SamlLib;
var binding = require('../../../build/index').Constants.wording.binding;
var spSet = [];
var epn = {
  'admin@idp.com': {
    assoHash: '$2a$10$/0lqAmz.r6trTurxW3qMJuFHyicUWsV3GKF94KcgN42eVR8y5c25S',
    app: {
      '369550': { email: 'admin@sp1.com' },
      '369551': { email: 'admin@sp2.com' },
      '369552': { email: 'exprsaml2@gmail.com', firstname: 'Elisa', lastname: 'Sarah', login: 'Elisa' }
    }
  }
};

/// Declare that entity, and load all settings when server is started
/// Restart server is needed when new metadata is imported
var idp1 = require('../../../build/index').IdentityProvider({
  privateKey: fs.readFileSync('../key/idp/privkey.pem'),
  isAssertionEncrypted: true,
  encPrivateKey: fs.readFileSync('../key/idp/encryptKey.pem'),
  encPrivateKeyPass: 'g7hGcRmp8PxT5QeP2q9Ehf1bWe9zTALN',
  privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  metadata: fs.readFileSync('../metadata/metadata_idp1.xml')
});

var idp2 = require('../../../build/index').IdentityProvider({
  privateKey: fs.readFileSync('../key/idp/privkey.pem'),
  isAssertionEncrypted: true,
  encPrivateKey: fs.readFileSync('../key/idp/encryptKey.pem'),
  encPrivateKeyPass: 'g7hGcRmp8PxT5QeP2q9Ehf1bWe9zTALN',
  privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  metadata: fs.readFileSync('../metadata/metadata_idp2.xml')
});

var idp3 = require('../../../build/index').IdentityProvider({
  privateKey: fs.readFileSync('../key/idp/privkey.pem'),
  isAssertionEncrypted: false,
  privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  metadata: fs.readFileSync('../metadata/metadata_idp1.xml'),
  loginResponseTemplate: {
    context: '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status><saml:Assertion ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AttributeStatement}</saml:Assertion></samlp:Response>',
    attributes: [{
      name: "email",
      valueTag: "user.email",
      nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
      valueXsiType: "xs:string"
    },{
      name: "firstname",
      valueTag: "user.firstname",
      nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
      valueXsiType: "xs:string"
    },{
      name: "lastname",
      valueTag: "user.lastname",
      nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
      valueXsiType: "xs:string"
    },{
      name: "login",
      valueTag: "user.login",
      nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
      valueXsiType: "xs:string"
    }]
  }
});

/// Declare the sp
var sp1 = require('../../../build/index').ServiceProvider({ metadata: fs.readFileSync('../metadata/metadata_sp1.xml') });
var sp2 = require('../../../build/index').ServiceProvider({ metadata: fs.readFileSync('../metadata/metadata_sp2.xml') });
// Declare the okta sp for its inbound saml
var sp3 = require('../../../build/index').ServiceProvider({
  metadata: fs.readFileSync('../metadata/metadata_sp_okta.xml'),
  loginResponseTemplate: ""
});

/// metadata is publicly released, can access at /sso/metadata
router.get('/metadata/:id', function (req, res, next) {
  var entity = entityPair(req.params.id);
  var assoIdp = entity.assoIdp;
  res.header('Content-Type', 'text/xml').send(assoIdp.getMetadata());
});

spSet.push(sp1);
spSet.push(sp2);
spSet.push(sp3);

function entityPair(id) {
  var targetSP, assoIdp;
  switch (id.toString()) {
    case '369550':
      targetSP = sp1;
      assoIdp = idp1;
      break;
    case '369551':
      targetSP = sp2;
      assoIdp = idp2;
      break;
    case '369552':
      targetSP = sp3;
      assoIdp = idp3;
      break;
    default:
      break;
  }
  return {
    targetSP: targetSP,
    assoIdp: assoIdp
  };
}

router.all('/:action/:id', function (req, res, next) {
  if (!req.isAuthenticated()) {
    var url = '/login';
    if (req.params && req.params.action == 'SingleSignOnService') {
      if (req.method.toLowerCase() == 'post') {
        url = '/login/external.esaml?METHOD=post&TARGET=' + utility.base64Encode(JSON.stringify({
          entityEndpoint: req.originalUrl,
          type: 'SAMLRequest',
          context: req.body.SAMLRequest,
          relayState: req.body.relayState
        }));
      } else if (req.method.toLowerCase() == 'get') {
        url = '/login/external.esaml?METHOD=get&TARGET=' + utility.base64Encode(req.originalUrl);
      }
    } else if (req.params && req.params.action == 'SingleLogoutService') {
      if (req.method.toLowerCase() == 'post') {
        url = '/logout/external.esaml?METHOD=post&TARGET=' + utility.base64Encode(JSON.stringify({
          entityEndpoint: req.originalUrl,
          type: 'LogoutRequest',
          context: req.body.LogoutRequest,
          relayState: req.body.relayState
        }));
      } else if (req.method.toLowerCase() == 'get') {
        url = '/logout/external.esaml?METHOD=get&TARGET=' + utility.base64Encode(req.originalUrl);
      }
    } else {
      // Unexpected error
      console.warn('Unexpected error');
    }
    return res.redirect(url);
  }
  next();
});

router.get('/SingleSignOnService/:id', function (req, res) {
  var entity = entityPair(req.params.id);
  var assoIdp = entity.assoIdp;
  var targetSP = entity.targetSP;
  assoIdp.parseLoginRequest(targetSP, 'redirect', req)
  .then(parseResult => {
      req.user.email = epn[req.user.sysEmail].app[req.params.id.toString()].email;
      return assoIdp.createLoginResponse(targetSP, parseResult, 'post', req.user);
  })
  .then(response => {
    res.render('actions', response);
  })
  .catch(err => {
    console.log(err);
    res.render('error', {
      message: err.message
    });
  });
});

router.post('/SingleSignOnService/:id', function (req, res) {

  console.log('flag 1', req.body, req.params);

  var entity = entityPair(req.params.id);
  var assoIdp = entity.assoIdp;
  var targetSP = entity.targetSP;

  console.log('flag 2');

  var tagReplacement = function(template) {
    var now = new Date();
    var spEntityID = targetSP.entityMeta.getEntityID();
    var idpSetting = assoIdp.entitySetting;
    var fiveMinutesLater = new Date(now.getTime());
    fiveMinutesLater.setMinutes(fiveMinutesLater.getMinutes() + 5);
    var fiveMinutesLater = new Date(fiveMinutesLater).toISOString();
    var now = now.toISOString();
    const acl = targetSP.entityMeta.getAssertionConsumerService(binding.post);
    var id = uuid.v4();
    var tvalue = {
      ID: id,
      AssertionID: idpSetting.generateID ? idpSetting.generateID() : uuid.v4(),
      Destination: acl,
      Audience: spEntityID,
      SubjectRecipient: acl,
      NameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      NameID: req.user.email,
      Issuer: assoIdp.entityMeta.getEntityID(),
      IssueInstant: now,
      ConditionsNotBefore: now,
      ConditionsNotOnOrAfter: fiveMinutesLater,
      SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater,
      AssertionConsumerServiceURL: acl,
      EntityID: spEntityID,
      StatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
      // replace attribute
      attrUserEmail: req.user.email,
      attrUserFirstname: req.user.firstname,
      attrUserLastname: req.user.lastname,
      attrUserLogin: req.user.login
    };
    response = SamlLib.replaceTagsByValue(template, tvalue);
    console.log('***********', response);
    // replace tag
    return {
      id,
      context: response
    };
  }

  assoIdp.parseLoginRequest(targetSP, 'post', req)
  .then(parseResult => {
    console.log('flag 3', parseResult);
    const user = epn[req.user.sysEmail].app[req.params.id.toString()];
    req.user.email = user.email;
    req.user.firstname = user.firstname;
    req.user.lastname = user.lastname;
    req.user.login = user.login;
    console.log('[debug]', req.user);
    return assoIdp.createLoginResponse(targetSP, parseResult, 'post', req.user, tagReplacement);
  }).then(response => {
    res.render('actions', response);
  }).catch(err => {
    console.log(err);
    res.render('error', {
      message: err.message
    });
  });

});

router.get('/SingleLogoutService/:id', function (req, res) {
  var entity = entityPair(req.params.id);
  var assoIdp = entity.assoIdp;
  var targetSP = entity.targetSP;
  assoIdp.parseLogoutResponse(targetSP, 'redirect', req)
    .then(parseResult => {
      if (req.query.RelayState) {
        res.redirect(req.query.RelayState);
      } else {
        req.logout();
        req.flash('info', 'All participating service provider has been logged out');
        res.redirect('/login');
      }
    }).catch(err => {
      console.log(err);

      res.render('error', {
        message: err.message
      });
    });
})

router.post('/SingleLogoutService/:id', function (req, res) {
  var entity = entityPair(req.params.id);
  var assoIdp = entity.assoIdp;
  var targetSP = entity.targetSP;
  assoIdp.parseLogoutResponse(targetSP, 'post', req)
  .then(parseResult => {
    if (req.body.RelayState) {
      res.redirect(req.body.RelayState);
    } else {
      delete req.session.relayStep;
      req.logout();
      req.flash('info', 'All participating service provider has been logged out');
      res.redirect('/login');
    }
  })
  .catch(err => {
    console.log(err);

    res.render('error', {
      message: err.message
    });
  });
});

router.get('/logout/all', function (req, res) {
  var serviceList = Object.keys(epn[req.user.sysEmail].app);
  var relayState = 'http://localhost:3001/sso/logout/all';
  var relayStep = req.session.relayStep;
  if (relayStep !== undefined && relayStep + 1 !== serviceList.length) {
    req.session.relayStep = parseInt(relayStep) + 1;
  } else {
    req.session.relayStep = 0;
  }
  if (req.session.relayStep < serviceList.length) {
    if (req.session.relayStep === serviceList.length - 1) {
      relayState = '';
    }
    var id = serviceList[req.session.relayStep];
    var entity = entityPair(id);
    var assoIdp = entity.assoIdp;
    var targetSP = entity.targetSP;
    req.user.email = epn[req.user.sysEmail].app[id.toString()].email;
    const response = assoIdp.createLogoutRequest(targetSP, 'post', req.user, relayState)
    if (req.query && req.query.async && req.query.async.toString() === 'true') {
      response.ajaxSubmit = true;
    }
    return res.render('actions', response);

  } else {
    req.logout();
    req.flash('info', 'Unexpected error in /relayState');
    return res.redirect('/login');
  }
});

router.get('/select/:id', function (req, res) {
  var entity = entityPair(req.params.id);
  var assoIdp = entity.assoIdp;
  var targetSP = entity.targetSP;
  req.user.email = epn[req.user.sysEmail].app[req.params.id.toString()].email;
  assoIdp.createLoginResponse(targetSP, null, 'post', req.user)
  .then(response => {
    response.title = 'POST data';
    res.render('actions', response);
  })
  .catch(err => {
    console.log(err);
    res.render('error', {
      message: err.message
    });
  });

});

module.exports = router;
