/**
* @file PostBinding.js
* @author Tony Ngan
* @desc Binding-level API, declare the functions using POST binding
*
* CHANGELOG keyword
* v1.1  SS-1.1
*/
var wording = require('./urn').wording;
var xmlTag = require('./urn').tags.xmlTag;
var namespace = require('./urn').namespace;
var uuid = require('node-uuid');
var SamlLib = require('./SamlLib');
var Utility = require('./Utility');
var binding = wording.binding;

var PostBinding = function PostBinding() {
  return {
    /**
    * @desc Generate a base64 encoded login request
    * @param  {string} referenceTagXPath           reference uri
    * @param  {object} entity                      object includes both idp and sp
    * @param  {function} rcallback     used when developers have their own login response template
    */
    base64LoginRequest: function base64LoginRequest(referenceTagXPath, entity, rcallback) {
      var metadata = {
        idp: entity.idp.entityMeta,
        sp: entity.sp.entityMeta
      };
      var spSetting = entity.sp.entitySetting;

      if(metadata && metadata.idp && metadata.sp) {
        var _base = metadata.idp.getSingleSignOnService(binding.post);
        var rawSamlRequest;

        if(metadata.sp.isAuthnRequestSigned() !== metadata.idp.isWantAuthnRequestsSigned()) {
          throw new Error('Conflict of metadata - sp isAuthnRequestSigned is not equal to idp isWantAuthnRequestsSigned');
        }

        if(spSetting.loginRequestTemplate) {
          rawSamlRequest = rcallback(spSetting.loginRequestTemplate);
        } else {
          rawSamlRequest = SamlLib.replaceTagsByValue(SamlLib.defaultLoginRequestTemplate, {
            ID: spSetting.generateID ? spSetting.generateID() : uuid.v4(),
            Destination: _base,
            Issuer: metadata.sp.getEntityID(),
            IssueInstant: new Date().toISOString(),
            AssertionConsumerServiceURL: metadata.sp.getAssertionConsumerService(binding.post),
            EntityID: metadata.sp.getEntityID(),
            AllowCreate: spSetting.allowCreate,
            NameIDFormat: namespace.format[spSetting.logoutNameIDFormat] || namespace.format.emailAddress,
          });
        }
        if(metadata.idp.isWantAuthnRequestsSigned()) {
          return SamlLib.constructSAMLSignature(rawSamlRequest, referenceTagXPath, metadata.sp.getX509Certificate('signing'), spSetting.privateKeyFile, spSetting.privateKeyFilePass, spSetting.requestSignatureAlgorithm); // SS1.1 add signature algorithm
          // No need to embeded XML signature
        } else {
          // No need to embeded XML signature
          return Utility.base64Encode(rawSamlRequest);
        }
      } else {
        throw new Error('Missing declaration of metadata');
      }
    },
    /**
    * @desc Generate a base64 encoded login response
    * @param  {object} requestInfo                 corresponding request, used to obtain the id
    * @param  {string} referenceTagXPath           reference uri
    * @param  {object} entity                      object includes both idp and sp
    * @param  {object} user                        current logged user (e.g. req.user)
    * @param  {function} rcallback     used when developers have their own login response template
    */
    base64LoginResponse: function base64LoginResponse(requestInfo, referenceTagXPath, entity, user, rcallback, rtnCallback) {
      var metadata = {
        idp: entity.idp.entityMeta,
        sp: entity.sp.entityMeta
      };
      var idpSetting = entity.idp.entitySetting;
      var resXml = undefined;
      if(metadata && metadata.idp && metadata.sp) {
        var _base = metadata.sp.getAssertionConsumerService(binding.post);
        var template;
        var _user = user || {};
        var rawSamlResponse;
        if(idpSetting.loginResponseTemplate) {
          rawSamlResponse = rcallback(idpSetting.loginResponseTemplate);
        } else {
          var now = new Date();
          var spEntityID = metadata.sp.getEntityID();
          var fiveMinutesLater = new Date(now.getTime());
          fiveMinutesLater.setMinutes(fiveMinutesLater.getMinutes() + 5);
          var fiveMinutesLater = new Date(fiveMinutesLater).toISOString();
          var now = now.toISOString();
          var tvalue = {
            ID: idpSetting.generateID ? idpSetting.generateID() : uuid.v4(),
            AssertionID: idpSetting.generateID ? idpSetting.generateID() : uuid.v4(),
            Destination: _base,
            Audience: spEntityID,
            SubjectRecipient: spEntityID,
            NameIDFormat: namespace.format[idpSetting.logoutNameIDFormat] || namespace.format.emailAddress,
            NameID: _user.email || '',
            Issuer: metadata.idp.getEntityID(),
            IssueInstant: now,
            ConditionsNotBefore: now,
            ConditionsNotOnOrAfter: fiveMinutesLater,
            SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater,
            AssertionConsumerServiceURL: metadata.sp.getAssertionConsumerService(binding.post),
            EntityID: spEntityID,
            StatusCode: namespace.statusCode.success,
            // future features
            AuthnStatement: '',
            AttributeStatement: ''
          };
          if(requestInfo !== null) {
            tvalue.InResponseTo = requestInfo.extract.authnrequest.id;
          }
          rawSamlResponse = SamlLib.replaceTagsByValue(SamlLib.defaultLoginResponseTemplate, tvalue);
        }
        resXml = metadata.sp.isWantAssertionsSigned() ? SamlLib.constructSAMLSignature(rawSamlResponse, referenceTagXPath, metadata.idp.getX509Certificate('signing'), idpSetting.privateKeyFile, idpSetting.privateKeyFilePass, idpSetting.requestSignatureAlgorithm, false) : rawSamlResponse; // SS1.1 add signature algorithm
        // SS-1.1
        idpSetting.isAssertionEncrypted ? SamlLib.encryptAssertion(entity.idp, entity.sp, resXml, rtnCallback) : rtnCallback(resXml);
      } else {
        throw new Error('Missing declaration of metadata');
      }
    },
    /**
    * @desc Generate a base64 encoded logout request
    * @param  {object} user                         current logged user (e.g. req.user)
    * @param  {string} referenceTagXPath            reference uri
    * @param  {object} entity                       object includes both idp and sp
    * @param  {function} rcallback      used when developers have their own login response template
    * @return {string} base64 encoded request
    */
    base64LogoutRequest: function base64LogoutRequest(user, referenceTagXPath, entity, relayState, rcallback) {
      var metadata = {
        init: entity.init.entityMeta,
        target: entity.target.entityMeta
      };
      var initSetting = entity.init.entitySetting;
      if(metadata && metadata.init && metadata.target) {
        var rawSamlRequest;
        if(initSetting.loginRequestTemplate) {
          rawSamlRequest = rcallback(initSetting.loginRequestTemplate);
        } else {
          var tvalue = {
            ID: initSetting.generateID ? initSetting.generateID() : uuid.v4(),
            Destination: metadata.target.getSingleLogoutService(binding.redirect),
            Issuer: metadata.init.getEntityID(),
            IssueInstant: new Date().toISOString(),
            EntityID: metadata.init.getEntityID(),
            NameIDFormat: namespace.format[initSetting.logoutNameIDFormat] || namespace.format.transient,
            NameID: user.logoutNameID
          };
          var rawSamlRequest = SamlLib.replaceTagsByValue(SamlLib.defaultLogoutRequestTemplate, tvalue);
        }
        if(entity.target.entitySetting.wantLogoutRequestSigned) {
          // Need to embeded XML signature
          return SamlLib.constructSAMLSignature(rawSamlRequest, referenceTagXPath, metadata.sp.getX509Certificate('signing'), initSetting.privateKeyFile, initSetting.privateKeyFilePass, initSetting.requestSignatureAlgorithm); // SS1.1 add signature algorithm
        } else {
          // No need to embeded XML signature
          return Utility.base64Encode(rawSamlRequest);
        }
      } else {
        throw new Error('Missing declaration of metadata');
      }
    },
    /**
    * @desc Generate a base64 encoded logout response
    * @param  {object} requestInfo                 corresponding request, used to obtain the id
    * @param  {string} referenceTagXPath           reference uri
    * @param  {object} entity                      object includes both idp and sp
    * @param  {function} rcallback     used when developers have their own login response template
    */
    base64LogoutResponse: function base64LogoutResponse(requestInfo, referenceTagXPath, entity, rcallback) {
      var metadata = {
        init: entity.init.entityMeta,
        target: entity.target.entityMeta
      };
      var initSetting = entity.init.entitySetting;
      if(metadata && metadata.init && metadata.target) {
        var rawSamlResponse;
        if(initSetting.logoutResponseTemplate) {
          rawSamlResponse = rcallback(initSetting.logoutResponseTemplate);
        } else {
          var tvalue = {
            ID: initSetting.generateID ? initSetting.generateID() : uuid.v4(),
            Destination:  metadata.target.getAssertionConsumerService(binding.post),
            EntityID: metadata.init.getEntityID(),
            Issuer: metadata.init.getEntityID(),
            IssueInstant: new Date().toISOString(),
            StatusCode: namespace.statusCode.success
          };
          if(requestInfo && requestInfo.extract && requestInfo.extract.logoutrequest) {
            tvalue.InResponseTo = requestInfo.extract.logoutrequest.id;
          }
          rawSamlResponse = SamlLib.replaceTagsByValue(SamlLib.defaultLogoutResponseTemplate, tvalue);
          if(entity.target.entitySetting.wantLogoutResponseSigned) {
            // Need to embeded XML signature
            return SamlLib.constructSAMLSignature(rawSamlResponse, referenceTagXPath, metadata.idp.getX509Certificate('signing'), initSetting.privateKeyFile, initSetting.privateKeyFilePass, initSetting.requestSignatureAlgorithm); // SS1.1 add signature algorithm
          } else {
            // No need to embeded XML signature
            return Utility.base64Encode(rawSamlResponse);
          }
        }
      } else {
        throw new Error('Missing declaration of metadata');
      }
    },
  };
};

module.exports = PostBinding();
