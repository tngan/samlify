/**
* @file RedirectBinding.js
* @author Tony Ngan
* @desc Binding-level API, declare the functions using Redirect binding
*
* CHANGELOG keyword
* v1.1  SS-1.1
*/
var Utility = require('./Utility');
var SamlLib = require('./SamlLib');
var wording = require('./urn').wording;
var uuid = require('node-uuid');
var namespace = require('./urn').namespace;
var binding = wording.binding;
var urlParams = wording.urlParams;

var RedirectBinding = function RedirectBinding() {
  /**
  * @private
  * @desc Helper of generating URL param/value pair
  * @param  {string} param     key
  * @param  {string} value     value of key
  * @param  {boolean} first    determine whether the param is the starting one in order to add query header '?'
  * @return {string}
  */
  var pvPair = function pvPair(param, value, first) {
    return (first === true ? '?' : '&') + param + '=' + value;
  };
  /**
  * @private
  * @desc Refractored part of URL generation for login/logout request
  * @param  {string} type
  * @param  {boolean} isSigned
  * @param  {string} rawSamlRequest
  * @param  {object} entitySetting
  * @return {string}
  */
  var buildRedirectURL = function buildRedirectURL(type, isSigned, rawSamlRequest, entitySetting, relayState) {
    // In general, this xmlstring is required to do deflate -> base64 -> urlencode
    var samlRequest = encodeURIComponent(Utility.base64Encode(Utility.deflateString(rawSamlRequest)));
    var _relayState = relayState || '';

    if (_relayState !== '') {
      _relayState = pvPair(urlParams.relayState, encodeURIComponent(_relayState));
    }
    if (isSigned) {
      var sigAlg = pvPair(urlParams.sigAlg,encodeURIComponent(entitySetting.requestSignatureAlgorithm));
      var octetString = samlRequest + sigAlg + _relayState;
      // include signature algorithm (either SHA1 or SHA256) (SS1.1)
      return pvPair(type, octetString, true) + pvPair(urlParams.signature, encodeURIComponent(SamlLib.constructMessageSignature(type + '=' + octetString, entitySetting.privateKeyFile, entitySetting.privateKeyFilePass, null, entitySetting.requestSignatureAlgorithm)));
    } else {
      return pvPair(type, samlRequest + _relayState, true);
    }
  };

  return {
    /**
    * @desc Redirect URL for login request
    * @param  {object} entity                       object includes both idp and sp
    * @param  {function} rcallback      used when developers have their own login response template
    * @return {string} redirect URL
    */
    loginRequestRedirectURL: function loginRequestRedirectURL(entity, rcallback) {
      var metadata = {
        idp: entity.idp.entityMeta,
        sp: entity.sp.entityMeta
      };
      var spSetting = entity.sp.entitySetting;
      if (metadata && metadata.idp && metadata.sp) {
        var _base = metadata.idp.getSingleSignOnService(binding.redirect);
        var rawSamlRequest;
        if (spSetting.loginRequestTemplate) {
          rawSamlRequest = rcallback(spSetting.loginRequestTemplate);
        } else {
          rawSamlRequest = SamlLib.replaceTagsByValue(SamlLib.defaultLoginRequestTemplate, {
            ID: spSetting.generateID ? spSetting.generateID() : uuid.v4(),
            Destination: _base,
            Issuer: metadata.sp.getEntityID(),
            IssueInstant: new Date().toISOString(),
            NameIDFormat: namespace.format[spSetting.logoutNameIDFormat] || namespace.format.emailAddress,
            AssertionConsumerServiceURL: metadata.sp.getAssertionConsumerService(binding.redirect),
            EntityID: metadata.sp.getEntityID(),
            AllowCreate: spSetting.allowCreate
          });
        }
        return _base + buildRedirectURL(urlParams.samlRequest, metadata.sp.isAuthnRequestSigned(), rawSamlRequest, spSetting);
      } else {
        throw new Error('Missing declaration of metadata');
      }
    },
    /**
    * @desc Redirect URL for logout request
    * @param  {object} user                        current logged user (e.g. req.user)
    * @param  {object} entity                      object includes both idp and sp
    * @param  {function} rcallback     used when developers have their own login response template
    * @return {string} redirect URL
    */
    logoutRequestRedirectURL: function logoutRequestRedirectURL(user, entity, relayState, rcallback) {
      var metadata = {
        init: entity.init.entityMeta,
        target: entity.target.entityMeta
      };
      var initSetting = entity.init.entitySetting;

      if (metadata && metadata.init && metadata.target) {
        var _base = metadata.target.getSingleLogoutService(binding.redirect);
        var rawSamlRequest;

        if (initSetting.logoutRequestTemplate) {
          rawSamlRequest = rcallback(initSetting.logoutRequestTemplate);
        } else {
          rawSamlRequest = SamlLib.replaceTagsByValue(SamlLib.defaultLogoutRequestTemplate, {
            ID: initSetting.generateID ? initSetting.generateID() : uuid.v4(),
            Destination: _base,
            EntityID: metadata.init.getEntityID(),
            Issuer: metadata.init.getEntityID(),
            IssueInstant: new Date().toISOString(),
            NameIDFormat: namespace.format[initSetting.logoutNameIDFormat] || namespace.format.emailAddress,
            NameID: user.logoutNameID,
            SessionIndex: user.sessionIndex
          });
        }
        return _base + buildRedirectURL(urlParams.logoutRequest, entity.target.entitySetting.wantLogoutRequestSigned, rawSamlRequest, initSetting, relayState);
      } else {
        throw new Error('Missing declaration of metadata');
      }
    },
    /**
    * @desc Redirect URL for logout response
    * @param  {object} requestInfo                 corresponding request, used to obtain the id
    * @param  {object} entity                      object includes both idp and sp
    * @param  {function} rcallback     used when developers have their own login response template
    */
    logoutResponseRedirectURL: function logoutResponseRedirectURL(requestInfo, entity, relayState, rcallback) {
      var metadata = {
        init: entity.init.entityMeta,
        target: entity.target.entityMeta
      };
      var initSetting = entity.init.entitySetting;

      if (metadata && metadata.init && metadata.target) {
        var _base = metadata.target.getSingleLogoutService(binding.redirect);
        var rawSamlResponse;

        if (initSetting.logoutResponseTemplate) {
          rawSamlResponse = rcallback(initSetting.logoutResponseTemplate);
        } else {
          var tvalue = {
            ID: initSetting.generateID ? initSetting.generateID() : uuid.v4(),
            Destination:  _base,
            Issuer: metadata.init.getEntityID(),
            EntityID: metadata.init.getEntityID(),
            IssueInstant: new Date().toISOString(),
            StatusCode: namespace.statusCode.success
          };
          if (requestInfo && requestInfo.extract && requestInfo.extract.logoutrequest) {
            tvalue.InResponseTo = requestInfo.extract.logoutrequest.id;
          }
          rawSamlResponse = SamlLib.replaceTagsByValue(SamlLib.defaultLogoutResponseTemplate, tvalue);
        }
        return _base + buildRedirectURL(urlParams.logoutResponse, entity.target.entitySetting.wantLogoutResponseSigned, rawSamlResponse, initSetting, relayState);
      } else {
        throw new Error('Missing declaration of metadata');
      }
    }
  };
};

module.exports = RedirectBinding();
