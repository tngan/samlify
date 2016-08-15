/**
* @file IdentityProvider.js
* @author Tony Ngan
* @desc  Declares the actions taken by identity provider
*/
var urn = require('./urn');
var namespace = urn.namespace;
var RedirectBinding = require('./RedirectBinding');
var PostBinding = require('./PostBinding');
var Utility = require('./Utility');
var SamlLib = require('./SamlLib');
var metaWord = urn.wording.metadata;
var Entity = require('./Entity');

/**
* @desc  Identity prvider can be configured using either metadata importing or idpSetting
* @param  {object} idpSetting
* @param  {string} metaFile
*/
module.exports = function(idpSetting, metaFile) {
  // local variables
  // idpSetting is an object with properties as follow:
  // -------------------------------------------------
  // {string}       requestSignatureAlgorithm     signature algorithm
  // {string}       loginResponseTemplate         template of login response
  // {string}       logoutRequestTemplate         template of logout request
  // {function}     generateID is the customized function used for generating request ID
  //
  // if no metadata is provided, idpSetting includes
  // {string}       entityID
  // {string}       privateKeyFile
  // {string}       privateKeyFilePass
  // {string}       signingCertFile
  // {string}       encryptCertFile (todo)
  // {[string]}     nameIDFormat
  // {[object]}     singleSignOnService
  // {[object]}     singleLogoutService
  // {boolean}      wantLogoutRequestSigned
  // {boolean}      wantAuthnRequestsSigned
  // {boolean}      wantLogoutResponseSigned
  //
  if (typeof idpSetting === 'string') {
    metaFile = idpSetting;
    idpSetting = {};
  }

  idpSetting = Utility.applyDefault({
    wantAuthnRequestsSigned: false
  }, idpSetting);
  //
  // optional if single logout service is not provided
  // {string} logoutNameIDFormat
  //
  function IdentityProvider() {}
  /**
  * @desc  Inherited from Entity
  * @param {object} entitySetting   setting of identity provider
  * @param {string} metaFile     metadata file path
  */
  IdentityProvider.prototype = new Entity(idpSetting, metaWord.idp, metaFile);
  /**
  * @desc  Generates the login response and callback to developers to design their own method
  * @param  {ServiceProvider}   sp               object of service provider
  * @param  {object}   requestInfo               corresponding request, used to obtain the id
  * @param  {string}   binding                   protocol binding
  * @param  {object}   user                      current logged user (e.g. req.user)
  * @param  {function} callback                  developers use their own form submit to do with passing information
  * @param  {function} rcallback                 used when developers have their own login response template
  */
  IdentityProvider.prototype.sendLoginResponse = function sendLoginResponse(sp, requestInfo, binding, user, callback, rcallback) {
    var _binding = namespace.binding[binding] || namespace.binding.redirect;
    if(_binding == namespace.binding.post) {
      PostBinding.base64LoginResponse(requestInfo, SamlLib.createXPath('Assertion'), {
        idp: this,
        sp: sp
      }, user, rcallback, function(res) {
        // xmlenc is using async process
        return callback({
          actionValue: res,
          entityEndpoint: sp.entityMeta.getAssertionConsumerService(binding),
          actionType: 'SAMLResponse'
        });
      });
    } else {
      // Will support arifact in the next release
      throw new Error('This binding is not support');
    }
  };
  /**
  * @desc   Validation and callback parsed the URL parameters
  * @param  {ServiceProvider}   sp               object of service provider
  * @param  {string}   binding                   protocol binding
  * @param  {request}   req                      request
  * @param  {function} callback                  developers use their own validation to do with passing information
  */
  IdentityProvider.prototype.parseLoginRequest = function parseLoginRequest(sp, binding, req, callback) {
    return this.abstractBindingParser({
      parserFormat: ['AuthnContextClassRef', 'Issuer', {
        localName: 'Signature',
        extractEntireBody: true
      },{
        localName: 'AuthnRequest',
        attributes: ['ID']
      },{
        localName: 'NameIDPolicy',
        attributes: ['Format', 'AllowCreate']
      }],
      checkSignature: this.entityMeta.isWantAuthnRequestsSigned(),
      parserType: 'SAMLRequest',
      actionType: 'login'
    }, binding, req, sp.entityMeta, callback);
  };
  /**
  * @desc return the prototype
  */
  return IdentityProvider.prototype;
};
