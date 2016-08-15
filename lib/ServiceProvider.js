/**
* @file ServiceProvider.js
* @author Tony Ngan
* @desc  Declares the actions taken by service provider
*/
var RedirectBinding = require('./RedirectBinding');
var PostBinding = require('./PostBinding');
var SamlLib = require('./SamlLib');
var xml = require('xml');
var Utility = require('./Utility');
var Entity = require('./Entity');
var urn = require('./urn');
var bindDict = urn.wording.binding;
var namespace = urn.namespace;
var xmlTag = urn.tags.xmlTag;
var metaWord = urn.wording.metadata;
/**
* @desc Service provider can be configured using either metadata importing or spSetting
* @param  {object} spSetting
* @param  {string} metaFile
*/
module.exports = function(spSetting, metaFile) {
  // local variables
  // spSetting is an object with properties as follow:
  // -------------------------------------------------
  if (typeof spSetting === 'string') {
    metaFile = spSetting;
    spSetting = {};
  }

  spSetting = Utility.applyDefault({
    authnRequestsSigned: false,
    wantAssertionsSigned: false
  }, spSetting);

  function ServiceProvider() {}
  /**
  * @desc  Inherited from Entity
  * @param {object} spSetting    setting of service provider
  * @param {string} metaFile     metadata file path
  */
  ServiceProvider.prototype = new Entity(spSetting, metaWord.sp, metaFile);
  /**
  * @desc  Generates the login request and callback to developers to design their own method
  * @param  {IdentityProvider} idp               object of identity provider
  * @param  {string}   binding                   protocol binding
  * @param  {function} callback                  developers do their own request to do with passing information
  * @param  {function} rcallback     used when developers have their own login response template
  */
  ServiceProvider.prototype.sendLoginRequest = function sendLoginRequest(idp, binding, callback, rcallback) {
    var _binding = namespace.binding[binding] || namespace.binding.redirect;
    if(_binding == namespace.binding.redirect) {
      return callback(RedirectBinding.loginRequestRedirectURL({
        idp: idp,
        sp: this
      }, rcallback));
    } else if(_binding == namespace.binding.post) {
      return callback({
        actionValue: PostBinding.base64LoginRequest(SamlLib.createXPath('Issuer'), {
          idp: idp,
          sp: this
        }, rcallback),
        relayState: this.entitySetting.relayState,
        entityEndpoint: idp.entityMeta.getSingleSignOnService(binding),
        actionType: 'SAMLRequest'
      });
    } else {
      // Will support arifact in the next release
      throw new Error('The binding is not support');
    }
  };
  /**
  * @desc   Validation and callback parsed the URL parameters
  * @param  {IdentityProvider}   idp             object of identity provider
  * @param  {string}   binding                   protocol binding
  * @param  {request}   req                      request
  * @param  {function} parseCallback             developers use their own validation to do with passing information
  */
  ServiceProvider.prototype.parseLoginResponse = function parseLoginResponse(idp, binding, req, parseCallback) {
    return this.abstractBindingParser({
      parserFormat: [{
        localName: 'StatusCode',
        attributes: ['Value']
      },{
        localName: 'Conditions',
        attributes: ['NotBefore', 'NotOnOrAfter']
      }, 'Audience', 'Issuer', 'NameID', {
        localName: 'Signature',
        extractEntireBody: true
      },{
        localName: {
          tag: 'Attribute',
          key: 'Name'
        },
        valueTag: 'AttributeValue'
      }],
      checkSignature: this.entityMeta.isWantAssertionsSigned(),
      from: idp,
      supportBindings: ['post'],
      parserType: 'SAMLResponse',
      actionType: 'login'
    }, binding, req, idp.entityMeta, parseCallback);
  };
  /**
  * @desc return the prototype
  */
  return ServiceProvider.prototype;
};
