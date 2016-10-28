/**
* @file entity-idp.ts
* @author tngan
* @desc  Declares the actions taken by identity provider
*/
import Entity from './entity';
import libsaml from './libsaml';
import utility from './utility';
import { wording, namespace, tags } from './urn';
import redirectBinding from './binding-redirect';
import postBinding from './binding-post';

const bindDict = wording.binding;
const xmlTag = tags.xmlTag;
const metaWord = wording.metadata;
const xml = require('xml');

export default class IdentityProvider extends Entity {
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
	/**
	* @desc  Identity prvider can be configured using either metadata importing or idpSetting
	* @param  {object} idpSetting
	* @param  {string} metaFile
	*/
	constructor (idpSetting) {
	  const entitySetting = Object.assign({
			wantAuthnRequestsSigned: false 
		}, idpSetting);
		super(entitySetting, metaWord.idp);
	}

  /**
  * @desc  Generates the login response and callback to developers to design their own method
  * @param  {ServiceProvider}   sp               object of service provider
  * @param  {object}   requestInfo               corresponding request, used to obtain the id
  * @param  {string}   binding                   protocol binding
  * @param  {object}   user                      current logged user (e.g. req.user)
  * @param  {function} callback                  developers use their own form submit to do with passing information
  * @param  {function} rcallback                 used when developers have their own login response template
  */
  public sendLoginResponse (sp, requestInfo, binding, user, callback, rcallback) {
    const protocol = namespace.binding[binding] || namespace.binding.redirect;
    if (protocol == namespace.binding.post) {
      postBinding.base64LoginResponse(requestInfo, libsaml.createXPath('Assertion'), {
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
  }
  /**
  * @desc   Validation and callback parsed the URL parameters
  * @param  {ServiceProvider}   sp               object of service provider
  * @param  {string}   binding                   protocol binding
  * @param  {request}   req                      request
  * @param  {function} callback                  developers use their own validation to do with passing information
  */
  public parseLoginRequest (sp, binding, req, callback) {
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
}
