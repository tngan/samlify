/**
* @file entity-sp.ts
* @author tngan
* @desc  Declares the actions taken by service provider
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

/**
* @desc Service provider can be configured using either metadata importing or spSetting
* @param  {object} spSetting
* @param  {string} metaFile
*/
export default class ServiceProvider extends Entity {
  /**
  * @desc  Inherited from Entity
  * @param {object} spSetting    setting of service provider
  * @param {string} metaFile     metadata file path
  */
	constructor(spSetting, metaFile) {
	  if (typeof spSetting === 'string') {
	    metaFile = spSetting;
	    spSetting = {};
	  }
	  spSetting = Object.assign({
	    authnRequestsSigned: false,
	    wantAssertionsSigned: false
	  }, spSetting);

		super(spSetting, metaFile.sp, metaFile);
	}
  /**
  * @desc  Generates the login request and callback to developers to design their own method
  * @param  {IdentityProvider} idp               object of identity provider
  * @param  {string}   binding                   protocol binding
  * @param  {function} callback                  developers do their own request to do with passing information
  * @param  {function} rcallback     used when developers have their own login response template
  */
  public sendLoginRequest (idp, binding, callback, rcallback) {
    const protocol = namespace.binding[binding] || namespace.binding.redirect;
    if (protocol == namespace.binding.redirect) {
      return callback(redirectBinding.loginRequestRedirectURL({
        idp: idp,
        sp: this
      }, rcallback));
    } else if (protocol == namespace.binding.post) {
      return callback({
        actionValue: postBinding.base64LoginRequest(libsaml.createXPath('Issuer'), {
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
  }
  /**
  * @desc   Validation and callback parsed the URL parameters
  * @param  {IdentityProvider}   idp             object of identity provider
  * @param  {string}   binding                   protocol binding
  * @param  {request}   req                      request
  * @param  {function} parseCallback             developers use their own validation to do with passing information
  */
  public parseLoginResponse (idp, binding, req, parseCallback) {
    return super.abstractBindingParser({
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

}
