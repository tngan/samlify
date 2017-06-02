/**
* @file entity-sp.ts
* @author tngan
* @desc  Declares the actions taken by service provider
*/
import Entity, { BindingContext, PostRequestInfo } from './entity';
import libsaml from './libsaml';
import utility from './utility';
import { wording, namespace, tags } from './urn';
import redirectBinding from './binding-redirect';
import postBinding from './binding-post';

const bindDict = wording.binding;
const xmlTag = tags.xmlTag;
const metaWord = wording.metadata;
const xml = require('xml');

/*
 * @desc interface function
 */
export default function (props) {
  return new ServiceProvider(props);
}
/**
* @desc Service provider can be configured using either metadata importing or spSetting
* @param  {object} spSetting
* @param  {string} meta
*/
export class ServiceProvider extends Entity {
  /**
  * @desc  Inherited from Entity
  * @param {object} spSetting    setting of service provider
  * @param {string} meta		     metadata
  */
  constructor(spSetting) {
    const entitySetting = Object.assign({
      authnRequestsSigned: false,
      wantAssertionsSigned: false,
      wantMessageSigned: false
    }, spSetting);
    super(entitySetting, 'sp');
  }
  /**
  * @desc  Generates the login request for developers to design their own method
  * @param  {IdentityProvider} idp               object of identity provider
  * @param  {string}   binding                   protocol binding
  * @param  {function} customTagReplacement     used when developers have their own login response template
  */
  public createLoginRequest(idp, binding = 'redirect', customTagReplacement): BindingContext | PostRequestInfo {
    const nsBinding = namespace.binding;
    const protocol = nsBinding[binding];
    if (protocol === nsBinding.redirect) {
      return redirectBinding.loginRequestRedirectURL({ idp, sp: this }, customTagReplacement);
    } else if (protocol === nsBinding.post) {
      const context = postBinding.base64LoginRequest(libsaml.createXPath('Issuer'), { idp, sp: this }, customTagReplacement);
      return {
        ...context,
        relayState: this.entitySetting.relayState,
        entityEndpoint: idp.entityMeta.getSingleSignOnService(binding),
        type: 'SAMLRequest'
      };
    } 
    // Will support artifact in the next release
    throw new Error('The binding is not support');
  }
  /**
  * @desc   Validation of the parsed the URL parameters
  * @param  {IdentityProvider}   idp             object of identity provider
  * @param  {string}   binding                   protocol binding
  * @param  {request}   req                      request
  */
  public parseLoginResponse(idp, binding, req) {
    return this.abstractBindingParser({
      parserFormat: [{
        localName: 'StatusCode',
        attributes: ['Value']
      }, {
        localName: 'Conditions',
        attributes: ['NotBefore', 'NotOnOrAfter']
      }, 'Audience', 'Issuer', 'NameID', {
        localName: 'Signature',
        extractEntireBody: true
      }, {
        localName: {
          tag: 'Attribute',
          key: 'Name'
        },
        valueTag: 'AttributeValue'
      }],
      from: idp,
      checkSiganture: true, // saml response must have signature
      supportBindings: ['post'],
      parserType: 'SAMLResponse',
      type: 'login'
    }, binding, req, idp.entityMeta);
  };

}
