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
import { assign } from 'lodash';

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
    const entitySetting = assign({
      authnRequestsSigned: false,
      wantAssertionsSigned: false
    }, spSetting);
    super(entitySetting, 'sp');
  }
  /**
  * @desc  Generates the login request for developers to design their own method
  * @param  {IdentityProvider} idp               object of identity provider
  * @param  {string}   binding                   protocol binding
  * @param  {function} customTagReplacement     used when developers have their own login response template
  */
  public createLoginRequest(idp, binding, customTagReplacement): any {
    const protocol = namespace.binding[binding] || namespace.binding.redirect;
    if (protocol == namespace.binding.redirect) {
      return redirectBinding.loginRequestRedirectURL({
        idp: idp,
        sp: this
      }, customTagReplacement);
    } else if (protocol == namespace.binding.post) {
      return {
        actionValue: postBinding.base64LoginRequest(libsaml.createXPath('Issuer'), {
          idp: idp,
          sp: this
        }, customTagReplacement),
        relayState: this.entitySetting.relayState,
        entityEndpoint: idp.entityMeta.getSingleSignOnService(binding),
        actionType: 'SAMLRequest'
      };
    } else {
      // Will support artifact in the next release
      throw new Error('The binding is not support');
    }
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
      checkSignature: this.entityMeta.isWantAssertionsSigned(),
      from: idp,
      supportBindings: ['post'],
      parserType: 'SAMLResponse',
      actionType: 'login'
    }, binding, req, idp.entityMeta);
  };

}
