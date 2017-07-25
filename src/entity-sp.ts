/**
* @file entity-sp.ts
* @author tngan
* @desc  Declares the actions taken by service provider
*/
import Entity, { BindingContext, PostBindingContext, ESamlHttpRequest, ParseResult } from './entity';
import {
  IdentityProviderConstructor as IdentityProvider,
  ServiceProviderMetadata,
  ServiceProviderSettings,
} from './types';
import libsaml from './libsaml';
import utility from './utility';
import { wording, namespace, tags } from './urn';
import redirectBinding from './binding-redirect';
import postBinding from './binding-post';
import * as xml from 'xml';

const bindDict = wording.binding;
const xmlTag = tags.xmlTag;
const metaWord = wording.metadata;

/*
 * @desc interface function
 */
export default function(props: ServiceProviderSettings) {
  return new ServiceProvider(props);
}

/**
* @desc Service provider can be configured using either metadata importing or spSetting
* @param  {object} spSetting
* @param  {string} meta
*/
export class ServiceProvider extends Entity {
  entityMeta: ServiceProviderMetadata;

  /**
  * @desc  Inherited from Entity
  * @param {object} spSetting    setting of service provider
  * @param {string} meta		     metadata
  */
  constructor(spSetting: ServiceProviderSettings) {
    const entitySetting = Object.assign({
      authnRequestsSigned: false,
      wantAssertionsSigned: false,
      wantMessageSigned: false,
    }, spSetting);
    super(entitySetting, 'sp');
  }

  /**
  * @desc  Generates the login request for developers to design their own method
  * @param  {IdentityProvider} idp               object of identity provider
  * @param  {string}   binding                   protocol binding
  * @param  {function} customTagReplacement     used when developers have their own login response template
  */
  public createLoginRequest(
    idp: IdentityProvider,
    binding = 'redirect',
    customTagReplacement?: (...args: any[]) => any,
  ): BindingContext | PostBindingContext {
    const nsBinding = namespace.binding;
    const protocol = nsBinding[binding];
    if (this.entityMeta.isAuthnRequestSigned() !== idp.entityMeta.isWantAuthnRequestsSigned()) {
      throw new Error('metadata conflict - sp isAuthnRequestSigned is not equal to idp isWantAuthnRequestsSigned');
    }

    if (protocol === nsBinding.redirect) {
      return redirectBinding.loginRequestRedirectURL({ idp, sp: this }, customTagReplacement);
    }

    if (protocol === nsBinding.post) {
      const context = postBinding.base64LoginRequest(libsaml.createXPath('Issuer'), { idp, sp: this }, customTagReplacement);
      return {
        ...context,
        relayState: this.entitySetting.relayState,
        entityEndpoint: idp.entityMeta.getSingleSignOnService(binding),
        type: 'SAMLRequest',
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
  public parseLoginResponse(idp, binding, req: ESamlHttpRequest) {
    return this.genericParser({
      parserFormat: [{
        localName: 'StatusCode',
        attributes: ['Value'],
      }, {
        localName: 'Conditions',
        attributes: ['NotBefore', 'NotOnOrAfter'],
      }, 'Audience', 'Issuer', 'NameID', {
        localName: 'Signature',
        extractEntireBody: true,
      }, {
        localName: {
          tag: 'Attribute',
          key: 'Name',
        },
        valueTag: 'AttributeValue',
      }],
      from: idp,
      checkSignature: true, // saml response must have signature
      supportBindings: ['post'],
      parserType: 'SAMLResponse',
      type: 'login',
    }, binding, req);
  }

}
