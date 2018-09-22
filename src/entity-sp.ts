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
import { namespace } from './urn';
import redirectBinding from './binding-redirect';
import postBinding from './binding-post';

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
      extractorFields: [
        {
          key: 'statusCode',
          localPath: ['Response', 'Status', 'StatusCode'],
          attributes: ['Value'],
          // if attributes only has 1, append string
          // xpath: "string(/*[local-name(.)='Response']/*[local-name(.)='Status']/*[local-name(.)='StatusCode']/@Value)"
        },
        {
          key: 'conditions',
          localPath: ['Response', 'Assertion', 'Conditions'],
          attributes: ['NotBefore', 'NotOnOrAfter'],
          // if attributes only has more than 1, no need to append string
          // xpath: "/*[local-name(.)='Response']/*[local-name(.)='Assertion']/*[local-name(.)='Conditions']/@*[name()='NotBefore' or name()='NotOnOrAfter']",
        },
        {
          key: 'response',
          localPath: ['Response'],
          attributes: ['ID', 'IssueInstant', 'Destination', 'InResponseTo'],
          // xpath: "/*[local-name(.)='Response']/@*[name()='ID' or name()='IssueInstant' or name()='Destination' or name()='InResponseTo']"
        },
        {
          key: 'audience',
          localPath: ['Response', 'Assertion', 'Conditions', 'AudienceRestriction', 'Audience'],
          attributes: [],
          // if attributes has nothing, get the text
          // xpath: "string(/*[local-name(.)='Response']/*[local-name(.)='Assertion']/*[local-name(.)='Conditions']/*[local-name(.)='AudienceRestriction']/*[local-name(.)='Audience']/text())",
        },
        {
          key: 'issuer',
          localPath: [
            ['Response', 'Issuer'],
            ['Response', 'Assertion', 'Issuer']
          ],
          attributes: []
          // if attributes has nothing and localPath is multiple arrays, get the node value
          // xpath: "/*[local-name(.)='Response']/*[local-name(.)='Issuer']/text() | /*[local-name(.)='Response']/*[local-name(.)='Assertion']/*[local-name(.)='Issuer']/text()"
        },
        {
          key: 'nameID',
          localPath: ['Response', 'Assertion', 'Subject', 'NameID'],
          attributes: []
          // if attributes has nothing, get the text
          // xpath: "string(/*[local-name(.)='Response']/*[local-name(.)='Assertion']/*[local-name(.)='Subject']/*[local-name(.)='NameID']/text())" 
        },
        {
          key: 'sessionIndex',
          localPath: ['Response', 'Assertion', 'AuthnStatement'],
          attributes: ['AuthnInstant', 'SessionNotOnOrAfter', 'SessionIndex'],
          // xpath: "/*[local-name(.)='Response']/*[local-name(.)='Assertion']/*[local-name(.)='AuthnStatement']/@*[name()='AuthnInstant' or name()='SessionNotOnOrAfter' or name()='SessionIndex']"  
        },
        {
          key: 'attributes',
          localPath: ['Response', 'Assertion', 'AttributeStatement', 'Attribute'],
          index: ['Name'],
          attributePath: ['AttributeValue'],
          attributes: []
          // find the index in localpath
          // find the attributes/text in attributePath which appends after the localPath
          // output: { name: '', value: '' }
        }
      ],
      from: idp,
      checkSignature: true, // saml response must have signature
      supportBindings: ['post'],
      parserType: 'SAMLResponse',
      type: 'login',
      binding: binding,
      request: req
    });
  }

}
