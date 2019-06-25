/**
* @file entity-sp.ts
* @author tngan
* @desc  Declares the actions taken by service provider
*/
import Entity, {
  BindingContext,
  PostBindingContext,
  ESamlHttpRequest,
} from './entity';
import {
  IdentityProviderConstructor as IdentityProvider,
  ServiceProviderMetadata,
  ServiceProviderSettings,
} from './types';
import { namespace } from './urn';
import redirectBinding from './binding-redirect';
import postBinding from './binding-post';
import { flow, FlowResult } from './flow';

/*
 * @desc interface function
 */
export default function(props: ServiceProviderSettings) {
  return new ServiceProvider(props);
}

/**
* @desc Service provider can be configured using either metadata importing or spSetting
* @param  {object} spSettingimport { FlowResult } from '../types/src/flow.d';

*/
export class ServiceProvider extends Entity {
  entityMeta: ServiceProviderMetadata;

  /**
  * @desc  Inherited from Entity
  * @param {object} spSetting    setting of service provider
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
    customTagReplacement?: (template: string) => BindingContext,
  ): BindingContext | PostBindingContext {
    const nsBinding = namespace.binding;
    const protocol = nsBinding[binding];
    if (this.entityMeta.isAuthnRequestSigned() !== idp.entityMeta.isWantAuthnRequestsSigned()) {
      throw new Error('ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG');
    }

    if (protocol === nsBinding.redirect) {
      return redirectBinding.loginRequestRedirectURL({ idp, sp: this }, customTagReplacement);
    }

    if (protocol === nsBinding.post) {
      const context = postBinding.base64LoginRequest("/*[local-name(.)='AuthnRequest']", { idp, sp: this }, customTagReplacement);
      return {
        ...context,
        relayState: this.entitySetting.relayState,
        entityEndpoint: idp.entityMeta.getSingleSignOnService(binding) as string,
        type: 'SAMLRequest',
      };
    }
    // Will support artifact in the next release
    throw new Error('ERR_SP_LOGIN_REQUEST_UNDEFINED_BINDING');
  }

  /**
  * @desc   Validation of the parsed the URL parameters
  * @param  {IdentityProvider}   idp             object of identity provider
  * @param  {string}   binding                   protocol binding
  * @param  {request}   req                      request
  */
  public parseLoginResponse(idp, binding, request: ESamlHttpRequest) {
    const self = this;
    return flow({
      from: idp,
      self: self,
      checkSignature: true, // saml response must have signature
      parserType: 'SAMLResponse',
      type: 'login',
      binding: binding,
      request: request
    });
  }

}
