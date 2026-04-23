/**
 * @file entity-sp.ts
 * @author tngan
 * @desc Service provider: builds login requests and parses inbound login
 * responses coming from an identity provider.
 */
import Entity from './entity';
import type {
  BindingContext,
  PostBindingContext,
  ESamlHttpRequest,
  SimpleSignBindingContext,
  IdentityProviderConstructor as IdentityProvider,
  ServiceProviderMetadata,
  ServiceProviderSettings,
} from './types';
import { namespace } from './urn';
import redirectBinding from './binding-redirect';
import postBinding from './binding-post';
import simpleSignBinding from './binding-simplesign';
import { flow } from './flow';

/**
 * Factory returning a new {@link ServiceProvider}. An SP can be built from
 * an XML metadata document or from a programmatic settings object.
 *
 * @param props SP settings
 */
export default function (props: ServiceProviderSettings): ServiceProvider {
  return new ServiceProvider(props);
}

/** Service-provider entity. */
export class ServiceProvider extends Entity {
  entityMeta!: ServiceProviderMetadata;

  /**
   * Build an SP with sensible defaults for signing flags.
   *
   * @param spSetting SP settings object
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
   * Build a login request targeting the supplied identity provider.
   *
   * @param idp target identity provider
   * @param binding `redirect` (default), `post`, or `simpleSign`
   * @param customTagReplacement optional custom template transformer
   */
  public createLoginRequest(
    idp: IdentityProvider,
    binding = 'redirect',
    customTagReplacement?: (template: string) => BindingContext,
  ): BindingContext | PostBindingContext | SimpleSignBindingContext {
    const nsBinding = namespace.binding;
    const protocol = nsBinding[binding];
    if (this.entityMeta.isAuthnRequestSigned() !== idp.entityMeta.isWantAuthnRequestsSigned()) {
      throw new Error('ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG');
    }

    let context: BindingContext | SimpleSignBindingContext | null = null;
    switch (protocol) {
      case nsBinding.redirect:
        return redirectBinding.loginRequestRedirectURL({ idp, sp: this }, customTagReplacement);

      case nsBinding.post:
        context = postBinding.base64LoginRequest(
          "/*[local-name(.)='AuthnRequest']",
          { idp, sp: this },
          customTagReplacement,
        );
        break;

      case nsBinding.simpleSign:
        context = simpleSignBinding.base64LoginRequest({ idp, sp: this }, customTagReplacement) as SimpleSignBindingContext;
        break;

      default:
        throw new Error('ERR_SP_LOGIN_REQUEST_UNDEFINED_BINDING');
    }

    return {
      ...context,
      relayState: this.entitySetting.relayState,
      entityEndpoint: idp.entityMeta.getSingleSignOnService(binding) as string,
      type: 'SAMLRequest',
    };
  }

  /**
   * Parse, validate and verify an inbound login response.
   *
   * @param idp identity provider that produced the response
   * @param binding `redirect`, `post`, or `simpleSign`
   * @param request HTTP request envelope
   */
  public parseLoginResponse(idp: IdentityProvider, binding: string, request: ESamlHttpRequest) {
    return flow({
      from: idp,
      self: this,
      // SAML response is always required to be signed.
      checkSignature: true,
      parserType: 'SAMLResponse',
      type: 'login',
      binding,
      request,
    });
  }
}
