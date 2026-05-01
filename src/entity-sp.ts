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
  CreateLoginRequestOptions,
  CustomTagReplacement,
} from './types';
import { normalizeCreateLoginRequestOptions } from './options';
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
    if (entitySetting.wantMessageSigned && entitySetting.signatureConfig === undefined) {
      // saml-bindings §3.5 — default signature placement when the SP wants
      // a signed message but didn't declare where. Matches the fallback the
      // binding builders already use at sign time, so downstream consumers
      // (e.g. `getEntitySetting().signatureConfig`) see a populated value
      // for already-working configurations instead of `undefined`.
      entitySetting.signatureConfig = {
        prefix: 'ds',
        location: {
          reference: "/*[local-name(.)='Response']/*[local-name(.)='Issuer']",
          action: 'after',
        },
      };
    }
    super(entitySetting, 'sp');
  }

  /**
   * Build a login request targeting the supplied identity provider.
   *
   * The third parameter accepts either a callback (legacy shape) or an
   * options bag `{ relayState?, customTagReplacement? }`. Per
   * `saml-bindings §3.4.3 / §3.5.3`, RelayState is request-scoped — pass
   * it via the options bag instead of `entitySetting.relayState`.
   *
   * @param idp target identity provider
   * @param binding `redirect` (default), `post`, or `simpleSign`
   * @param optionsOrCallback per-request options or a custom-template callback
   */
  public createLoginRequest(
    idp: IdentityProvider,
    binding?: string,
    optionsOrCallback?: CreateLoginRequestOptions | CustomTagReplacement,
  ): BindingContext | PostBindingContext | SimpleSignBindingContext {
    const opts = normalizeCreateLoginRequestOptions(optionsOrCallback);
    const customTagReplacement = opts.customTagReplacement;
    const requestRelayState = opts.relayState ?? this.entitySetting.relayState;
    // saml-core §3.4.1 — `ForceAuthn` is a per-request boolean flag; when
    // true the IdP MUST re-authenticate the user instead of relying on a
    // previous security context (saml-profiles §4.1.4.1).
    const forceAuthn = opts.forceAuthn;
    const selectedBinding = binding ?? 'redirect';

    const nsBinding = namespace.binding;
    const protocol = nsBinding[selectedBinding];
    // saml-core §3.4.1 / saml-metadata §2.4.4: the SP's `AuthnRequestsSigned`
    // attribute and the IdP's `WantAuthnRequestsSigned` attribute must agree;
    // surface both observed values so the operator can tell which side is
    // misconfigured. The error code stays first so prefix-based handlers
    // (per saml-conformance §3) keep working.
    const spSigned = this.entityMeta.isAuthnRequestSigned();
    const idpWants = idp.entityMeta.isWantAuthnRequestsSigned();
    if (spSigned !== idpWants) {
      throw new Error(
        `ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG: SP AuthnRequestsSigned=${spSigned} but IdP WantAuthnRequestsSigned=${idpWants}`,
      );
    }

    let context: BindingContext | SimpleSignBindingContext | null = null;
    switch (protocol) {
      case nsBinding.redirect:
        return redirectBinding.loginRequestRedirectURL(
          { idp, sp: this },
          customTagReplacement,
          requestRelayState,
          forceAuthn,
        );

      case nsBinding.post:
        context = postBinding.base64LoginRequest(
          "/*[local-name(.)='AuthnRequest']",
          { idp, sp: this },
          customTagReplacement,
          forceAuthn,
        );
        break;

      case nsBinding.simpleSign:
        context = simpleSignBinding.base64LoginRequest(
          { idp, sp: this },
          customTagReplacement,
          requestRelayState,
          forceAuthn,
        ) as SimpleSignBindingContext;
        break;

      default:
        throw new Error('ERR_SP_LOGIN_REQUEST_UNDEFINED_BINDING');
    }

    return {
      ...context,
      relayState: requestRelayState,
      entityEndpoint: idp.entityMeta.getSingleSignOnService(selectedBinding) as string,
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
