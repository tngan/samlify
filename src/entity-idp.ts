/**
 * @file entity-idp.ts
 * @author tngan
 * @desc Identity provider: builds login responses and parses inbound
 * login requests coming from a service provider.
 */
import Entity from './entity';
import type {
  BindingContext,
  ESamlHttpRequest,
  PostBindingContext,
  SimpleSignBindingContext,
  RequestInfo,
  SAMLUser,
  IdentityProviderSettings,
  ServiceProviderMetadata,
  IdentityProviderMetadata,
  ServiceProviderConstructor as ServiceProvider,
  CreateLoginResponseOptions,
  CustomTagReplacement,
} from './types';
import { normalizeCreateLoginResponseOptions } from './options';
import libsaml from './libsaml';
import { namespace } from './urn';
import postBinding from './binding-post';
import redirectBinding from './binding-redirect';
import simpleSignBinding from './binding-simplesign';
import { flow } from './flow';
import { isString } from './utility';

/**
 * Factory returning a new {@link IdentityProvider}. An IdP can be built
 * from an XML metadata document or from a programmatic settings object.
 *
 * @param props IdP settings
 */
export default function (props: IdentityProviderSettings): IdentityProvider {
  return new IdentityProvider(props);
}

/**
 * Swap the default `samlp:` / `saml:` prefixes inside an XML template
 * with caller-supplied prefixes. Both the prefix occurrences and the
 * `xmlns:` namespace bindings are rewritten so the resulting XML
 * remains well-formed and namespace-correct (saml-core §1.4 — prefix
 * choice is not normative).
 */
function applyTagPrefixes(
  xml: string,
  prefixes: { protocol?: string; assertion?: string },
): string {
  let out = xml;
  if (prefixes.protocol && prefixes.protocol !== 'samlp') {
    const p = prefixes.protocol;
    out = out
      .replace(/<samlp:/g, `<${p}:`)
      .replace(/<\/samlp:/g, `</${p}:`)
      .replace(/xmlns:samlp="/g, `xmlns:${p}="`);
  }
  if (prefixes.assertion && prefixes.assertion !== 'saml') {
    const a = prefixes.assertion;
    out = out
      .replace(/<saml:/g, `<${a}:`)
      .replace(/<\/saml:/g, `</${a}:`)
      .replace(/xmlns:saml="/g, `xmlns:${a}="`);
  }
  return out;
}

/** Identity-provider entity. */
export class IdentityProvider extends Entity {

  entityMeta!: IdentityProviderMetadata;

  /**
   * Build an IdP, expanding `loginResponseTemplate.attributes` into a
   * pre-baked AttributeStatement template when supplied.
   */
  constructor(idpSetting: IdentityProviderSettings) {
    const defaultIdpEntitySetting: Partial<IdentityProviderSettings> = {
      wantAuthnRequestsSigned: false,
      tagPrefix: {
        encryptedAssertion: 'saml',
      },
    };
    const entitySetting = Object.assign({}, defaultIdpEntitySetting, idpSetting) as IdentityProviderSettings;
    // Deep-merge tagPrefix so callers can override `protocol` / `assertion`
    // without dropping the `encryptedAssertion: 'saml'` default that
    // libsaml.encryptAssertion depends on (#388, saml-core §1.4).
    entitySetting.tagPrefix = {
      ...defaultIdpEntitySetting.tagPrefix,
      ...idpSetting.tagPrefix,
    };

    if (idpSetting.loginResponseTemplate) {
      const template = idpSetting.loginResponseTemplate as typeof idpSetting.loginResponseTemplate & {
        attributes?: Parameters<typeof libsaml.attributeStatementBuilder>[0];
      };
      if (isString(template.context) && Array.isArray(template.attributes)) {
        const additional = template.additionalTemplates;
        const attributeStatementTemplate = additional && additional.attributeStatementTemplate
          ? additional.attributeStatementTemplate
          : libsaml.defaultAttributeStatementTemplate;
        const attributeTemplate = additional && additional.attributeTemplate
          ? additional.attributeTemplate
          : libsaml.defaultAttributeTemplate;

        const replacement = {
          AttributeStatement: libsaml.attributeStatementBuilder(
            template.attributes!,
            attributeTemplate,
            attributeStatementTemplate,
          ),
        };
        entitySetting.loginResponseTemplate = {
          ...entitySetting.loginResponseTemplate,
          context: libsaml.replaceTagsByValue(entitySetting.loginResponseTemplate!.context!, replacement),
        };
      } else {
        console.warn('Invalid login response template');
      }
    }

    // saml-core §1.4 — XML namespace prefixes are not normative; only the
    // URI bindings are. When the caller overrides `tagPrefix.protocol` or
    // `tagPrefix.assertion`, rewrite both the caller's templates and the
    // built-in defaults so the bindings emit the rebound prefixes
    // downstream (closes #388). The rewritten defaults land on a separate
    // `tagPrefixedDefaults` slot so users that only set
    // `loginResponseTemplate` (without `tagPrefix`) continue to follow the
    // legacy binding fallback path.
    const tp = entitySetting.tagPrefix;
    const protocolPrefix = tp?.protocol;
    const assertionPrefix = tp?.assertion;
    const overridesProtocol = !!protocolPrefix && protocolPrefix !== 'samlp';
    const overridesAssertion = !!assertionPrefix && assertionPrefix !== 'saml';
    if (overridesProtocol || overridesAssertion) {
      const prefixes = { protocol: protocolPrefix, assertion: assertionPrefix };
      // Rewrite any caller-supplied templates in place so customTagReplacement
      // consumers see the rebound prefixes too.
      const callerLoginCtx = entitySetting.loginResponseTemplate?.context;
      if (isString(callerLoginCtx)) {
        entitySetting.loginResponseTemplate = {
          ...entitySetting.loginResponseTemplate,
          context: applyTagPrefixes(callerLoginCtx, prefixes),
        };
      }
      const callerLogoutReqCtx = entitySetting.logoutRequestTemplate?.context;
      if (isString(callerLogoutReqCtx)) {
        entitySetting.logoutRequestTemplate = {
          ...entitySetting.logoutRequestTemplate,
          context: applyTagPrefixes(callerLogoutReqCtx, prefixes),
        };
      }
      const callerLogoutRespCtx = entitySetting.logoutResponseTemplate?.context;
      if (isString(callerLogoutRespCtx)) {
        entitySetting.logoutResponseTemplate = {
          ...entitySetting.logoutResponseTemplate,
          context: applyTagPrefixes(callerLogoutRespCtx, prefixes),
        };
      }
      // Pre-rewrite copies of the default templates so the bindings emit
      // rebound prefixes when no caller template is supplied.
      entitySetting.tagPrefixedDefaults = {
        loginResponseTemplate: {
          context: applyTagPrefixes(libsaml.defaultLoginResponseTemplate.context, prefixes),
        },
        logoutRequestTemplate: {
          context: applyTagPrefixes(libsaml.defaultLogoutRequestTemplate.context, prefixes),
        },
        logoutResponseTemplate: {
          context: applyTagPrefixes(libsaml.defaultLogoutResponseTemplate.context, prefixes),
        },
      };
    }

    super(entitySetting, 'idp');
  }

  /**
   * Build a login response for delivery to the supplied service provider.
   *
   * The fifth parameter accepts either a callback (legacy positional shape)
   * or an options bag `{ relayState?, customTagReplacement?, encryptThenSign? }`.
   * When the legacy shape is used, the trailing `legacyEncryptThenSign` and
   * `legacyRelayState` positional arguments are honoured. Per
   * `saml-bindings §3.4.3 / §3.5.3`, RelayState is request-scoped — pass it
   * via the options bag instead of `entitySetting.relayState`.
   *
   * @param sp target service provider
   * @param requestInfo parsed request used to set `InResponseTo`
   * @param binding `post`, `simpleSign`, or `redirect`
   * @param user authenticated user
   * @param optionsOrCallback per-request options or legacy custom-template callback
   * @param legacyEncryptThenSign legacy positional `encryptThenSign`; ignored when options bag is used
   * @param legacyRelayState legacy positional `relayState`; ignored when options bag is used
   */
  public async createLoginResponse(
    sp: ServiceProvider,
    requestInfo: RequestInfo,
    binding: string,
    user: SAMLUser,
    optionsOrCallback?: CreateLoginResponseOptions | CustomTagReplacement,
    legacyEncryptThenSign?: boolean,
    legacyRelayState?: string,
  ): Promise<BindingContext | PostBindingContext | SimpleSignBindingContext> {
    const opts = normalizeCreateLoginResponseOptions(
      optionsOrCallback,
      legacyEncryptThenSign,
      legacyRelayState,
    );
    const customTagReplacement = opts.customTagReplacement;
    const encryptThenSign = opts.encryptThenSign;
    const relayState = opts.relayState;

    const protocol = namespace.binding[binding];
    let context: BindingContext | SimpleSignBindingContext | null = null;
    switch (protocol) {
      case namespace.binding.post:
        context = await postBinding.base64LoginResponse(requestInfo, {
          idp: this,
          sp,
        }, user, customTagReplacement, encryptThenSign);
        break;

      case namespace.binding.simpleSign:
        context = await simpleSignBinding.base64LoginResponse(requestInfo, {
          idp: this,
          sp,
        }, user, relayState, customTagReplacement) as SimpleSignBindingContext;
        break;

      case namespace.binding.redirect:
        return redirectBinding.loginResponseRedirectURL(requestInfo, {
          idp: this,
          sp,
        }, user, relayState, customTagReplacement);

      default:
        throw new Error('ERR_CREATE_RESPONSE_UNDEFINED_BINDING');
    }

    return {
      ...context,
      relayState,
      entityEndpoint: (sp.entityMeta as ServiceProviderMetadata).getAssertionConsumerService(binding) as string,
      type: 'SAMLResponse',
    };
  }

  /**
   * Parse, validate and verify an inbound login request.
   *
   * @param sp service provider that produced the request
   * @param binding `redirect`, `post`, or `simpleSign`
   * @param req HTTP request envelope
   */
  parseLoginRequest(sp: ServiceProvider, binding: string, req: ESamlHttpRequest) {
    return flow({
      from: sp,
      self: this,
      checkSignature: this.entityMeta.isWantAuthnRequestsSigned(),
      parserType: 'SAMLRequest',
      type: 'login',
      binding,
      request: req,
    });
  }
}
