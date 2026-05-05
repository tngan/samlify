import { LoginResponseTemplate } from './libsaml';

export { IdentityProvider as IdentityProviderConstructor } from './entity-idp';
export { IdpMetadata as IdentityProviderMetadata } from './metadata-idp';

export { ServiceProvider as ServiceProviderConstructor } from './entity-sp';
export { SpMetadata as ServiceProviderMetadata } from './metadata-sp';

/** Raw metadata payload: either the XML contents or a path. */
export type MetadataFile = string | Buffer;

/** SAML SSO service endpoint descriptor. */
export interface SSOService {
  isDefault?: boolean;
  Binding: string;
  Location: string;
}

/** Primitive value types that appear inside XML attributes. */
export type XmlAttributeValue = string | number | boolean | undefined;

/** Attribute bag accepted by the `xml` module (element `_attr` slot). */
export type XmlAttributeMap = Record<string, XmlAttributeValue>;

/** An `{ _attr: {...} }` node accepted by the `xml` module. */
export interface XmlAttrNode {
  _attr: XmlAttributeMap;
}

/** Recursive node shape accepted by the `xml` module. */
export type XmlNode =
  | string
  | number
  | boolean
  | XmlAttrNode
  | { [tagName: string]: unknown }
  | XmlNode[];

/** Element array for the `xml` module builder. */
export type XmlElementArray = XmlNode[];

/**
 * Replacement map for template-tag interpolation.
 * Values are stringified by the replacement routine.
 */
export type TagReplacementMap = Record<string, string | number | boolean | null | undefined>;

/** Per-scalar value produced by the SAML XPath extractor. */
export type ExtractorValue =
  | string
  | string[]
  | number
  | boolean
  | null
  | Record<string, string | string[]>;

/**
 * Result object produced by `extract`. Keys depend on the fields requested;
 * the documented members below cover the common SAML flows.
 */
export interface ExtractorResult {
  [key: string]: ExtractorValue | undefined;
  signature?: string | string[];
  issuer?: string | string[];
  nameID?: string;
  conditions?: Record<string, string | string[]>;
  sessionIndex?: Record<string, string | string[]>;
  attributes?: Record<string, string | string[]>;
  response?: Record<string, string | string[]>;
  request?: Record<string, string | string[]>;
  audience?: string | string[];
  authnContextClassRef?: string | string[];
  nameIDPolicy?: Record<string, string | string[]>;
}

/** Field definition consumed by `extract`. */
export interface ExtractorField {
  key: string;
  localPath: string[] | string[][];
  attributes: string[];
  index?: string[];
  attributePath?: string[];
  context?: boolean;
  shortcut?: string;
}

/** Array of extractor field definitions. */
export type ExtractorFields = ExtractorField[];

/**
 * Minimal HTTP request shape the library consumes from the caller's web
 * framework. Only the fields SAML needs are typed.
 */
export interface ESamlHttpRequest {
  query?: Record<string, string | undefined>;
  body?: Record<string, string | undefined>;
  octetString?: string;
}

/**
 * Parsed request snapshot passed around when building response messages
 * so the response can include matching `InResponseTo` references.
 */
export interface RequestInfo {
  extract: ExtractorResult;
  [key: string]: unknown;
}

/**
 * Authenticated user passed to the IdP when building a login/logout
 * response. Additional custom claims are permitted via the index signature.
 */
export interface SAMLUser {
  email?: string;
  logoutNameID?: string;
  sessionIndex?: string;
  [key: string]: unknown;
}

/**
 * Caller-supplied template transformer used by the create* methods.
 * Receives the raw template string and returns the substituted result
 * along with the SAML message ID.
 */
export type CustomTagReplacement = (template: string) => BindingContext;

/**
 * Per-request options accepted by `ServiceProvider#createLoginRequest`.
 *
 * `relayState` here takes precedence over `entitySetting.relayState`,
 * which is deprecated for v3 — see `saml-bindings §3.4.3` and §3.5.3
 * (RelayState is request-scoped, not entity-scoped).
 */
export interface CreateLoginRequestOptions {
  relayState?: string;
  customTagReplacement?: CustomTagReplacement;
  /** saml-core §3.4.1 — when true, the IdP MUST re-authenticate the user. */
  forceAuthn?: boolean;
  /**
   * saml-core §3.4.1 — `<samlp:AuthnRequest>` may identify the desired ACS
   * endpoint either by URL+ProtocolBinding *or* by an index into the SP's
   * metadata. The three attributes are mutually exclusive: "If the
   * `<AssertionConsumerServiceIndex>` attribute is present, neither
   * `<AssertionConsumerServiceURL>` nor `<ProtocolBinding>` may be set."
   *
   * When this option is set, samlify omits both `AssertionConsumerServiceURL`
   * and `ProtocolBinding` from the rendered request — including any
   * metadata-derived ACS URL the SP would otherwise inject. In other words,
   * if the caller sets `assertionConsumerServiceIndex`, the index wins;
   * mutual exclusion enforcement is the caller's responsibility.
   *
   * Useful for IdPs (legacy Shibboleth, certain ADFS configurations) that
   * prefer the metadata-indexed form per saml-profiles §4.1.4.1.
   */
  assertionConsumerServiceIndex?: number;
}

/** Per-request options accepted by `IdentityProvider#createLoginResponse`. */
export interface CreateLoginResponseOptions {
  relayState?: string;
  customTagReplacement?: CustomTagReplacement;
  /** When true, encrypt the assertion before signing the message. */
  encryptThenSign?: boolean;
}

/** Per-request options accepted by `Entity#createLogoutRequest`. */
export interface CreateLogoutRequestOptions {
  relayState?: string;
  customTagReplacement?: CustomTagReplacement;
}

/** Per-request options accepted by `Entity#createLogoutResponse`. */
export interface CreateLogoutResponseOptions {
  relayState?: string;
  customTagReplacement?: CustomTagReplacement;
}

/** Output of an XML-signature binding step (base64 SAML + request id). */
export interface BindingContext {
  context: string;
  id: string;
}

/** Post-binding output extended with the endpoint, relay state, and kind. */
export interface PostBindingContext extends BindingContext {
  relayState?: string;
  entityEndpoint: string;
  type: string;
}

/** Simple-sign binding output. */
export interface SimpleSignBindingContext extends PostBindingContext {
  sigAlg?: string;
  signature?: string;
  keyInfo?: string;
}

/** Simple-sign computed output without the outer endpoint wrapper. */
export interface SimpleSignComputedContext extends BindingContext {
  sigAlg?: string;
  signature?: string;
}

/** Parsed result emitted by SAML binding parsers. */
export interface ParseResult {
  samlContent: string;
  extract: ExtractorResult;
  sigAlg: string;
}

/** Options for `MetadataSpOptions#signatureConfig`. */
export interface SignatureConfig {
  prefix?: string;
  location?: {
    reference?: string;
    action?: 'append' | 'prepend' | 'before' | 'after';
  };
  attrs?: Record<string, string>;
  existingPrefixes?: Record<string, string>;
}

/** SAML root-element wrapping template (request/response contexts). */
export interface SAMLDocumentTemplate {
  context?: string;
}

/** Options accepted when constructing IdP metadata programmatically. */
export interface MetadataIdpOptions {
  entityID?: string;
  signingCert?: string | Buffer | (string | Buffer)[];
  encryptCert?: string | Buffer | (string | Buffer)[];
  wantAuthnRequestsSigned?: boolean;
  nameIDFormat?: string[];
  singleSignOnService?: SSOService[];
  singleLogoutService?: SSOService[];
  requestSignatureAlgorithm?: string;
}

/** Constructor argument for IdP metadata: options or raw XML. */
export type MetadataIdpConstructor =
  | MetadataIdpOptions
  | MetadataFile;

/** Options accepted when constructing SP metadata programmatically. */
export interface MetadataSpOptions {
  entityID?: string;
  signingCert?: string | Buffer | (string | Buffer)[];
  encryptCert?: string | Buffer | (string | Buffer)[];
  authnRequestsSigned?: boolean;
  wantAssertionsSigned?: boolean;
  wantMessageSigned?: boolean;
  signatureConfig?: SignatureConfig;
  nameIDFormat?: string[];
  singleSignOnService?: SSOService[];
  singleLogoutService?: SSOService[];
  assertionConsumerService?: SSOService[];
  elementsOrder?: string[];
}

/** Constructor argument for SP metadata: options or raw XML. */
export type MetadataSpConstructor =
  | MetadataSpOptions
  | MetadataFile;

/** Combined settings bag carried by an Entity. */
export type EntitySetting = ServiceProviderSettings & IdentityProviderSettings;

/** Service-provider configuration accepted by the SP factory. */
export interface ServiceProviderSettings {
  metadata?: string | Buffer;
  entityID?: string;
  authnRequestsSigned?: boolean;
  wantAssertionsSigned?: boolean;
  wantMessageSigned?: boolean;
  wantLogoutResponseSigned?: boolean;
  wantLogoutRequestSigned?: boolean;
  privateKey?: string | Buffer;
  privateKeyPass?: string;
  isAssertionEncrypted?: boolean;
  requestSignatureAlgorithm?: string;
  encPrivateKey?: string | Buffer;
  encPrivateKeyPass?: string | Buffer;
  assertionConsumerService?: SSOService[];
  singleLogoutService?: SSOService[];
  signatureConfig?: SignatureConfig;
  loginRequestTemplate?: SAMLDocumentTemplate;
  logoutRequestTemplate?: SAMLDocumentTemplate;
  logoutResponseTemplate?: SAMLDocumentTemplate;
  signingCert?: string | Buffer | (string | Buffer)[];
  encryptCert?: string | Buffer | (string | Buffer)[];
  transformationAlgorithms?: string[];
  nameIDFormat?: string[];
  allowCreate?: boolean;
  /**
   * @deprecated Pass `relayState` per request via the options bag on
   * `createLoginRequest` / `createLogoutRequest` / `createLogoutResponse`
   * instead. RelayState is request-scoped per `saml-bindings §3.4.3, §3.5.3`;
   * keeping it on the entity makes a single SP/IdP instance unsafe for
   * concurrent requests with different relay state values. Will be removed
   * in v3.
   */
  relayState?: string;
  /** Clock drift tolerance in ms for notBefore / notOnOrAfter checks. */
  clockDrifts?: [number, number];
}

/** Identity-provider configuration accepted by the IdP factory. */
export interface IdentityProviderSettings {
  metadata?: string | Buffer;

  /** XML-DSig signature algorithm URI for requests. */
  requestSignatureAlgorithm?: string;

  /** Login response template with optional attribute statements. */
  loginResponseTemplate?: LoginResponseTemplate;

  /** Logout request XML template. */
  logoutRequestTemplate?: SAMLDocumentTemplate;

  /** Logout response XML template. */
  logoutResponseTemplate?: SAMLDocumentTemplate;

  /** Callback used to generate a unique SAML message ID. */
  generateID?: () => string;

  entityID?: string;
  privateKey?: string | Buffer;
  privateKeyPass?: string;
  signingCert?: string | Buffer | (string | Buffer)[];
  encryptCert?: string | Buffer | (string | Buffer)[];
  nameIDFormat?: string[];
  singleSignOnService?: SSOService[];
  singleLogoutService?: SSOService[];
  isAssertionEncrypted?: boolean;
  encPrivateKey?: string | Buffer;
  encPrivateKeyPass?: string;
  messageSigningOrder?: string;
  wantLogoutRequestSigned?: boolean;
  wantLogoutResponseSigned?: boolean;
  wantAuthnRequestsSigned?: boolean;
  wantLogoutRequestSignedResponseSigned?: boolean;
  /**
   * Override the XML namespace prefixes used when rendering the IdP's
   * default request/response templates.
   *
   * - `protocol` rebinds the SAML protocol namespace
   *   (`urn:oasis:names:tc:SAML:2.0:protocol`, default prefix `samlp`).
   * - `assertion` rebinds the SAML assertion namespace
   *   (`urn:oasis:names:tc:SAML:2.0:assertion`, default prefix `saml`).
   * - `encryptedAssertion` is the prefix wrapped around
   *   `<EncryptedAssertion>` inside `libsaml.encryptAssertion`.
   *
   * Per saml-core §1.4 the prefix choice is not normative — only the
   * namespace URI bindings are. Some peers (legacy ADFS quirks, custom
   * integrations) require non-standard prefixes; this lets callers swap
   * `samlp:` ↔ `samlp2:` and `saml:` ↔ `saml2:` without supplying a fully
   * custom template (closes #388).
   */
  tagPrefix?: {
    /** Prefix bound to the SAML protocol namespace (default: 'samlp'). */
    protocol?: string;
    /** Prefix bound to the SAML assertion namespace (default: 'saml'). */
    assertion?: string;
    /** Prefix used when wrapping `<EncryptedAssertion>`. */
    encryptedAssertion?: string;
    [key: string]: string | undefined;
  };
  /**
   * @internal Populated by the IdP constructor when `tagPrefix.protocol`
   * or `tagPrefix.assertion` is overridden — pre-rewritten copies of the
   * built-in default request/response templates that the bindings consume
   * in place of the library-internal defaults. Not part of the public
   * configuration surface.
   */
  tagPrefixedDefaults?: {
    loginResponseTemplate?: SAMLDocumentTemplate;
    logoutRequestTemplate?: SAMLDocumentTemplate;
    logoutResponseTemplate?: SAMLDocumentTemplate;
  };
}
