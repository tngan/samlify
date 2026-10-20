/**
 * @file libsaml.ts
 * @author tngan
 * @desc SAML primitives: templates, XML signing/verification, assertion
 * encryption/decryption, and XPath helpers used by the higher-level flows.
 */

import utility, { flattenDeep, isString, escapeXPathValue, camelCase } from './utility';
import { algorithms, wording, namespace } from './urn';
import { select, SelectReturnType } from 'xpath';
import { MetadataInterface } from './metadata';
import nrsa, { SigningSchemeHash } from 'node-rsa';
import { SignedXml } from 'xml-crypto';
import * as xmlenc from '@authenio/xml-encryption';
import { getContext } from './api';
import { parseXml } from './xml';
import { renderTemplate, escapeXmlValue, placeholderName } from './template';
import type { TemplateRenderer } from './template';
import xmlEscape from 'xml-escape';
import * as crypto from 'crypto';
import * as fs from 'fs';
import type {
  EntitySetting,
  SignatureConfig,
  TagReplacementMap,
  XmlAttributeMap,
  XmlElementArray,
} from './types';

const signatureAlgorithms = algorithms.signature;
const digestAlgorithms = algorithms.digest;
const certUse = wording.certUse;
const urlParams = wording.urlParams;
// Key transport and data encryption algorithms refused on decryption unless
// `allowInsecureDecryptionAlgorithms` is set.
const insecureEncryptionAlgorithms = [
  algorithms.encryption.key.RSA_1_5,
  algorithms.encryption.data.TRI_DEC,
];

/** Coerce the heterogeneous return of `xpath.select` into a Node array. */
function toNodeArray(result: SelectReturnType): Node[] {
  if (Array.isArray(result)) return result;
  if (result != null && typeof result === 'object' && 'nodeType' in (result as object)) {
    return [result as Node];
  }
  return [];
}

/** Options accepted by {@link LibSamlInterface.constructSAMLSignature}. */
export interface SignatureConstructor {
  rawSamlMessage: string;
  referenceTagXPath?: string;
  privateKey: string;
  privateKeyPass?: string;
  signatureAlgorithm: string;
  signingCert: string | Buffer;
  isBase64Output?: boolean;
  signatureConfig?: SignatureConfig;
  isMessageSigned?: boolean;
  transformationAlgorithms?: string[];
}

/** Options accepted by {@link LibSamlInterface.verifySignature}. */
export interface SignatureVerifierOptions {
  metadata?: MetadataInterface;
  keyFile?: string;
  /**
   * @deprecated Ignored: the algorithm is read from each signature's
   * `<SignatureMethod>`. Use `allowedSignatureAlgorithms` to restrict it.
   */
  signatureAlgorithm?: string;
  /**
   * Accepted signature algorithm URIs; unset accepts every supported one.
   * Each `<DigestMethod>` must be the digest of an allowed algorithm.
   */
  allowedSignatureAlgorithms?: string[];
  /** Reject a message whose root element carries no signature. */
  requireMessageSignature?: boolean;
}

/**
 * Generic extracted SAML result shape retained for backwards compatibility.
 * Prefer {@link import('./types').ExtractorResult} in new code.
 */
export interface ExtractorResult {
  [key: string]: unknown;
  signature?: string | string[];
  issuer?: string | string[];
  nameID?: string;
  notexist?: boolean;
}

/** Attribute configuration used when building an AttributeStatement. */
export interface LoginResponseAttribute {
  name: string;
  nameFormat: string;
  valueXsiType: string;
  valueTag: string;
  valueXmlnsXs?: string;
  valueXmlnsXsi?: string;
}

/** Overridable templates used when building a LoginResponse. */
export interface LoginResponseAdditionalTemplates {
  attributeStatementTemplate?: AttributeStatementTemplate;
  attributeTemplate?: AttributeTemplate;
}

/** Shared shape for all SAML document templates. */
export interface BaseSamlTemplate {
  context: string;
}

export interface LoginResponseTemplate extends BaseSamlTemplate {
  attributes?: LoginResponseAttribute[];
  additionalTemplates?: LoginResponseAdditionalTemplates;
}

export interface AttributeStatementTemplate extends BaseSamlTemplate { }
export interface AttributeTemplate extends BaseSamlTemplate { }
export interface LoginRequestTemplate extends BaseSamlTemplate { }
export interface LogoutRequestTemplate extends BaseSamlTemplate { }
export interface LogoutResponseTemplate extends BaseSamlTemplate { }

/** Valid certificate `use` attribute values in metadata KeyDescriptor. */
export type KeyUse = 'signing' | 'encryption';

/** Shape of a KeyDescriptor element assembled by `createKeySection`. */
export interface KeyComponent {
  [key: string]: unknown;
  KeyDescriptor: XmlElementArray;
}

/** Structural shape of an Entity (IdP or SP) consumed by libsaml. */
export interface EntityLike {
  entitySetting: EntitySetting & {
    isAssertionEncrypted?: boolean;
    dataEncryptionAlgorithm?: string;
    keyEncryptionAlgorithm?: string;
    tagPrefix?: {
      protocol?: string;
      assertion?: string;
      encryptedAssertion?: string;
      [key: string]: string | undefined;
    };
    encPrivateKey?: string | Buffer;
    encPrivateKeyPass?: string | Buffer;
    allowInsecureDecryptionAlgorithms?: boolean;
  };
  entityMeta: MetadataInterface;
}

/** Public surface exposed by the libsaml singleton. */
export interface LibSamlInterface {
  getQueryParamByType: (type: string) => string;
  createXPath: (local: string | { name: string; attr: string }, isExtractAll?: boolean) => string;
  /** @deprecated Use `renderTemplate`; see docs/template-migration.md. */
  replaceTagsByValue: (rawXML: string, tagValues: TagReplacementMap) => string;
  renderTags: (rawXML: string, tagValues: TagReplacementMap, renderer?: TemplateRenderer) => string;
  renderTemplate: (template: string, values: TagReplacementMap) => string;
  attributeStatementBuilder: (
    attributes: LoginResponseAttribute[],
    attributeTemplate?: AttributeTemplate,
    attributeStatementTemplate?: AttributeStatementTemplate,
    renderer?: TemplateRenderer,
  ) => string;
  constructSAMLSignature: (opts: SignatureConstructor) => string;
  verifySignature: (xml: string, opts: SignatureVerifierOptions) => [boolean, string | null];
  createKeySection: (use: KeyUse, cert: string | Buffer) => KeyComponent;
  constructMessageSignature: (
    octetString: string,
    key: string,
    passphrase?: string,
    isBase64?: boolean,
    signingAlgorithm?: string,
  ) => string | Buffer;

  verifyMessageSignature: (
    metadata: MetadataInterface,
    octetString: string,
    signature: string | Buffer,
    verifyAlgorithm?: string,
  ) => boolean;
  getKeyInfo: (
    x509Certificate: string,
    signatureConfig?: SignatureConfig,
  ) => { getKeyInfo: () => string; getKey: () => string };
  encryptAssertion: (
    sourceEntity: EntityLike,
    targetEntity: EntityLike,
    entireXML: string,
  ) => Promise<string>;
  decryptAssertion: (here: EntityLike, entireXML: string) => Promise<[string, string]>;

  getSigningScheme: (sigAlg: string) => SigningSchemeHash | null;
  getDigestMethod: (sigAlg: string) => string | null;

  nrsaAliasMapping: Record<string, SigningSchemeHash>;
  defaultLoginRequestTemplate: LoginRequestTemplate;
  defaultLoginResponseTemplate: LoginResponseTemplate;
  defaultAttributeStatementTemplate: AttributeStatementTemplate;
  defaultAttributeTemplate: AttributeTemplate;
  defaultLogoutRequestTemplate: LogoutRequestTemplate;
  defaultLogoutResponseTemplate: LogoutResponseTemplate;
}

// XML 1.0 Char production (§2.2).
const NON_XML_CHAR = new RegExp('[^\\t\\n\\r\\u0020-\\uD7FF\\uE000-\\uFFFD\\u{10000}-\\u{10FFFF}]', 'u');
const CHAR_REFERENCE = /&#(?:x([0-9a-fA-F]+)|([0-9]+));/g;

function isXmlChar(codePoint: number): boolean {
  return codePoint === 0x9 || codePoint === 0xA || codePoint === 0xD
    || (codePoint >= 0x20 && codePoint <= 0xD7FF)
    || (codePoint >= 0xE000 && codePoint <= 0xFFFD)
    || (codePoint >= 0x10000 && codePoint <= 0x10FFFF);
}

/**
 * Reject input that is not a plain, well-formed XML document before it
 * reaches the schema validator: a DTD (SAML messages never carry one), a
 * character or character reference outside the XML Char range, or anything
 * the XML parser rejects. Throws `ERR_INVALID_XML`.
 *
 * @param input SAML XML string
 */
function assertPlainXml(input: string): void {
  if (typeof input !== 'string' || input.includes('<!DOCTYPE') || NON_XML_CHAR.test(input)) {
    throw new Error('ERR_INVALID_XML');
  }
  for (const [, hex, decimal] of input.matchAll(CHAR_REFERENCE)) {
    if (!isXmlChar(hex !== undefined ? parseInt(hex, 16) : parseInt(decimal, 10))) {
      throw new Error('ERR_INVALID_XML');
    }
  }
  let root: Element | null;
  try {
    root = parseXml(input).documentElement;
  } catch {
    throw new Error('ERR_INVALID_XML');
  }
  if (!root) {
    throw new Error('ERR_INVALID_XML');
  }
}

/**
 * Throw unless a signature algorithm is in the allow-list.
 *
 * @param sigAlg signature algorithm URI declared by the sender
 * @param allowed accepted signature algorithm URIs
 */
export function assertAllowedSignatureAlgorithm(sigAlg: string, allowed: string[]): void {
  if (!allowed.includes(sigAlg)) {
    throw new Error('ERR_SIGNATURE_ALGORITHM_NOT_ALLOWED');
  }
}

/** Check an XML signature's `<SignatureMethod>` and every `<DigestMethod>`. */
function assertAllowedXmlSignatureAlgorithms(signatureNode: Node, allowed: string[]): void {
  const algorithmOf = (path: string) =>
    (select(path, signatureNode) as Attr[]).map(attr => attr.value);
  const [signatureMethod] = algorithmOf("./*[local-name(.)='SignedInfo']/*[local-name(.)='SignatureMethod']/@Algorithm");
  assertAllowedSignatureAlgorithm(signatureMethod ?? '', allowed);
  const allowedDigests = allowed.map(alg => (digestAlgorithms as Record<string, string>)[alg]).filter(Boolean);
  const digestMethods = algorithmOf("./*[local-name(.)='SignedInfo']/*[local-name(.)='Reference']/*[local-name(.)='DigestMethod']/@Algorithm");
  if (digestMethods.some(digest => !allowedDigests.includes(digest))) {
    throw new Error('ERR_SIGNATURE_ALGORITHM_NOT_ALLOWED');
  }
}

const libSaml = () => {

  /**
   * Map a SAML URL parameter type onto its canonical query-string key
   * (`SAMLRequest` or `SAMLResponse`).
   *
   * @param type SAML URL parameter name
   * @returns `SAMLRequest` or `SAMLResponse`
   */
  function getQueryParamByType(type: string): string {
    if ([urlParams.logoutRequest, urlParams.samlRequest].indexOf(type) !== -1) {
      return 'SAMLRequest';
    }
    if ([urlParams.logoutResponse, urlParams.samlResponse].indexOf(type) !== -1) {
      return 'SAMLResponse';
    }
    throw new Error('ERR_UNDEFINED_QUERY_PARAMS');
  }

  /**
   * Mapping from XML-DSig signature algorithm URIs to node-rsa schemes.
   *
   * The PSS entry covers the redirect-binding detached signature path:
   * `node-rsa` accepts `pss-sha256` directly as a `signingScheme` value.
   * The `xmldsig-more#sha256-rsa-MGF1` URI (W3C Note, 2007-05) is listed
   * in `xmldsig-core §6.4.2` as the recommended successor to PKCS#1 v1.5
   * RSA-SHA256 (`saml-sec-consider §6.5`).
   */
  const nrsaAliasMapping: Record<string, SigningSchemeHash> = {
    'http://www.w3.org/2000/09/xmldsig#rsa-sha1': 'pkcs1-sha1',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'pkcs1-sha256',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': 'pkcs1-sha512',
    'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1': 'pss-sha256',
  };

  /**
   * RSASSA-PSS plugin class for `xml-crypto`'s `SignedXml.SignatureAlgorithms`
   * registry (`xmldsig-core §6.4.2`).
   *
   * **Temporary shim.** xml-crypto already implements PSS-SHA256 on its
   * master branch (PR node-saml/xml-crypto#488, merged 2025-10-17), but
   * the latest published npm version (6.1.2, 2024-08) predates that
   * commit. Once xml-crypto cuts a release containing #488, delete this
   * class and the `registerPssAlgorithms` helper below — the URI alone
   * in `algorithms.signature` is sufficient and the constructor will
   * seed `SignatureAlgorithms` with the upstream implementation.
   *
   * `RSA_PKCS1_PSS_PADDING` with `RSA_PSS_SALTLEN_DIGEST` matches the
   * MGF1+SHA-256 convention referenced by the `sha256-rsa-MGF1` URI
   * (xmldsig-more, W3C Note 2007-05).
   */
  const pssPaddingOptions = {
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
  } as const;

  class RsaSha256Mgf1 {
    getSignature = (signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string => {
      const signOpts: crypto.SignPrivateKeyInput = {
        key: privateKey as crypto.SignPrivateKeyInput['key'],
        padding: pssPaddingOptions.padding,
        saltLength: pssPaddingOptions.saltLength,
      };
      return crypto.sign('RSA-SHA256', Buffer.from(signedInfo as string), signOpts).toString('base64');
    };
    verifySignature = (material: string, key: crypto.KeyLike, signatureValue: string): boolean => {
      const verifyOpts: crypto.VerifyPublicKeyInput = {
        key: key as crypto.VerifyPublicKeyInput['key'],
        padding: pssPaddingOptions.padding,
        saltLength: pssPaddingOptions.saltLength,
      };
      return crypto.verify('RSA-SHA256', Buffer.from(material), verifyOpts, Buffer.from(signatureValue, 'base64'));
    };
    getAlgorithmName = (): string => 'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1';
  }

  /**
   * Register the RSASSA-PSS SHA-256 signature class on a fresh `SignedXml`
   * instance so the algorithm-agility surface from `xmldsig-core §6.4` is
   * available for both signing and verification. PKCS#1 v1.5 entries are
   * preserved untouched.
   */
  function registerPssAlgorithms(sig: SignedXml): void {
    sig.SignatureAlgorithms = {
      ...sig.SignatureAlgorithms,
      'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1': RsaSha256Mgf1,
    };
  }

  /**
   * Default AuthnRequest XML template.
   *
   * Per saml-core §3.4.1, `ProtocolBinding`, `AssertionConsumerServiceURL`,
   * and `AssertionConsumerServiceIndex` are all `use="optional"` and
   * mutually exclusive — when the index is set, neither URL nor
   * ProtocolBinding may be present. All three are placeholders here so
   * that `replaceTagsByValue` drops whichever the caller leaves
   * undefined (closes #437).
   */
  const defaultLoginRequestTemplate: LoginRequestTemplate = {
    context: '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" ForceAuthn="{ForceAuthn}" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="{ProtocolBinding}" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}" AssertionConsumerServiceIndex="{AssertionConsumerServiceIndex}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>',
  };

  /**
   * Default LogoutRequest XML template.
   *
   * The optional `<samlp:SessionIndex>` element (saml-core §3.7.1) is
   * included with a placeholder body. When the caller leaves
   * `user.sessionIndex` undefined, `replaceTagsByValue` drops the whole
   * element from the rendered XML, matching the schema's
   * `minOccurs="0"` declaration.
   */
  const defaultLogoutRequestTemplate: LogoutRequestTemplate = {
    context: '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}"><saml:Issuer>{Issuer}</saml:Issuer><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><samlp:SessionIndex>{SessionIndex}</samlp:SessionIndex></samlp:LogoutRequest>',
  };

  /** Default AttributeStatement XML fragment template. */
  const defaultAttributeStatementTemplate: AttributeStatementTemplate = {
    context: '<saml:AttributeStatement>{Attributes}</saml:AttributeStatement>',
  };

  /** Default Attribute XML fragment template. */
  const defaultAttributeTemplate: AttributeTemplate = {
    context: '<saml:Attribute Name="{Name}" NameFormat="{NameFormat}"><saml:AttributeValue xmlns:xs="{ValueXmlnsXs}" xmlns:xsi="{ValueXmlnsXsi}" xsi:type="{ValueXsiType}">{Value}</saml:AttributeValue></saml:Attribute>',
  };

  /** Default LoginResponse XML template. */
  const defaultLoginResponseTemplate: LoginResponseTemplate = {
    context: '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AuthnStatement}{AttributeStatement}</saml:Assertion></samlp:Response>',
    attributes: [],
    additionalTemplates: {
      attributeStatementTemplate: defaultAttributeStatementTemplate,
      attributeTemplate: defaultAttributeTemplate,
    },
  };

  /** Default LogoutResponse XML template. */
  const defaultLogoutResponseTemplate: LogoutResponseTemplate = {
    context: '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status></samlp:LogoutResponse>',
  };

  /**
   * Map a SAML signature algorithm URI to its node-rsa signing scheme.
   *
   * - When `sigAlg` is omitted, the default RSA-SHA256 scheme is used
   *   (per `saml-bindings §3.4.4.1` recommendation).
   * - When `sigAlg` is supplied but does not match a known URI, the
   *   function throws. Silently downgrading to RSA-SHA1 (the previous
   *   behaviour) was a verification-time vulnerability: an attacker
   *   could supply an unknown `SigAlg` query parameter to coerce
   *   verification onto SHA-1, which is collision-broken
   *   (`saml-sec-consider §6.5`, `xmldsig-core §6.4`).
   *
   * @param sigAlg signature algorithm URI
   * @returns node-rsa signing scheme string
   * @throws when `sigAlg` is supplied and does not match a supported URI
   */
  function getSigningScheme(sigAlg?: string): SigningSchemeHash {
    if (sigAlg === undefined) {
      return nrsaAliasMapping[signatureAlgorithms.RSA_SHA256];
    }
    const algAlias = nrsaAliasMapping[sigAlg];
    if (algAlias === undefined) {
      throw new Error('ERR_UNSUPPORTED_SIGNATURE_ALGORITHM');
    }
    return algAlias;
  }

  /**
   * Return the companion digest URI for a given signature algorithm URI.
   *
   * @param sigAlg signature algorithm URI
   * @returns digest algorithm URI or undefined when unsupported
   */
  function getDigestMethod(sigAlg: string): string | undefined {
    return digestAlgorithms[sigAlg];
  }

  /**
   * Build an XPath expression that matches either a named element or one of
   * its attributes.
   *
   * @param local element name, or `{ name, attr }` for an attribute selector
   * @param isExtractAll when true the element selector resolves to its text()
   * @returns XPath expression
   */
  function createXPath(
    local: string | { name: string; attr: string },
    isExtractAll?: boolean,
  ): string {
    if (isString(local)) {
      const escaped = escapeXPathValue(local);
      return isExtractAll === true
        ? '//*[local-name(.)=' + escaped + ']/text()'
        : '//*[local-name(.)=' + escaped + ']';
    }
    const { name, attr } = local as { name: string; attr: string };
    return '//*[local-name(.)=' + escapeXPathValue(name) + ']/@' + attr;
  }

  /**
   * Capitalise a content string after camel-casing and optionally prefix it.
   */
  function tagging(prefix: string, content: string): string {
    const camelContent = camelCase(content);
    return prefix + camelContent.charAt(0).toUpperCase() + camelContent.slice(1);
  }

  /**
   * Replacer for {@link replaceTagsByValue}. Always XML-escapes the
   * replacement text, in both attribute and element-text contexts, to
   * prevent SAML attribute/element injection through user-controlled
   * template values.
   */
  function escapeTag(replacement: unknown): (...args: string[]) => string {
    return (_match: string, quote?: string) => {
      const text: string = replacement === null || replacement === undefined ? '' : String(replacement);
      return quote ? `${quote}${escapeXmlValue(text)}` : escapeXmlValue(text);
    };
  }

  return {

    createXPath,
    getQueryParamByType,
    defaultLoginRequestTemplate,
    defaultLoginResponseTemplate,
    defaultAttributeStatementTemplate,
    defaultAttributeTemplate,
    defaultLogoutRequestTemplate,
    defaultLogoutResponseTemplate,

    /**
     * Substitute `{Tag}` placeholders inside an XML template with the given
     * replacement map. Replacement text is XML-escaped in both attribute and
     * element-text positions to prevent SAML element/attribute injection.
     *
     * When a tag's value is `null` or `undefined`:
     *   - in **attribute position** (`name="{Tag}"`) the entire attribute is
     *     omitted from the rendered XML, per `saml-core §3.4.1` (every
     *     `<AuthnRequest>` attribute is `use="optional"`); previously samlify
     *     emitted `name=""` or the literal `name="undefined"`, which is
     *     invalid for typed attributes (e.g. `AssertionConsumerServiceURL`
     *     declared as `xs:anyURI`).
     *   - in **element-only-body position** (`<X>{Tag}</X>` or
     *     `<X attr="...">{Tag}</X>`) the entire element is dropped — per
     *     `saml-core §3.7.1` for `<samlp:SessionIndex>` and any other
     *     `minOccurs="0"` element where the body is solely a placeholder.
     *   - in **mixed-text position** (`<X>prefix{Tag}suffix</X>`) the
     *     placeholder is replaced with the empty string (legacy behaviour).
     *
     * Values are inserted in a single pass and never scanned again, and tag
     * names are matched literally.
     *
     * @deprecated Use {@link renderTemplate} (`libsaml.renderTemplate`), which
     *   validates where each placeholder sits and escapes for that position;
     *   see docs/template-migration.md. Kept for backward compatibility; will
     *   be removed in v3.
     * @param rawXML template with `{Tag}` placeholders
     * @param tagValues replacement map keyed by tag name
     * @returns XML with placeholders resolved
     */
    replaceTagsByValue(rawXML: string, tagValues: TagReplacementMap): string {
      // Tag names are looked up literally (never compiled into a RegExp),
      // including their encoded form (see `placeholderName`).
      const lookup = new Map<string, string>();
      Object.keys(tagValues).forEach(t => {
        lookup.set(placeholderName(t), t);
        lookup.set(t, t);
      });
      const omitted = (name: string) => {
        const key = lookup.get(name);
        return key !== undefined && (tagValues[key] === null || tagValues[key] === undefined);
      };
      // Optional attributes and elements are dropped on the template itself,
      // before any value is inserted.
      rawXML = rawXML.replace(
        /\s+[A-Za-z_:][\w:.-]*=("|')\{([^{}]*)\}\1/g,
        (match, _quote, name) => (omitted(name) ? '' : match),
      );
      rawXML = rawXML.replace(
        /<([A-Za-z_:][\w:.-]*)((?:\s+[^>]*)?)>\{([^{}]*)\}<\/\1>/g,
        (match, _tag, _attrs, name) => (omitted(name) ? '' : match),
      );
      // Single pass: inserted values are never scanned for placeholders again.
      return rawXML.replace(/("?)\{([^{}]*)\}/g, (match, quote: string, name: string) => {
        const key = lookup.get(name);
        if (key === undefined) {
          return match;
        }
        const value = tagValues[key];
        if (value === null || value === undefined) {
          return quote;
        }
        return escapeTag(value)(match, quote);
      });
    },

    /**
     * Render a template with the engine selected by an entity's
     * `templateRenderer` setting: {@link renderTemplate} for `strict`,
     * {@link replaceTagsByValue} otherwise.
     *
     * @param rawXML template with `{Tag}` placeholders
     * @param tagValues replacement map keyed by tag name
     * @param renderer template engine
     * @returns XML with placeholders resolved
     */
    renderTags(rawXML: string, tagValues: TagReplacementMap, renderer?: TemplateRenderer): string {
      return renderer === 'strict' ? renderTemplate(rawXML, tagValues) : this.replaceTagsByValue(rawXML, tagValues);
    },

    renderTemplate,

    /**
     * Build a serialized `<AttributeStatement>` from attribute descriptors
     * by applying the attribute and statement templates.
     *
     * @param attributes attribute descriptors (name, format, value)
     * @param attributeTemplate per-attribute template
     * @param attributeStatementTemplate wrapping statement template
     * @returns serialized XML fragment
     */
    attributeStatementBuilder(
      attributes: LoginResponseAttribute[],
      attributeTemplate: AttributeTemplate = defaultAttributeTemplate,
      attributeStatementTemplate: AttributeStatementTemplate = defaultAttributeStatementTemplate,
      renderer?: TemplateRenderer,
    ): string {
      // `{Value}` becomes the `{attr…}` placeholder filled in when the
      // response is rendered. Attribute metadata is escaped like any value,
      // and replacer functions keep `$&`-style patterns in data literal.
      const fill = (template: string, fields: TagReplacementMap) => (renderer === 'strict'
        ? renderTemplate(template, fields)
        : Object.keys(fields).reduce(
          (line, placeholder) => line.replace(`{${placeholder}}`, () => escapeXmlValue(String(fields[placeholder]))),
          template,
        ));
      const attr = attributes.map(({ name, nameFormat, valueTag, valueXsiType, valueXmlnsXs, valueXmlnsXsi }) => {
        const line = fill(attributeTemplate.context, {
          Name: String(name),
          NameFormat: String(nameFormat),
          ValueXmlnsXs: valueXmlnsXs ? valueXmlnsXs : 'http://www.w3.org/2001/XMLSchema',
          ValueXmlnsXsi: valueXmlnsXsi ? valueXmlnsXsi : 'http://www.w3.org/2001/XMLSchema-instance',
          ValueXsiType: String(valueXsiType),
        });
        return line.replace('{Value}', () => `{${placeholderName(tagging('attr', valueTag))}}`);
      }).join('');
      const statement = renderer === 'strict'
        ? renderTemplate(attributeStatementTemplate.context, {})
        : attributeStatementTemplate.context;
      return statement.replace('{Attributes}', () => attr);
    },

    /**
     * Compute an XML-DSig signature over the supplied SAML message. Can
     * sign the message root (`isMessageSigned`), a referenced subtree
     * (`referenceTagXPath`), or both.
     *
     * @param opts signature inputs and layout options
     * @returns base64 (default) or raw signed XML string
     */
    constructSAMLSignature(opts: SignatureConstructor): string {
      const {
        rawSamlMessage,
        referenceTagXPath,
        privateKey,
        privateKeyPass,
        signatureAlgorithm = signatureAlgorithms.RSA_SHA256,
        transformationAlgorithms = [
          'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
          'http://www.w3.org/2001/10/xml-exc-c14n#',
        ],
        signingCert,
        signatureConfig,
        isBase64Output = true,
        isMessageSigned = false,
      } = opts;
      const sig = new SignedXml();
      // xmldsig-core §6.4.2 — make PSS variants available alongside the
      // PKCS#1 v1.5 set built into xml-crypto v6.x. No-op for callers
      // staying on RSA-SHA*; required when `signatureAlgorithm` is one of
      // the `xmldsig-more 2007-05` PSS URIs.
      registerPssAlgorithms(sig);
      const digestAlgorithm = getDigestMethod(signatureAlgorithm);
      if (referenceTagXPath) {
        sig.addReference({
          xpath: referenceTagXPath,
          transforms: transformationAlgorithms,
          digestAlgorithm,
        });
      }
      if (isMessageSigned) {
        sig.addReference({
          xpath: '/*',
          transforms: transformationAlgorithms,
          digestAlgorithm,
        });
      }
      sig.signatureAlgorithm = signatureAlgorithm;
      sig.publicCert = this.getKeyInfo(signingCert as string, signatureConfig).getKey();
      sig.getKeyInfoContent = this.getKeyInfo(signingCert as string, signatureConfig).getKeyInfo;
      sig.privateKey = utility.readPrivateKey(privateKey, privateKeyPass, true);
      sig.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';

      if (signatureConfig) {
        sig.computeSignature(rawSamlMessage, signatureConfig);
      } else {
        sig.computeSignature(rawSamlMessage);
      }
      return isBase64Output !== false
        ? utility.base64Encode(sig.getSignedXml())
        : sig.getSignedXml();
    },

    /**
     * Verify an XML-DSig signature on a SAML payload and, on success, return
     * the cryptographically authenticated assertion node.
     *
     * Defends against classic wrapping attacks by rejecting assertions that
     * appear inside a `SubjectConfirmationData` subtree.
     *
     * @param xml SAML message XML
     * @param opts metadata or key file plus signature algorithm
     * @returns tuple `[verified, authenticatedAssertion | null]`
     */
    verifySignature(xml: string, opts: SignatureVerifierOptions): [boolean, string | null] {
      const doc = parseXml(xml);

      // Absolute XPaths defend against signature-wrapping attacks.
      const messageSignatureXpath = "/*[contains(local-name(), 'Response') or contains(local-name(), 'Request')]/*[local-name(.)='Signature']";
      // Only a <Response> may carry assertions (saml-schema-protocol ResponseType).
      // A request or logout message is authenticated by its own root-level
      // signature alone; an embedded assertion's signature covers only that
      // assertion (saml-core §5.4.2) and must not vouch for the message.
      const assertionSignatureXpath = "/*[local-name(.)='Response']/*[local-name(.)='Assertion']/*[local-name(.)='Signature']";
      const wrappingElementsXPath = "/*[contains(local-name(), 'Response')]/*[local-name(.)='Assertion']/*[local-name(.)='Subject']/*[local-name(.)='SubjectConfirmation']/*[local-name(.)='SubjectConfirmationData']//*[local-name(.)='Assertion' or local-name(.)='Signature']";

      let selection: Node[] = [];
      const messageSignatureNode = toNodeArray(select(messageSignatureXpath, doc));
      const assertionSignatureNode = toNodeArray(select(assertionSignatureXpath, doc));
      const wrappingElementNode = toNodeArray(select(wrappingElementsXPath, doc));

      selection = selection.concat(messageSignatureNode);
      selection = selection.concat(assertionSignatureNode);

      if (wrappingElementNode.length !== 0) {
        throw new Error('ERR_POTENTIAL_WRAPPING_ATTACK');
      }

      if (opts.requireMessageSignature && messageSignatureNode.length === 0) {
        throw new Error('ERR_MISSING_MESSAGE_SIGNATURE');
      }

      if (selection.length === 0) {
        return [false, null];
      }

      for (const signatureNode of selection) {
        const sig = new SignedXml();
        // Register PSS plugins on the verifier instance so the algorithm
        // declared inside the signed XML can resolve to a SignatureAlgorithm
        // class (xmldsig-core §6.4.2; see `registerPssAlgorithms`).
        registerPssAlgorithms(sig);
        let verified = false;

        if (opts.allowedSignatureAlgorithms) {
          assertAllowedXmlSignatureAlgorithms(signatureNode, opts.allowedSignatureAlgorithms);
        }

        if (!opts.keyFile && !opts.metadata) {
          throw new Error('ERR_UNDEFINED_SIGNATURE_VERIFIER_OPTIONS');
        }

        if (opts.keyFile) {
          sig.publicCert = fs.readFileSync(opts.keyFile);
        }

        if (opts.metadata) {
          const certificateNode = toNodeArray(select(".//*[local-name(.)='X509Certificate']", signatureNode));
          const declaredCert = opts.metadata.getX509Certificate(certUse.signing);
          const metadataCert = (Array.isArray(declaredCert)
            ? flattenDeep<string>(declaredCert as string[])
            : typeof declaredCert === 'string' ? [declaredCert] : []
          )
            .map(utility.normalizeCerString)
            .filter(cert => cert.trim() !== '');

          // Only certificates declared in the peer's metadata are trusted
          // (saml-metadata §2.4.1.1); a certificate carried in the message's
          // own KeyInfo is attacker-controlled and must never be used unless
          // it matches one of them.
          if (metadataCert.length === 0) {
            throw new Error('NO_SELECTED_CERTIFICATE');
          }

          if (certificateNode.length !== 0) {
            const certEl = certificateNode[0] as Element;
            const x509CertificateData = certEl.textContent ?? '';
            const x509Certificate = utility.normalizeCerString(x509CertificateData).trim();
            const trustedCert = metadataCert.find(cert => cert.trim() === x509Certificate);

            if (!trustedCert) {
              throw new Error('ERROR_UNMATCH_CERTIFICATE_DECLARATION_IN_METADATA');
            }

            sig.publicCert = this.getKeyInfo(trustedCert).getKey();
          } else {
            sig.publicCert = this.getKeyInfo(metadataCert[0]).getKey();
          }
        }

        sig.loadSignature(signatureNode);

        verified = sig.checkSignature(doc.toString());

        // A signature that is present but does not verify fails the message;
        // falling through to the next one would let a broken message
        // signature be ignored whenever the assertion signature verifies.
        if (!verified) {
          return [false, null];
        }
        if (!(sig.getSignedReferences().length >= 1)) {
          throw new Error('NO_SIGNATURE_REFERENCES');
        }
        const signedVerifiedXML = sig.getSignedReferences()[0];
        const rootNode = parseXml(signedVerifiedXML).documentElement;

        // saml-core §5.4.2: the signature must be enveloped in the element it
        // signs. A valid signature moved under another element (e.g. a forged
        // root wrapping the genuine message) must not vouch for that element.
        const signedElement = signatureNode.parentNode as Element | null;
        if (
          !signedElement
          || !rootNode.getAttribute('ID')
          || rootNode.getAttribute('ID') !== signedElement.getAttribute('ID')
          || rootNode.localName !== signedElement.localName
          || rootNode.namespaceURI !== signedElement.namespaceURI
        ) {
          throw new Error('ERR_POTENTIAL_WRAPPING_ATTACK');
        }

        if (rootNode.localName === 'Response') {
          const assertions = toNodeArray(select("./*[local-name()='Assertion']", rootNode));
          const encryptedAssertions = toNodeArray(select("./*[local-name()='EncryptedAssertion']", rootNode));
          if (assertions.length === 1) {
            return [true, assertions[0].toString()];
          } else if (encryptedAssertions.length >= 1) {
            // Return a Response node so the caller can decrypt it later.
            return [true, rootNode.toString()];
          }
          return [true, null];
        } else if (rootNode.localName === 'Assertion') {
          return [true, rootNode.toString()];
        }
        // Signature is valid but there is no assertion (e.g. metadata).
        return [true, null];
      }
      return [false, null];
    },

    /**
     * Build the metadata `<KeyDescriptor>` fragment for a certificate use.
     *
     * @param use `signing` or `encryption`
     * @param certString PEM certificate body or Buffer
     * @returns element tree consumable by the `xml` module
     */
    createKeySection(use: KeyUse, certString: string | Buffer): KeyComponent {
      return {
        KeyDescriptor: [
          {
            _attr: { use },
          },
          {
            'ds:KeyInfo': [
              {
                _attr: {
                  'xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
                },
              },
              {
                'ds:X509Data': [{
                  'ds:X509Certificate': utility.normalizeCerString(certString),
                }],
              },
            ],
          },
        ],
      };
    },

    /**
     * Produce a detached RSA signature over a SAML redirect-binding octet
     * string. See SAML bindings spec §3.4.4.1.
     *
     * @param octetString canonical query-string to sign
     * @param key PEM private key
     * @param passphrase optional passphrase for the key
     * @param isBase64 when true (default), base64-encode the signature
     * @param signingAlgorithm signature algorithm URI
     * @returns base64 string (default) or raw Buffer signature
     */
    constructMessageSignature(
      octetString: string,
      key: string,
      passphrase?: string,
      isBase64?: boolean,
      signingAlgorithm?: string,
    ): string | Buffer {
      const decryptedKey = new nrsa(
        utility.readPrivateKey(key, passphrase),
        undefined,
        {
          signingScheme: getSigningScheme(signingAlgorithm),
        },
      );
      const signature = decryptedKey.sign(octetString);
      return isBase64 !== false ? signature.toString('base64') : signature;
    },

    /**
     * Verify a detached RSA signature over a redirect-binding octet string.
     *
     * @param metadata peer metadata carrying the signing certificate
     * @param octetString canonical query-string that was signed
     * @param signature signature bytes
     * @param verifyAlgorithm signature algorithm URI (optional)
     * @returns true when the signature verifies
     */
    verifyMessageSignature(
      metadata: MetadataInterface,
      octetString: string,
      signature: string | Buffer,
      verifyAlgorithm?: string,
    ): boolean {
      const declared = metadata.getX509Certificate(certUse.signing);
      const certificates = (Array.isArray(declared) ? flattenDeep<string>(declared as string[]) : declared ? [declared] : [])
        .filter(cert => typeof cert === 'string' && cert.trim() !== '');
      if (certificates.length === 0) {
        throw new Error('NO_SELECTED_CERTIFICATE');
      }
      const signingScheme = getSigningScheme(verifyAlgorithm);
      // Any signing certificate declared in metadata may have signed it (key rollover).
      return certificates.some(cert => {
        const key = new nrsa(utility.getPublicKeyPemFromCertificate(cert), 'public', { signingScheme });
        return key.verify(Buffer.from(octetString), Buffer.from(signature));
      });
    },

    /**
     * Build the KeyInfo XML fragment and PEM public key for a certificate.
     *
     * @param x509Certificate certificate body (no PEM wrappers)
     * @param signatureConfig optional prefix/location for the KeyInfo element
     */
    getKeyInfo(x509Certificate: string, signatureConfig: SignatureConfig = {}) {
      const prefix = signatureConfig.prefix ? `${signatureConfig.prefix}:` : '';
      return {
        getKeyInfo: (): string => {
          const body = utility.toCertificateBody(x509Certificate);
          return `<${prefix}X509Data><${prefix}X509Certificate>${body}</${prefix}X509Certificate></${prefix}X509Data>`;
        },
        getKey: (): string => {
          return utility.getPublicKeyPemFromCertificate(x509Certificate).toString();
        },
      };
    },

    /**
     * Encrypt the `<Assertion>` inside a SAML response using the target
     * entity's encryption certificate. Returns the base64-encoded XML
     * containing the `<EncryptedAssertion>` element in place of the plaintext.
     *
     * @param sourceEntity entity initiating the encryption (its settings drive the algorithms)
     * @param targetEntity entity whose certificate is used
     * @param xml response XML containing a single `<Assertion>`
     * @returns promise resolving to base64-encoded XML
     */
    encryptAssertion(sourceEntity: EntityLike, targetEntity: EntityLike, xml?: string): Promise<string> {
      return new Promise<string>((resolve, reject) => {
        if (!xml) {
          return reject(new Error('ERR_UNDEFINED_ASSERTION'));
        }

        const sourceEntitySetting = sourceEntity.entitySetting;
        const targetEntityMetadata = targetEntity.entityMeta;
        const doc = parseXml(xml);
        const assertions = select("//*[local-name(.)='Assertion']", doc) as Node[];
        if (!Array.isArray(assertions) || assertions.length === 0) {
          throw new Error('ERR_NO_ASSERTION');
        }
        if (assertions.length > 1) {
          throw new Error('ERR_MULTIPLE_ASSERTION');
        }
        const rawAssertionNode = assertions[0];

        if (sourceEntitySetting.isAssertionEncrypted) {
          const encryptCert = utility.toCertificateBody(targetEntityMetadata.getX509Certificate(certUse.encrypt) as string);
          const publicKeyPem = utility.getPublicKeyPemFromCertificate(encryptCert);

          xmlenc.encrypt(rawAssertionNode.toString(), {
            rsa_pub: Buffer.from(publicKeyPem),
            pem: Buffer.from(`-----BEGIN CERTIFICATE-----${encryptCert}-----END CERTIFICATE-----`),
            encryptionAlgorithm: sourceEntitySetting.dataEncryptionAlgorithm,
            keyEncryptionAlgorithm: sourceEntitySetting.keyEncryptionAlgorithm,
          }, (err, res) => {
            /* v8 ignore start */
            if (err) {
              console.error(err);
              return reject(new Error('ERR_EXCEPTION_OF_ASSERTION_ENCRYPTION'));
            }
            if (!res) {
              return reject(new Error('ERR_UNDEFINED_ENCRYPTED_ASSERTION'));
            }
            /* v8 ignore stop */
            const encAssertionPrefix = sourceEntitySetting.tagPrefix!.encryptedAssertion;
            const encryptAssertionDoc = parseXml(
              `<${encAssertionPrefix}:EncryptedAssertion xmlns:${encAssertionPrefix}="${namespace.names.assertion}">${res}</${encAssertionPrefix}:EncryptedAssertion>`,
            );
            doc.documentElement.replaceChild(encryptAssertionDoc.documentElement, rawAssertionNode);
            return resolve(utility.base64Encode(doc.toString()));
          });
        } else {
          return resolve(utility.base64Encode(xml));
        }
      });
    },

    /**
     * Decrypt the `<EncryptedAssertion>` inside a SAML response using the
     * local entity's private key. Returns both the decrypted document XML
     * and the raw assertion fragment for downstream extraction.
     *
     * @param here local entity performing decryption
     * @param entireXML SAML response XML containing `<EncryptedAssertion>`
     * @returns tuple `[decryptedDocumentXml, rawAssertionXml]`
     */
    decryptAssertion(here: EntityLike, entireXML: string): Promise<[string, string]> {
      return new Promise<[string, string]>((resolve, reject) => {
        if (!entireXML) {
          return reject(new Error('ERR_UNDEFINED_ASSERTION'));
        }
        const hereSetting = here.entitySetting;
        const doc = parseXml(entireXML);
        const encryptedAssertions = select(
          "/*[contains(local-name(), 'Response')]/*[local-name(.)='EncryptedAssertion']",
          doc,
        ) as Node[];
        if (!Array.isArray(encryptedAssertions) || encryptedAssertions.length === 0) {
          throw new Error('ERR_UNDEFINED_ENCRYPTED_ASSERTION');
        }
        if (encryptedAssertions.length > 1) {
          throw new Error('ERR_MULTIPLE_ASSERTION');
        }
        const encAssertionNode = encryptedAssertions[0];

        // RSA-1.5 key transport and 3DES are read from the incoming XML, so
        // reject them before any key is used (xmlenc-core1 §5.4.1).
        const allowInsecure = hereSetting.allowInsecureDecryptionAlgorithms === true;
        if (!allowInsecure) {
          const methods = select(".//*[local-name(.)='EncryptionMethod']/@Algorithm", encAssertionNode) as Attr[];
          if (methods.some(method => insecureEncryptionAlgorithms.includes(method.value))) {
            return reject(new Error('ERR_INSECURE_ENCRYPTION_ALGORITHM'));
          }
        }

        return xmlenc.decrypt(encAssertionNode.toString(), {
          key: utility.readPrivateKey(
            hereSetting.encPrivateKey as string | Buffer,
            hereSetting.encPrivateKeyPass as string | undefined,
          ),
          disallowDecryptionWithInsecureAlgorithm: !allowInsecure,
        }, (err, res) => {
          /* v8 ignore start */
          if (err) {
            console.error(err);
            return reject(new Error('ERR_EXCEPTION_OF_ASSERTION_DECRYPTION'));
          }
          if (!res) {
            return reject(new Error('ERR_UNDEFINED_ENCRYPTED_ASSERTION'));
          }
          /* v8 ignore stop */
          const rawAssertionDoc = parseXml(res);
          doc.documentElement.replaceChild(rawAssertionDoc.documentElement, encAssertionNode);
          return resolve([doc.toString(), res]);
        });
      });
    },

    /**
     * Validate the SAML XML against the registered schema validator. Throws
     * when no validator has been configured via {@link setSchemaValidator}
     * so consumers can't silently ship without schema checks.
     *
     * @param input SAML XML string
     */
    async isValidXml(input: string): Promise<unknown> {
      const { validate } = getContext();

      if (!validate) {
        return Promise.reject(new Error(
          'Your application is potentially vulnerable because no validation function found. Please read the documentation on how to setup the validator. (https://github.com/tngan/samlify#installation)',
        ));
      }

      assertPlainXml(input);
      return await validate(input);
    },
  };
};

export default libSaml();
