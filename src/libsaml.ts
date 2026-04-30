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
import xmlEscape from 'xml-escape';
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
  signatureAlgorithm?: string;
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
    tagPrefix?: Record<string, string>;
    encPrivateKey?: string | Buffer;
    encPrivateKeyPass?: string | Buffer;
  };
  entityMeta: MetadataInterface;
}

/** Public surface exposed by the libsaml singleton. */
export interface LibSamlInterface {
  getQueryParamByType: (type: string) => string;
  createXPath: (local: string | { name: string; attr: string }, isExtractAll?: boolean) => string;
  replaceTagsByValue: (rawXML: string, tagValues: TagReplacementMap) => string;
  attributeStatementBuilder: (
    attributes: LoginResponseAttribute[],
    attributeTemplate: AttributeTemplate,
    attributeStatementTemplate: AttributeStatementTemplate,
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

  /** Mapping from XML-DSig signature algorithm URIs to node-rsa schemes. */
  const nrsaAliasMapping: Record<string, SigningSchemeHash> = {
    'http://www.w3.org/2000/09/xmldsig#rsa-sha1': 'pkcs1-sha1',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'pkcs1-sha256',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': 'pkcs1-sha512',
  };

  /** Default AuthnRequest XML template. */
  const defaultLoginRequestTemplate: LoginRequestTemplate = {
    context: '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>',
  };

  /** Default LogoutRequest XML template. */
  const defaultLogoutRequestTemplate: LogoutRequestTemplate = {
    context: '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}"><saml:Issuer>{Issuer}</saml:Issuer><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID></samlp:LogoutRequest>',
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
   * Replacer for {@link replaceTagsByValue}. XML-escapes attribute values
   * but leaves element text untouched so the caller can inject nested XML.
   */
  function escapeTag(replacement: unknown): (...args: string[]) => string {
    return (_match: string, quote?: string) => {
      const text: string = replacement === null || replacement === undefined ? '' : String(replacement);
      return quote ? `${quote}${xmlEscape(text)}` : text;
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
     * replacement map. Attribute values are XML-escaped; element text is not.
     *
     * @param rawXML template with `{Tag}` placeholders
     * @param tagValues replacement map keyed by tag name
     * @returns XML with placeholders resolved
     */
    replaceTagsByValue(rawXML: string, tagValues: TagReplacementMap): string {
      Object.keys(tagValues).forEach(t => {
        rawXML = rawXML.replace(
          new RegExp(`("?)\\{${t}\\}`, 'g'),
          escapeTag(tagValues[t]),
        );
      });
      return rawXML;
    },

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
    ): string {
      const attr = attributes.map(({ name, nameFormat, valueTag, valueXsiType, valueXmlnsXs, valueXmlnsXsi }) => {
        const defaultValueXmlnsXs = 'http://www.w3.org/2001/XMLSchema';
        const defaultValueXmlnsXsi = 'http://www.w3.org/2001/XMLSchema-instance';
        let attributeLine = attributeTemplate.context;
        attributeLine = attributeLine.replace('{Name}', name);
        attributeLine = attributeLine.replace('{NameFormat}', nameFormat);
        attributeLine = attributeLine.replace('{ValueXmlnsXs}', valueXmlnsXs ? valueXmlnsXs : defaultValueXmlnsXs);
        attributeLine = attributeLine.replace('{ValueXmlnsXsi}', valueXmlnsXsi ? valueXmlnsXsi : defaultValueXmlnsXsi);
        attributeLine = attributeLine.replace('{ValueXsiType}', valueXsiType);
        attributeLine = attributeLine.replace('{Value}', `{${tagging('attr', valueTag)}}`);
        return attributeLine;
      }).join('');
      return attributeStatementTemplate.context.replace('{Attributes}', attr);
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
      const { dom } = getContext();
      const doc = dom.parseFromString(xml);

      const { dom: contextDom } = getContext();
      const docParser = contextDom;
      // Absolute XPaths defend against signature-wrapping attacks.
      const messageSignatureXpath = "/*[contains(local-name(), 'Response') or contains(local-name(), 'Request')]/*[local-name(.)='Signature']";
      const assertionSignatureXpath = "/*[contains(local-name(), 'Response') or contains(local-name(), 'Request')]/*[local-name(.)='Assertion']/*[local-name(.)='Signature']";
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

      if (selection.length === 0) {
        return [false, null];
      }

      for (const signatureNode of selection) {
        const sig = new SignedXml();
        let verified = false;

        sig.signatureAlgorithm = opts.signatureAlgorithm!;

        if (!opts.keyFile && !opts.metadata) {
          throw new Error('ERR_UNDEFINED_SIGNATURE_VERIFIER_OPTIONS');
        }

        if (opts.keyFile) {
          sig.publicCert = fs.readFileSync(opts.keyFile);
        }

        if (opts.metadata) {
          const certificateNode = toNodeArray(select(".//*[local-name(.)='X509Certificate']", signatureNode));
          let metadataCert: string | string[] | undefined = opts.metadata.getX509Certificate(certUse.signing);
          if (Array.isArray(metadataCert)) {
            metadataCert = flattenDeep<string>(metadataCert as string[]);
          } else if (typeof metadataCert === 'string') {
            metadataCert = [metadataCert];
          }
          metadataCert = (metadataCert as string[]).map(utility.normalizeCerString);

          if (certificateNode.length === 0 && metadataCert.length === 0) {
            throw new Error('NO_SELECTED_CERTIFICATE');
          }

          if (certificateNode.length !== 0) {
            const certEl = certificateNode[0] as Element;
            const x509CertificateData = certEl.textContent ?? '';
            const x509Certificate = utility.normalizeCerString(x509CertificateData);

            if (
              metadataCert.length >= 1 &&
              !metadataCert.find(cert => cert.trim() === x509Certificate.trim())
            ) {
              throw new Error('ERROR_UNMATCH_CERTIFICATE_DECLARATION_IN_METADATA');
            }

            sig.publicCert = this.getKeyInfo(x509Certificate).getKey();
          } else {
            sig.publicCert = this.getKeyInfo(metadataCert[0]).getKey();
          }
        }

        sig.loadSignature(signatureNode);

        verified = sig.checkSignature(doc.toString());

        if (!verified) {
          continue;
        }
        if (!(sig.getSignedReferences().length >= 1)) {
          throw new Error('NO_SIGNATURE_REFERENCES');
        }
        const signedVerifiedXML = sig.getSignedReferences()[0];
        const rootNode = docParser.parseFromString(signedVerifiedXML, 'text/xml').documentElement;

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
      const signCert = metadata.getX509Certificate(certUse.signing) as string;
      const signingScheme = getSigningScheme(verifyAlgorithm);
      const key = new nrsa(utility.getPublicKeyPemFromCertificate(signCert), 'public', { signingScheme });
      return key.verify(Buffer.from(octetString), Buffer.from(signature));
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
          return `<${prefix}X509Data><${prefix}X509Certificate>${x509Certificate}</${prefix}X509Certificate></${prefix}X509Data>`;
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
        const { dom } = getContext();
        const doc = dom.parseFromString(xml);
        const assertions = select("//*[local-name(.)='Assertion']", doc) as Node[];
        if (!Array.isArray(assertions) || assertions.length === 0) {
          throw new Error('ERR_NO_ASSERTION');
        }
        if (assertions.length > 1) {
          throw new Error('ERR_MULTIPLE_ASSERTION');
        }
        const rawAssertionNode = assertions[0];

        if (sourceEntitySetting.isAssertionEncrypted) {
          const encryptCert = targetEntityMetadata.getX509Certificate(certUse.encrypt) as string;
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
            const encryptAssertionDoc = dom.parseFromString(
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
        const { dom } = getContext();
        const doc = dom.parseFromString(entireXML);
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

        return xmlenc.decrypt(encAssertionNode.toString(), {
          key: utility.readPrivateKey(
            hereSetting.encPrivateKey as string | Buffer,
            hereSetting.encPrivateKeyPass as string | undefined,
          ),
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
          const rawAssertionDoc = dom.parseFromString(res);
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

      return await validate(input);
    },
  };
};

export default libSaml();
