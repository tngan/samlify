/**
* @file SamlLib.js
* @author tngan
* @desc  A simple library including some common functions
*/

import { DOMParser } from 'xmldom';
import utility, { flattenDeep, isString } from './utility';
import { algorithms, wording, namespace } from './urn';
import { select, SelectedValue } from 'xpath';
import { MetadataInterface } from './metadata';
import * as nrsa from 'node-rsa';
import { SignedXml, FileKeyInfo } from 'xml-crypto';
import * as xmlenc from '@authenio/xml-encryption';
import { extract } from './extractor';
import { getValidatorModule, SchemaValidator } from './schema-validator';
import camelCase from 'camelcase';

const signatureAlgorithms = algorithms.signature;
const digestAlgorithms = algorithms.digest;
const certUse = wording.certUse;
const urlParams = wording.urlParams;
const dom = DOMParser;

export interface SignatureConstructor {
  rawSamlMessage: string;
  referenceTagXPath?: string;
  privateKey: string;
  privateKeyPass?: string;
  signatureAlgorithm: string;
  signingCert: string | Buffer;
  isBase64Output?: boolean;
  signatureConfig?: any;
  isMessageSigned?: boolean;
  transformationAlgorithms?: string[];
}

export interface SignatureVerifierOptions {
  cert?: MetadataInterface;
  signatureAlgorithm?: string;
  keyFile?: string;
}

export interface ExtractorResult {
  [key: string]: any;
  signature?: string | string[];
  issuer?: string | string[];
  nameid?: string;
  notexist?: boolean;
}

export interface LoginResponseAttribute {
  name: string;
  nameFormat: string; //
  valueXsiType: string; //
  valueTag: string;
}

export interface BaseSamlTemplate {
  context: string;
}

export interface LoginResponseTemplate extends BaseSamlTemplate {
  attributes?: LoginResponseAttribute[];
}
export interface LoginRequestTemplate extends BaseSamlTemplate { }

export interface LogoutRequestTemplate extends BaseSamlTemplate { }

export interface LogoutResponseTemplate extends BaseSamlTemplate { }

export type KeyUse = 'signing' | 'encryption';

export interface KeyComponent {
  [key: string]: any;
}

export interface LibSamlInterface {
  getQueryParamByType: (type: string) => string;
  createXPath: (local, isExtractAll?: boolean) => string;
  replaceTagsByValue: (rawXML: string, tagValues: any) => string;
  attributeStatementBuilder: (attributes: LoginResponseAttribute[]) => string;
  constructSAMLSignature: (opts: SignatureConstructor) => string;
  verifySignature: (xml: string, opts) => [boolean, any];
  createKeySection: (use: KeyUse, cert: string | Buffer) => {};
  constructMessageSignature: (octetString: string, key: string, passphrase?: string, isBase64?: boolean, signingAlgorithm?: string) => string;
  verifyMessageSignature: (metadata, octetString: string, signature: string | Buffer, verifyAlgorithm?: string) => boolean;
  getKeyInfo: (x509Certificate: string, signatureConfig?: any) => void;
  encryptAssertion: (sourceEntity, targetEntity, entireXML: string) => Promise<string>;
  decryptAssertion: (here, entireXML: string) => Promise<[string, any]>;

  getSigningScheme: (sigAlg: string) => string | null;
  getDigestMethod: (sigAlg: string) => string | null;

  nrsaAliasMapping: any;
  defaultLoginRequestTemplate: LoginRequestTemplate;
  defaultLoginResponseTemplate: LoginResponseTemplate;
  defaultLogoutRequestTemplate: LogoutRequestTemplate;
  defaultLogoutResponseTemplate: LogoutResponseTemplate;
}

const libSaml = () => {

  /**
  * @desc helper function to get back the query param for redirect binding for SLO/SSO
  * @type {string}
  */
  function getQueryParamByType(type: string) {
    if ([urlParams.logoutRequest, urlParams.samlRequest].indexOf(type) !== -1) {
      return 'SAMLRequest';
    }
    if ([urlParams.logoutResponse, urlParams.samlResponse].indexOf(type) !== -1) {
      return 'SAMLResponse';
    }
    throw new Error('ERR_UNDEFINED_QUERY_PARAMS');
  }
  /**
   *
   */
  const nrsaAliasMapping = {
    'http://www.w3.org/2000/09/xmldsig#rsa-sha1': 'sha1',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'sha256',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': 'sha512',
  };
  /**
  * @desc Default login request template
  * @type {LoginRequestTemplate}
  */
  const defaultLoginRequestTemplate = {
    context: '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>',
  };
  /**
  * @desc Default logout request template
  * @type {LogoutRequestTemplate}
  */
  const defaultLogoutRequestTemplate = {
    context: '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}"><saml:Issuer>{Issuer}</saml:Issuer><saml:NameID SPNameQualifier="{EntityID}" Format="{NameIDFormat}">{NameID}</saml:NameID></samlp:LogoutRequest>',
  };
  /**
  * @desc Default login response template
  * @type {LoginResponseTemplate}
  */
  const defaultLoginResponseTemplate = {
    context: '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AuthnStatement}{AttributeStatement}</saml:Assertion></samlp:Response>',
    attributes: [],
  };
  /**
  * @desc Default logout response template
  * @type {LogoutResponseTemplate}
  */
  const defaultLogoutResponseTemplate = {
    context: '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status></samlp:LogoutResponse>',
  };
  /**
  * @private
  * @desc Get the signing scheme alias by signature algorithms, used by the node-rsa module
  * @param {string} sigAlg    signature algorithm
  * @return {string/null} signing algorithm short-hand for the module node-rsa
  */
  function getSigningScheme(sigAlg?: string): string | null {
    if (sigAlg) {
      const algAlias = nrsaAliasMapping[sigAlg];
      if (!(algAlias === undefined)) {
        return algAlias;
      }
    }
    return nrsaAliasMapping[signatureAlgorithms.RSA_SHA1]; // default value
  }
  /**
  * @private
  * @desc Get the digest algorithms by signature algorithms
  * @param {string} sigAlg    signature algorithm
  * @return {string/null} digest algorithm
  */
  function getDigestMethod(sigAlg: string): string | null {
    const digestAlg = digestAlgorithms[sigAlg];
    if (!(digestAlg === undefined)) {
      return digestAlg;
    }
    return null; // default value
  }
  /**
  * @public
  * @desc Create XPath
  * @param  {string/object} local     parameters to create XPath
  * @param  {boolean} isExtractAll    define whether returns whole content according to the XPath
  * @return {string} xpath
  */
  function createXPath(local, isExtractAll?: boolean): string {
    if (isString(local)) {
      return isExtractAll === true ? "//*[local-name(.)='" + local + "']/text()" : "//*[local-name(.)='" + local + "']";
    }
    return "//*[local-name(.)='" + local.name + "']/@" + local.attr;
  }

  /**
   * @private
   * @desc Tag normalization
   * @param {string} prefix     prefix of the tag
   * @param {content} content   normalize it to capitalized camel case
   * @return {string}
   */
  function tagging(prefix: string, content: string): string {
    const camelContent = camelCase(content);
    return prefix + camelContent.charAt(0).toUpperCase() + camelContent.slice(1);
  }

  return {

    createXPath,
    getQueryParamByType,
    defaultLoginRequestTemplate,
    defaultLoginResponseTemplate,
    defaultLogoutRequestTemplate,
    defaultLogoutResponseTemplate,

    /**
    * @desc Repalce the tag (e.g. {tag}) inside the raw XML
    * @param  {string} rawXML      raw XML string used to do keyword replacement
    * @param  {array} tagValues    tag values
    * @return {string}
    */
    replaceTagsByValue(rawXML: string, tagValues: any): string {
      Object.keys(tagValues).forEach(t => {
        rawXML = rawXML.replace(new RegExp(`{${t}}`, 'g'), tagValues[t]);
      });
      return rawXML;
    },
    /**
    * @desc Helper function to build the AttributeStatement tag
    * @param  {LoginResponseAttribute} attributes    an array of attribute configuration
    * @return {string}
    */
    attributeStatementBuilder(attributes: LoginResponseAttribute[]): string {
      const attr = attributes.map(({ name, nameFormat, valueTag, valueXsiType }) => {
        return `<saml:Attribute Name="${name}" NameFormat="${nameFormat}"><saml:AttributeValue xsi:type="${valueXsiType}">{${tagging('attr', valueTag)}}</saml:AttributeValue></saml:Attribute>`;
      }).join('');
      return `<saml:AttributeStatement>${attr}</saml:AttributeStatement>`;
    },
    /**
    * @desc Construct the XML signature for POST binding
    * @param  {string} rawSamlMessage      request/response xml string
    * @param  {string} referenceTagXPath    reference uri
    * @param  {string} privateKey           declares the private key
    * @param  {string} passphrase           passphrase of the private key [optional]
    * @param  {string|buffer} signingCert   signing certificate
    * @param  {string} signatureAlgorithm   signature algorithm
    * @param  {string[]} transformationAlgorithms   canonicalization and transformation Algorithms
    * @return {string} base64 encoded string
    */
    constructSAMLSignature(opts: SignatureConstructor) {
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
      // Add assertion sections as reference
      if (referenceTagXPath) {
        sig.addReference(
          referenceTagXPath,
          opts.transformationAlgorithms,
          getDigestMethod(signatureAlgorithm)
        );
      }
      if (isMessageSigned) {
        sig.addReference(
          // reference to the root node
          '/*',
          transformationAlgorithms,
          getDigestMethod(signatureAlgorithm),
          '',
          '',
          '',
          false,
        );
      }
      sig.signatureAlgorithm = signatureAlgorithm;
      sig.keyInfoProvider = new this.getKeyInfo(signingCert, signatureConfig);
      sig.signingKey = utility.readPrivateKey(privateKey, privateKeyPass, true);
      if (signatureConfig) {
        sig.computeSignature(rawSamlMessage, signatureConfig);
      } else {
        sig.computeSignature(rawSamlMessage);
      }
      return isBase64Output !== false ? utility.base64Encode(sig.getSignedXml()) : sig.getSignedXml();
    },
    /**
    * @desc Verify the XML signature
    * @param  {string} xml xml
    * @param  {signature} signature context of XML signature
    * @param  {SignatureVerifierOptions} opts cert declares the X509 certificate
    * @return {boolean} verification result
    */
    verifySignature(xml: string, opts: SignatureVerifierOptions) {

      const doc = new dom().parseFromString(xml);
      // In order to avoid the wrapping attack, we have changed to use absolute xpath instead of naively fetching the signature element
      // message signature (logout response / saml response)
      const messageSignatureXpath = "/*[contains(local-name(), 'Response') or contains(local-name(), 'Request')]/*[local-name(.)='Signature']";
      // assertion signature (logout response / saml response)
      const assertionSignatureXpath = "/*[contains(local-name(), 'Response') or contains(local-name(), 'Request')]/*[local-name(.)='Assertion']/*[local-name(.)='Signature']";
      // check if there is a potential malicious wrapping signature
      const wrappingElementsXPath = "/*[contains(local-name(), 'Response')]/*[local-name(.)='Assertion']/*[local-name(.)='Subject']/*[local-name(.)='SubjectConfirmation']/*[local-name(.)='SubjectConfirmationData']//*[local-name(.)='Assertion' or local-name(.)='Signature']";

      // select the signature node
      let selection: any = [];
      let assertionNode: string | null = null;
      const messageSignatureNode = select(messageSignatureXpath, doc);
      const assertionSignatureNode = select(assertionSignatureXpath, doc);
      const wrappingElementNode = select(wrappingElementsXPath, doc);

      selection = selection.concat(messageSignatureNode);
      selection = selection.concat(assertionSignatureNode);

      // try to catch potential wrapping attack
      if (wrappingElementNode.length !== 0) {
        throw new Error('ERR_POTENTIAL_WRAPPING_ATTACK');
      }

      // guarantee to have a signature in saml response
      if (selection.length === 0) {
        throw new Error('ERR_ZERO_SIGNATURE');
      }

      const sig = new SignedXml();
      let verified = true;
      // need to refactor later on
      selection.forEach(signatureNode => {
        sig.signatureAlgorithm = opts.signatureAlgorithm;
        if (opts.keyFile) {
          sig.keyInfoProvider = new FileKeyInfo(opts.keyFile);
        } else if (opts.cert) {

          const certificateNode = select(".//*[local-name(.)='X509Certificate']", signatureNode) as any;
          
          // certificate in metadata
          let metadataCert: any = opts.cert.getX509Certificate(certUse.signing);
          if (typeof metadataCert === 'string') {
            metadataCert = [metadataCert];
          } else if (metadataCert instanceof Array) {
            // flattens the nested array of Certificates from each KeyDescriptor
            metadataCert = flattenDeep(metadataCert);
          }
          metadataCert = metadataCert.map(utility.normalizeCerString);

          // use the first 
          let selectedCert = metadataCert[0];
          // no certificate node in response
          if (certificateNode.length !== 0) {
            const x509CertificateData = certificateNode[0].firstChild.data;
            const x509Certificate = utility.normalizeCerString(x509CertificateData);
            selectedCert = x509Certificate;
          }

          if (selectedCert === null) {
            throw new Error('NO_SELECTED_CERTIFICATE');
          }
          if (metadataCert.length >= 1 && !metadataCert.find(cert => cert === selectedCert)) {
            // keep this restriction for rolling certificate usage
            // to make sure the response certificate is one of those specified in metadata
            throw new Error('ERROR_UNMATCH_CERTIFICATE_DECLARATION_IN_METADATA');
          }
          sig.keyInfoProvider = new this.getKeyInfo(selectedCert);
        } else {
          throw new Error('ERR_UNDEFINED_SIGNATURE_VERIFIER_OPTIONS');
        }
        sig.loadSignature(signatureNode);

        doc.removeChild(signatureNode);

        verified = verified && sig.checkSignature(doc.toString());

        // immediately throw error when any one of the signature is failed to get verified
        if (!verified) {
          throw new Error('ERR_FAILED_TO_VERIFY_SIGNATURE');
        }

      });

      // response must be signed, either entire document or assertion
      // default we will take the assertion section under root
      if (messageSignatureNode.length === 1) {
        const node = select("/*[contains(local-name(), 'Response') or contains(local-name(), 'Request')]/*[local-name(.)='Assertion']", doc);
        if (node.length === 1) {
          assertionNode = node[0].toString();
        }
      }

      if (assertionSignatureNode.length === 1) {
        const verifiedAssertionInfo = extract(assertionSignatureNode[0].toString(), [{
          key: 'refURI',
          localPath: ['Signature', 'SignedInfo', 'Reference'],
          attributes: ['URI']
        }]);
        // get the assertion supposed to be the one should be verified
        const desiredAssertionInfo = extract(doc.toString(), [{
          key: 'id',
          localPath: ['~Response', 'Assertion'],
          attributes: ['ID']
        }]);
        // 5.4.2 References
        // SAML assertions and protocol messages MUST supply a value for the ID attribute on the root element of
        // the assertion or protocol message being signed. The assertion’s or protocol message's root element may
        // or may not be the root element of the actual XML document containing the signed assertion or protocol
        // message (e.g., it might be contained within a SOAP envelope).
        // Signatures MUST contain a single <ds:Reference> containing a same-document reference to the ID
        // attribute value of the root element of the assertion or protocol message being signed. For example, if the
        // ID attribute value is "foo", then the URI attribute in the <ds:Reference> element MUST be "#foo".
        if (verifiedAssertionInfo.refURI !== `#${desiredAssertionInfo.id}`) {
          throw new Error('ERR_POTENTIAL_WRAPPING_ATTACK');
        }
        const verifiedDoc = extract(doc.toString(), [{
          key: 'assertion',
          localPath: ['~Response', 'Assertion'],
          attributes: [],
          context: true
        }]);
        assertionNode = verifiedDoc.assertion.toString();
      }

      return [verified, assertionNode];
    },
    /**
    * @desc Helper function to create the key section in metadata (abstraction for signing and encrypt use)
    * @param  {string} use          type of certificate (e.g. signing, encrypt)
    * @param  {string} certString    declares the certificate String
    * @return {object} object used in xml module
    */
    createKeySection(use: KeyUse, certString: string | Buffer): KeyComponent {
      return {
        ['KeyDescriptor']: [
          {
            _attr: { use },
          },
          {
            ['ds:KeyInfo']: [
              {
                _attr: {
                  'xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
                },
              },
              {
                ['ds:X509Data']: [{
                  'ds:X509Certificate': utility.normalizeCerString(certString),
                }],
              },
            ],
          }],
      };
    },
    /**
    * @desc Constructs SAML message
    * @param  {string} octetString               see "Bindings for the OASIS Security Assertion Markup Language (SAML V2.0)" P.17/46
    * @param  {string} key                       declares the pem-formatted private key
    * @param  {string} passphrase                passphrase of private key [optional]
    * @param  {string} signingAlgorithm          signing algorithm
    * @return {string} message signature
    */
    constructMessageSignature(octetString: string, key: string, passphrase?: string, isBase64?: boolean, signingAlgorithm?: string) {
      // Default returning base64 encoded signature
      // Embed with node-rsa module
      const decryptedKey = new nrsa(utility.readPrivateKey(key, passphrase), {
        signingScheme: getSigningScheme(signingAlgorithm),
      });
      const signature = decryptedKey.sign(octetString);
      // Use private key to sign data
      return isBase64 !== false ? signature.toString('base64') : signature;
    },
    /**
    * @desc Verifies message signature
    * @param  {Metadata} metadata                 metadata object of identity provider or service provider
    * @param  {string} octetString                see "Bindings for the OASIS Security Assertion Markup Language (SAML V2.0)" P.17/46
    * @param  {string} signature                  context of XML signature
    * @param  {string} verifyAlgorithm            algorithm used to verify
    * @return {boolean} verification result
    */
    verifyMessageSignature(metadata, octetString: string, signature: string | Buffer, verifyAlgorithm?: string) {
      const signCert = metadata.getX509Certificate(certUse.signing);
      const signingScheme = getSigningScheme(verifyAlgorithm);
      const key = new nrsa(utility.getPublicKeyPemFromCertificate(signCert), { signingScheme });
      return key.verify(new Buffer(octetString), signature);
    },
    /**
    * @desc Get the public key in string format
    * @param  {string} x509Certificate certificate
    * @return {string} public key
    */
    getKeyInfo(x509Certificate: string, signatureConfig: any = {}) {
      this.getKeyInfo = key => {
        const prefix = signatureConfig.prefix ? `${signatureConfig.prefix}:` : '';
        return `<${prefix}X509Data><${prefix}X509Certificate>${x509Certificate}</${prefix}X509Certificate></${prefix}X509Data>`;
      };
      this.getKey = keyInfo => {
        return utility.getPublicKeyPemFromCertificate(x509Certificate).toString();
      };
    },
    /**
    * @desc Encrypt the assertion section in Response
    * @param  {Entity} sourceEntity             source entity
    * @param  {Entity} targetEntity             target entity
    * @param  {string} xml                      response in xml string format
    * @return {Promise} a promise to resolve the finalized xml
    */
    encryptAssertion(sourceEntity, targetEntity, xml?: string) {
      // Implement encryption after signature if it has
      return new Promise<string>((resolve, reject) => {

        if (!xml) {
          return reject(new Error('ERR_UNDEFINED_ASSERTION'));
        }

        const sourceEntitySetting = sourceEntity.entitySetting;
        const targetEntityMetadata = targetEntity.entityMeta;
        const doc = new dom().parseFromString(xml);
        const assertions = select("//*[local-name(.)='Assertion']", doc) as Node[];
        if (!Array.isArray(assertions)) {
          throw new Error('ERR_NO_ASSERTION');
        }
        if (assertions.length !== 1) {
          throw new Error('ERR_MULTIPLE_ASSERTION');
        }
        // Perform encryption depends on the setting, default is false
        if (sourceEntitySetting.isAssertionEncrypted) {
          xmlenc.encrypt(assertions[0].toString(), {
            // use xml-encryption module
            rsa_pub: new Buffer(utility.getPublicKeyPemFromCertificate(targetEntityMetadata.getX509Certificate(certUse.encrypt)).replace(/\r?\n|\r/g, '')), // public key from certificate
            pem: new Buffer('-----BEGIN CERTIFICATE-----' + targetEntityMetadata.getX509Certificate(certUse.encrypt) + '-----END CERTIFICATE-----'),
            encryptionAlgorithm: sourceEntitySetting.dataEncryptionAlgorithm,
            keyEncryptionAlgorighm: sourceEntitySetting.keyEncryptionAlgorithm,
          }, (err, res) => {
            if (err) {
              console.error(err);
              return reject(new Error('ERR_EXCEPTION_OF_ASSERTION_ENCRYPTION'));
            }
            if (!res) {
              return reject(new Error('ERR_UNDEFINED_ENCRYPTED_ASSERTION'));
            }
            const { encryptedAssertion: encAssertionPrefix } = sourceEntitySetting.tagPrefix;
            const encryptAssertionNode = new dom().parseFromString(`<${encAssertionPrefix}:EncryptedAssertion xmlns:${encAssertionPrefix}="${namespace.names.assertion}">${res}</${encAssertionPrefix}:EncryptedAssertion>`);
            doc.replaceChild(encryptAssertionNode, assertions[0]);
            return resolve(utility.base64Encode(doc.toString()));
          });
        } else {
          return resolve(utility.base64Encode(xml)); // No need to do encrpytion
        }
      });
    },
    /**
    * @desc Decrypt the assertion section in Response
    * @param  {string} type             only accept SAMLResponse to proceed decryption
    * @param  {Entity} here             this entity
    * @param  {Entity} from             from the entity where the message is sent
    * @param {string} entireXML         response in xml string format
    * @return {function} a promise to get back the entire xml with decrypted assertion
    */
    decryptAssertion(here, entireXML: string) {
      return new Promise<[string, any]>((resolve, reject) => {
        // Implement decryption first then check the signature
        if (!entireXML) {
          return reject(new Error('ERR_UNDEFINED_ASSERTION'));
        }
        // Perform encryption depends on the setting of where the message is sent, default is false
        const hereSetting = here.entitySetting;
        const xml = new dom().parseFromString(entireXML);
        const encryptedAssertions = select("/*[contains(local-name(), 'Response')]/*[local-name(.)='EncryptedAssertion']", xml) as Node[];
        if (!Array.isArray(encryptedAssertions)) {
          throw new Error('ERR_UNDEFINED_ENCRYPTED_ASSERTION');
        }
        if (encryptedAssertions.length !== 1) {
          throw new Error('ERR_MULTIPLE_ASSERTION');
        }
        return xmlenc.decrypt(encryptedAssertions[0].toString(), {
          key: utility.readPrivateKey(hereSetting.encPrivateKey, hereSetting.encPrivateKeyPass),
        }, (err, res) => {
          if (err) {
            console.error(err);
            return reject(new Error('ERR_EXCEPTION_OF_ASSERTION_DECRYPTION'));
          }
          if (!res) {
            return reject(new Error('ERR_UNDEFINED_ENCRYPTED_ASSERTION'));
          }
          const assertionNode = new dom().parseFromString(res);
          xml.replaceChild(assertionNode, encryptedAssertions[0]);
          return resolve([xml.toString(), res]);
        });
      });
    },
    /**
     * @desc Check if the xml string is valid and bounded
     */
    async isValidXml(input: string) {
      try {
        await mod!.validate(input);
        return Promise.resolve();
      } catch (e) {
        throw e;
      }
    },
  };
};

// load the validator module before the function runtime
let mod: SchemaValidator | null = null;
(async () => mod = await getValidatorModule())();

export default libSaml();
