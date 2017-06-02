/**
* @file SamlLib.js
* @author tngan
* @desc  A simple library including some common functions
*/

import { DOMParser } from 'xmldom';
import * as fs from 'fs';
import { pki } from 'node-forge';
import utility from './utility';
import { tags, algorithms, wording } from './urn';
import xpath, { select } from 'xpath';
import * as camel from 'camelcase';
import { MetadataInterface } from './metadata'
import { isString, isObject, isUndefined } from 'lodash';

const nrsa = require('node-rsa');
const xml = require('xml');
const xmlenc = require('xml-encryption');
const signatureAlgorithms = algorithms.signature;
const digestAlgorithms = algorithms.digest;
const certUse = wording.certUse;
const requestTags = tags.request;
const urlParams = wording.urlParams;
const dom = DOMParser;

let { SignedXml, FileKeyInfo } = require('xml-crypto');

export interface SignatureConstructor {
  rawSamlMessage: string;
  referenceTagXPath: string;
  privateKey: string;
  privateKeyPass: string;
  signatureAlgorithm: string;
  signingCert: string | Buffer;
  isBase64Output?: boolean;
  messageSignatureConfig?: any;
}

interface SignatureVerifierOptions {
  cert?: MetadataInterface;
  signatureAlgorithm?: string;
  keyFile?: string;
}

interface ExtractorResult {
  [key: string]: any;
  signature?: any;
  issuer?: string;
  nameid?: string;
  notexist?: boolean;
}

interface LoginResponseAttribute {
  name: string;
  nameFormat: string; //
  valueXsiType: string; //
  valueTag: string;
}

export interface BaseSamlTemplate {
  context: string;
}

export interface LoginResponseTemplate extends BaseSamlTemplate {
  attributes?: Array<LoginResponseAttribute>;
}
export interface LoginRequestTemplate extends BaseSamlTemplate {}

export interface LogoutRequestTemplate extends BaseSamlTemplate {}

export interface LogoutResponseTemplate extends BaseSamlTemplate {}

export interface LibSamlInterface {
  getQueryParamByType: (type: string) => string;
  createXPath: (local, isExtractAll?: boolean) => string;
  replaceTagsByValue: (rawXML: string, tagValues: any) => string;
  attributeStatementBuilder: (attributes: Array<LoginResponseAttribute>) => string;
  constructSAMLSignature: (opts: SignatureConstructor) => string;
  verifySignature: (xml: string, signature, opts) => boolean;
  extractor: (xmlString: string, fields) => ExtractorResult;
  createKeySection: (use: string, cert: string | Buffer) => {};
  constructMessageSignature: (octetString: string, key: string, passphrase?: string, isBase64?: boolean, signingAlgorithm?: string) => string;
  verifyMessageSignature: (metadata, octetString: string, signature: string | Buffer, verifyAlgorithm?: string) => boolean;
  getKeyInfo: (x509Certificate: string) => void;
  encryptAssertion: (sourceEntity, targetEntity, entireXML: string) => Promise<string>;
  decryptAssertion: (type: string, here, from, entireXML: string) => Promise<string>;

  getSigningScheme: (sigAlg: string) => string | null;
  getDigestMethod: (sigAlg: string) => string | null;
  getAttribute: (xmlDoc, localName: string, attribute: string) => string;
  getAttributes: (xmlDoc, localName: string, attributes: Array<string>) => string | [string];
  getInnerTextWithOuterKey: (xmlDoc, localName: string, localNameKey: string, valueTag: string) => any;
  getAttributeKey: (xmlDoc, localName: string, localNameKey: string, attributeTag: string) => any;
  getEntireBody: (xmlDoc, localName: string, isOutputString?: boolean) => any;
  getInnerText: (xmlDoc, localName: string) => string | [string];

  nrsaAliasMapping: any;
  defaultLoginRequestTemplate: LoginRequestTemplate;
  defaultLoginResponseTemplate: LoginResponseTemplate;
  defaultLogoutRequestTemplate: LogoutRequestTemplate;
  defaultLogoutResponseTemplate: LogoutResponseTemplate;
}

const libSaml = function () {
  /**
  * @desc helper function to get back the query param for redirect binding for SLO/SSO
  * @type {string}
  */
  function getQueryParamByType(type: string) {
    if ([urlParams.logoutRequest, urlParams.samlRequest].indexOf(type) !== -1) {
      return urlParams.samlRequest;
    }
    if ([urlParams.logoutResponse, urlParams.samlResponse].indexOf(type) !== -1) {
      return urlParams.samlResponse;
    }
    throw new Error('undefined parserType');
  }
  /**
   *
   */
  const nrsaAliasMapping = {
    'http://www.w3.org/2000/09/xmldsig#rsa-sha1': 'sha1',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'sha256',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': 'sha512'
  };
  /**
  * @desc Default login request template
  * @type {LoginRequestTemplate}
  */
  const defaultLoginRequestTemplate = {
    context: '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>'
  };
  /**
  * @desc Default logout request template
  * @type {LogoutRequestTemplate}
  */
  const defaultLogoutRequestTemplate = {
    context: '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}"><saml:Issuer>{Issuer}</saml:Issuer><saml:NameID SPNameQualifier="{EntityID}" Format="{NameIDFormat}">{NameID}</saml:NameID></samlp:LogoutRequest>'
  };
  /**
  * @desc Default login response template
  * @type {LoginResponseTemplate}
  */
  const defaultLoginResponseTemplate = {
    context: '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status><saml:Assertion ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AuthnStatement}{AttributeStatement}</saml:Assertion></samlp:Response>',
    attributes: []
  };
  /**
  * @desc Default logout response template
  * @type {LogoutResponseTemplate}
  */
  const defaultLogoutResponseTemplate = {
    context: '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status></samlp:LogoutResponse>'
  };
  /**
  * @private
  * @desc Get the signing scheme alias by signature algorithms, used by the node-rsa module
  * @param {string} sigAlg    signature algorithm
  * @return {string/null} signing algorithm short-hand for the module node-rsa
  */
  function getSigningScheme(sigAlg?: string): string | null {
    const algAlias = nrsaAliasMapping[sigAlg];
    if (!isUndefined(algAlias)) {
      return algAlias;
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
    let digestAlg = digestAlgorithms[sigAlg];
    if (!isUndefined(digestAlg)) {
      return digestAlg;
    }
    return null; // default value
  }
  /**
  * @private
  * @desc Helper function used by another private function: getAttributes
  * @param  {xml} xmlDoc          used xml document
  * @param  {string} localName    tag name without prefix
  * @param  {string} attribute    name of attribute
  * @return {string} attribute value
  */
  function getAttribute(xmlDoc, localName: string, attribute: string): string {
    let xpathStr = createXPath({
      name: localName,
      attr: attribute
    });
    let selection = select(xpathStr, xmlDoc);

    if (selection.length !== 1) {
      return undefined;
    } else {
      return selection[0].nodeValue.toString();
    }
  }
  /**
  * @private
  * @desc Get the attibutes
  * @param  {xml} xmlDoc              used xml document
  * @param  {string} localName        tag name without prefix
  * @param  {[string]} attributes     array consists of name of attributes
  * @return {string/array}
  */
  function getAttributes(xmlDoc, localName: string, attributes: Array<string>) {
    let xpathStr = createXPath(localName);
    let selection = select(xpathStr, xmlDoc);
    let data = [];
    if (selection.length === 0) {
      return undefined;
    }
    selection.forEach(s => {
      let dat = {};
      let doc = new dom().parseFromString(String(s));
      attributes.forEach(attr => {
        dat[attr.toLowerCase()] = getAttribute(doc, localName, attr);
      });
      data.push(dat);
    });
    return data.length === 1 ? data[0] : data;
  }
  /**
  * @private
  * @desc Helper function used to return result with complex format
  * @param  {xml} xmlDoc              used xml document
  * @param  {string} localName        tag name without prefix
  * @param  {string} localNameKey     key associated with tag name
  * @param  {string} valueTag         tag of the value
  */
  function getInnerTextWithOuterKey(xmlDoc, localName: string, localNameKey: string, valueTag: string) {
    let xpathStr = createXPath(localName);
    let selection = select(xpathStr, xmlDoc);
    let obj = {};

    selection.forEach(function (_s) {
      let xd = new dom().parseFromString(_s.toString());
      let key = select("//*[local-name(.)='" + localName + "']/@" + localNameKey, xd);
      let value = select("//*[local-name(.)='" + valueTag + "']/text()", xd);
      let res;

      if (key && key.length == 1 && utility.isNonEmptyArray(value)) {
        if (value.length == 1) {
          res = value[0].nodeValue.toString();
        } else {
          let dat = [];
          value.forEach(v => dat.push(String(v.nodeValue)));
          res = dat;
        }
        obj[key[0].nodeValue.toString()] = res;
      } else {
        //console.warn('Multiple keys or null value is found');
      }
    });
    return Object.keys(obj).length === 0 ? undefined : obj;
  }
  /**
  * @private
  * @desc  Get the attribute according to the key
  * @param  {string} localName            tag name without prefix
  * @param  {string} localNameKey         key associated with tag name
  * @param  {string} attributeTag         tag of the attribute
  */
  function getAttributeKey(xmlDoc, localName: string, localNameKey: string, attributeTag: string) {
    let xpathStr = createXPath(localName);
    let selection = select(xpathStr, xmlDoc);
    let data = [];

    selection.forEach(function (_s) {
      let xd = new dom().parseFromString(_s.toString());
      let key = select("//*[local-name(.)='" + localName + "']/@" + localNameKey, xd);
      let value = select("//*[local-name(.)='" + localName + "']/@" + attributeTag, xd);

      if (value && value.length == 1 && key && key.length == 1) {
        let obj = {};
        obj[key[0].nodeValue.toString()] = value[0].nodeValue.toString();
        data.push(obj);
      } else {
        //console.warn('Multiple keys or null value is found');
      }
    });
    return data.length === 0 ? undefined : data;
  }
  /**
  * @private
  * @desc Get the entire body according to the XPath
  * @param  {xml} xmlDoc              used xml document
  * @param  {string} localName        tag name without prefix
  * @param  {boolean} isOutputString  output is string format (default is true)
  * @return {string/array}
  */
  function getEntireBody(xmlDoc, localName: string, isOutputString?: boolean) {
    let xpathStr = createXPath(localName);
    let selection = select(xpathStr, xmlDoc);
    if (selection.length === 0) {
      return undefined;
    }
    let data = [];
    selection.forEach(function (_s) {
      data.push(utility.convertToString(_s, isOutputString !== false));
    });
    return data.length === 1 ? data[0] : data;
  }
  /**
  * @private
  * @desc  Get the inner xml according to the XPath
  * @param  {xml} xmlDoc          used xml document
  * @param  {string} localName    tag name without prefix
  * @return {string/array} value
  */
  function getInnerText(xmlDoc, localName: string) {
    let xpathStr = createXPath(localName, true);
    let selection = select(xpathStr, xmlDoc);
    if (selection.length === 0) {
      return undefined;
    }
    let data = [];
    selection.forEach(function (_s) {
      data.push(_s.nodeValue.toString());
    });
    return data.length === 1 ? data[0] : data;
  }
  /**
  * @public
  * @desc Create XPath
  * @param  {string/object} local     parameters to create XPath
  * @param  {boolean} isExtractAll    define whether returns whole content according to the XPath
  * @return {string} xpath
  */
  function createXPath(local, isExtractAll?: boolean): string {
    if (isObject(local)) {
      return "//*[local-name(.)='" + local.name + "']/@" + local.attr;
    }
    return isExtractAll === true ? "//*[local-name(.)='" + local + "']/text()" : "//*[local-name(.)='" + local + "']";
  }
  /**
   * @private
   * @desc Tag normalization
   * @param {string} prefix     prefix of the tag
   * @param {content} content   normalize it to capitalized camel case
   * @return {string}
   */
  function tagging(prefix: string, content: string): string {
    let camelContent = camel(content);
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
    replaceTagsByValue: function (rawXML: string, tagValues: any): string {
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
    attributeStatementBuilder: function (attributes: Array<LoginResponseAttribute>): string {
      const attr = attributes.map(({ name, nameFormat, valueTag, valueXsiType }) => {
        return `<saml:Attribute Name="${name}" NameFormat="${nameFormat}"><saml:AttributeValue xsi:type="${valueXsiType}">{${tagging('attr', valueTag)}}</saml:AttributeValue></saml:Attribute>`
      }).join('');
      return `<saml:AttributeStatement>${attr}</saml:AttributeStatement>`
    },
    /**
    * @desc Construct the XML signature for POST binding
    * @param  {string} rawSamlMessage      request/response xml string
    * @param  {string} referenceTagXPath    reference uri
    * @param  {string} privateKey           declares the private key
    * @param  {string} passphrase           passphrase of the private key [optional]
    * @param  {string|buffer} signingCert   signing certificate
    * @param  {string} signatureAlgorithm   signature algorithm 
    * @return {string} base64 encoded string
    */
    constructSAMLSignature: function (opts: SignatureConstructor) {
      const { rawSamlMessage, referenceTagXPath, privateKey, privateKeyPass, signatureAlgorithm, signingCert, isBase64Output = true, messageSignatureConfig } = opts;
      let sig = new SignedXml();
      // Add assertion sections as reference
      if (referenceTagXPath && referenceTagXPath !== '') {
        sig.addReference(referenceTagXPath, null, getDigestMethod(signatureAlgorithm));
      }
      sig.signatureAlgorithm = signatureAlgorithm;
      sig.keyInfoProvider = new this.getKeyInfo(signingCert);
      sig.signingKey = utility.readPrivateKey(privateKey, privateKeyPass, true);
      if (messageSignatureConfig) {
        sig.computeSignature(rawSamlMessage, messageSignatureConfig);
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
    verifySignature: function (xml: string, signature, opts: SignatureVerifierOptions) {
      let signatureAlgorithm = opts.signatureAlgorithm || signatureAlgorithms.RSA_SHA1;
      let sig = new SignedXml();
      sig.signatureAlgorithm = signatureAlgorithm;
      // Add assertion sections as reference
      if (opts.keyFile) {
        sig.keyInfoProvider = new FileKeyInfo(opts.keyFile);
      } else if (opts.cert) {
        sig.keyInfoProvider = new this.getKeyInfo(opts.cert.getX509Certificate(certUse.signing));
      } else {
        throw new Error('Undefined certificate in \'opts\' object');
      }
      sig.loadSignature(signature.toString());
      if (sig.checkSignature(xml)) {
        return true;
      }
      throw new Error(sig.validationErrors);
    },
    /**
    * @desc High-level XML extractor
    * @param  {string} xmlString
    * @param  {object} fields
    */
    extractor: function (xmlString: string, fields) {
      let doc = new dom().parseFromString(xmlString);
      let meta = {};
      fields.forEach(field => {
        let objKey;
        let res;
        if (isString(field)) {
          meta[field.toLowerCase()] = getInnerText(doc, field);
        } else if (typeof field === 'object') {
          let localName = field.localName;
          let extractEntireBody = field.extractEntireBody === true;
          let attributes = field.attributes || [];
          let customKey = field.customKey || '';

          if (isString(localName)) {
            objKey = localName;
            if (extractEntireBody) {
              res = getEntireBody(doc, localName);
            } else {
              if (attributes.length !== 0) {
                res = getAttributes(doc, localName, attributes);
              } else {
                res = getInnerText(doc, localName);
              }
            }
          } else {
            objKey = localName.tag;
            if (field.attributeTag) {
              res = getAttributeKey(doc, objKey, localName.key, field.attributeTag);
            } else if (field.valueTag) {
              res = getInnerTextWithOuterKey(doc, objKey, localName.key, field.valueTag);
            }
          }
          meta[customKey === '' ? objKey.toLowerCase() : customKey] = res;
        }
      });
      return <ExtractorResult>meta;
    },
    /**
    * @desc Helper function to create the key section in metadata (abstraction for signing and encrypt use)
    * @param  {string} use          type of certificate (e.g. signing, encrypt)
    * @param  {string} certString    declares the certificate String
    * @return {object} object used in xml module
    */
    createKeySection: function (use: string, certString: string | Buffer) {
      return {
        KeyDescriptor: [{
          _attr: { use }
        }, {
          KeyInfo: [{
            _attr: {
              'xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#'
            }
          }, {
            X509Data: [{
              X509Certificate: utility.normalizeCerString(certString)
            }]
          }]
        }]
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
    constructMessageSignature: function (octetString: string, key: string, passphrase?: string, isBase64?: boolean, signingAlgorithm?: string) {
      // Default returning base64 encoded signature
      // Embed with node-rsa module
      let decryptedKey = new nrsa(utility.readPrivateKey(key, passphrase), {
        signingScheme: getSigningScheme(signingAlgorithm)
      });
      let signature = decryptedKey.sign(octetString);
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
    verifyMessageSignature: function (metadata, octetString: string, signature: string | Buffer, verifyAlgorithm?: string) {
      let key = new nrsa(utility.getPublicKeyPemFromCertificate(metadata.getX509Certificate(certUse.signing)), {
        signingScheme: getSigningScheme(verifyAlgorithm)
      });
      return key.verify(new Buffer(octetString), signature);
    },
    /**
    * @desc Get the public key in string format
    * @param  {string} x509Certificate certificate
    * @return {string} public key
    */
    getKeyInfo: function (x509Certificate: string) {
      this.getKeyInfo = function (key) {
        return '<X509Data><X509Certificate>' + x509Certificate + '</X509Certificate></X509Data>';
      };
      this.getKey = function (keyInfo) {
        return utility.getPublicKeyPemFromCertificate(x509Certificate).toString();
      };
    },
    /**
    * @desc Encrypt the assertion section in Response
    * @param  {Entity} sourceEntity             source entity
    * @param  {Entity} targetEntity             target entity
    * @param {string} entireXML                 response in xml string format
    * @return {Promise} a promise to resolve the finalized xml
    */
    encryptAssertion: function (sourceEntity, targetEntity, entireXML: string) {
      // Implement encryption after signature if it has
      return new Promise<string>((resolve, reject) => {
        if (entireXML) {
          let sourceEntitySetting = sourceEntity.entitySetting;
          let targetEntitySetting = targetEntity.entitySetting;
          let sourceEntityMetadata = sourceEntity.entityMeta;
          let targetEntityMetadata = targetEntity.entityMeta;
          let assertionNode = getEntireBody(new dom().parseFromString(entireXML), 'Assertion');
          let assertion = !isUndefined(assertionNode) ? utility.parseString(assertionNode.toString()) : '';

          if (assertion === '') {
            return reject(new Error('undefined assertion or invalid syntax'));
          }
          // Perform encryption depends on the setting, default is false
          if (sourceEntitySetting.isAssertionEncrypted) {
            xmlenc.encrypt(assertion, {
              // use xml-encryption module
              rsa_pub: new Buffer(utility.getPublicKeyPemFromCertificate(targetEntityMetadata.getX509Certificate(certUse.encrypt)).replace(/\r?\n|\r/g, '')), // public key from certificate
              pem: new Buffer('-----BEGIN CERTIFICATE-----' + targetEntityMetadata.getX509Certificate(certUse.encrypt) + '-----END CERTIFICATE-----'),
              encryptionAlgorithm: sourceEntitySetting.dataEncryptionAlgorithm,
              keyEncryptionAlgorighm: sourceEntitySetting.keyEncryptionAlgorithm
            }, (err, res) => {
              if (err) {
                return reject(new Error('exception in encrpytedAssertion ' + err));
              }
              if (!res) {
                return reject(new Error('undefined encrypted assertion'));
              }
              return resolve(utility.base64Encode(entireXML.replace(/<(.*?)Assertion(.*?)>(.*?)<\/(.*?)Assertion>/g, `<saml:EncryptedAssertion>${res}</saml:EncryptedAssertion>`)));
            });
          } else {
            return resolve(utility.base64Encode(entireXML)); // No need to do encrpytion
          }
        } else {
          return reject(new Error('empty or undefined xml string during encryption'));
        }
      })
    },
    /**
    * @desc Decrypt the assertion section in Response
    * @param  {string} type             only accept SAMLResponse to proceed decryption
    * @param  {Entity} here             this entity
    * @param  {Entity} from             from the entity where the message is sent
    * @param {string} entireXML         response in xml string format
    * @return {function} a promise to get back the entire xml with decrypted assertion
    */
    decryptAssertion: function (type: string, here, from, entireXML: string) {
      return new Promise<string>((resolve, reject) => {
        // Implement decryption first then check the signature
        if (entireXML) {
          // Perform encryption depends on the setting of where the message is sent, default is false
          if (type === 'SAMLResponse' && from.entitySetting.isAssertionEncrypted) {
            let hereSetting = here.entitySetting;
            let parseEntireXML = new dom().parseFromString(String(entireXML));
            let encryptedDataNode = getEntireBody(parseEntireXML, 'EncryptedData');
            let encryptedData = !isUndefined(encryptedDataNode) ? utility.parseString(String(encryptedDataNode)) : '';
            if (encryptedData === '') {
              return reject(new Error('undefined assertion or invalid syntax'));
            }
            return xmlenc.decrypt(encryptedData, {
              key: utility.readPrivateKey(hereSetting.encPrivateKey, hereSetting.encPrivateKeyPass)
            }, (err, res) => {
              if (err) {
                return reject(new Error('exception in decryptAssertion ' + err));
              }
              if (!res) {
                return reject(new Error('undefined encrypted assertion'));
              }
              return resolve(String(parseEntireXML).replace(/<(.*?)EncryptedAssertion(.*?)>/g, '').replace(encryptedData, res));
            });
          } else {
            return resolve(entireXML); // No need to do encrpytion
          }
        } else {
          return reject(new Error('empty or undefined xml string during decryption'));
        }
      });
    }
  };
}

export default libSaml();
