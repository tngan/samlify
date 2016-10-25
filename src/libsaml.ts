/**
* @file SamlLib.js
* @author tngan
* @desc  A simple library including some common functions
*
* v2.0
* v1.1  SS-1.1
*/

import { DOMParser } from 'xmldom';
import * as fs from 'fs';
import { pki } from 'node-forge';
import utility from './utility';
import { tags, algorithms, wording } from './urn';
import xpath from 'xpath';

const nrsa = require('node-rsa');
const xml = require('xml');
const xmlenc = require('xml-encryption');
const signatureAlgorithms = algorithms.signature;
const digestAlgorithms = algorithms.digest;
const certUsage = wording.certUse;
const requestTags = tags.request;
const dom = DOMParser;

let { SignedXml, FileKeyInfo } = require('xml-crypto');

interface ExtractorResultInterface {
  signature: any;
  issuer: string;
}

export interface LibSamlInterface {
  createXPath: (local, isExtractAll?: boolean) => string;
  defaultLoginRequestTemplate: string;
  defaultLogoutRequestTemplate: string;
  defaultLoginResponseTemplate: string;
  defaultLogoutResponseTemplate: string;
  replaceTagsByValue: (rawXML: string, tagValues: Array<any>) => string;
  constructSAMLSignature: (xmlString: string, referenceXPath: string, x509: string, keyFile: string, passphrase: string, signatureAlgorithm: string, isBase64Output: boolean) => string;
  verifySignature: (xml: string, signature, opts) => boolean;
  extractor: (xmlString: string, fields) => ExtractorResultInterface;
  createKeySection: (use: string, certFile: string) => {};
  constructMessageSignature: (octetString: string, keyFile: string, passphrase: string, isBase64?: boolean, signingAlgorithm?: string) => string;
  verifyMessageSignature: (metadata, octetString: string, signature: string | Buffer, verifyAlgorithm: string) => boolean;
  getKeyInfo: (x509Certificate: string) => void;
  encryptAssertion: (sourceEntity, targetEntity, entireXML: string, callback) => void;
  decryptAssertion: (type: string, here, from, entireXML: string, callback) => void;
}

class LibSaml implements LibSamlInterface {

  private nrsaAliasMapping: any;
  public defaultLoginRequestTemplate: string;
  public defaultLogoutRequestTemplate: string;
  public defaultLoginResponseTemplate: string;
  public defaultLogoutResponseTemplate: string;

  consturctor() {
    this.nrsaAliasMapping = {
      'http://www.w3.org/2000/09/xmldsig#rsa-sha1' : 'sha1',
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' : 'sha256',
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512' : 'sha512'
    };
    /**
    * @desc Default login request template
    * @type {string}
    */
    this.defaultLoginRequestTemplate = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>';
    /**
    * @desc Default logout request template
    * @type {string}
    */
    this.defaultLogoutRequestTemplate = '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}"><saml:Issuer>{Issuer}</saml:Issuer><saml:NameID SPNameQualifier="{EntityID}" Format="{NameIDFormat}">{NameID}</saml:NameID></samlp:LogoutRequest>';
    /**
    * @desc Default login response template
    * @type {String}
    */
    this.defaultLoginResponseTemplate = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status><saml:Assertion ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AuthnStatement}{AttributeStatement}</saml:Assertion></samlp:Response>';
    /**
    * @desc Default logout response template
    * @type {String}
    */
    this.defaultLogoutResponseTemplate = '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status></samlp:LogoutResponse>';
  }
  /**
  * @private
  * @desc Get the signing scheme alias by signature algorithms, used by the node-rsa module
  * @param {string} sigAlg    signature algorithm
  * @return {string/null} signing algorithm short-hand for the module node-rsa
  */
  private getSigningScheme (sigAlg: string): string | null {
    const algAlias = this.nrsaAliasMapping[sigAlg];
    if (algAlias !== undefined) {
      return algAlias;
    }
    return this.nrsaAliasMapping[signatureAlgorithms.RSA_SHA1]; // default value
  };
  /**
  * @private
  * @desc Get the digest algorithms by signature algorithms
  * @param {string} sigAlg    signature algorithm
  * @return {string/null} digest algorithm
  */
  private getDigestMethod (sigAlg: string): string | null {
    let digestAlg = digestAlgorithms[sigAlg];
    if (digestAlg !== undefined) {
      return digestAlg;
    }
    return null; // default value
  }
  /**
  * @private
  * @desc Get the attibutes
  * @param  {xml} xmlDoc              used xml document
  * @param  {string} localName        tag name without prefix
  * @param  {[string]} attributes     array consists of name of attributes
  * @return {string/array}
  */
  private getAttributes (xmlDoc, localName: string, attributes: Array<string>) {
    let xpathStr = this.createXPath(localName);
    let selection = xpath.select(xpathStr, xmlDoc);
    let data = [];
    if (selection.length === 0) {
      return undefined;
    }
    selection.forEach(s => {
      let dat = {};
      let doc = new dom().parseFromString(String(s));
      attributes.forEach(attr => {
        dat[attr.toLowerCase()] = this.getAttribute(doc, localName, attr);
      });
      data.push(dat);
    });
    return data.length === 1 ? data[0] : data;
  };
  /**
  * @private
  * @desc Helper function used by another private function: getAttributes
  * @param  {xml} xmlDoc          used xml document
  * @param  {string} localName    tag name without prefix
  * @param  {string} attribute    name of attribute
  * @return {string} attribute value
  */
  private getAttribute = function (xmlDoc, localName: string, attribute: string): string {
    let xpathStr = this.createXPath({
      name: localName,
      attr: attribute
    });
    let selection = xpath.select(xpathStr, xmlDoc);

    if (selection.length !== 1) {
      return undefined;
    } else {
      return selection[0].nodeValue.toString();
    }
  };
  /**
  * @private
  * @desc Helper function used to return result with complex format
  * @param  {xml} xmlDoc              used xml document
  * @param  {string} localName        tag name without prefix
  * @param  {string} localNameKey     key associated with tag name
  * @param  {string} valueTag         tag of the value
  */
  private getInnerTextWithOuterKey = function (xmlDoc, localName: string, localNameKey: string, valueTag: string) {
    let xpathStr = this.createXPath(localName);
    let selection = xpath.select(xpathStr, xmlDoc);
    let obj = {};

    selection.forEach(function(_s) {
      let xd = new dom().parseFromString(_s.toString());
      let key = xpath.select("//*[local-name(.)='" + localName + "']/@" + localNameKey, xd);
      let value = xpath.select("//*[local-name(.)='" + valueTag + "']/text()", xd);
      let res;

      if (key && key.length == 1 && value && value.length > 0) {
        if (value.length == 1) {
          res = value[0].nodeValue.toString();
        } else {
          let dat = [];
          value.forEach(v => dat.push(String(v.nodeValue)));
          res = dat;
        }
        obj[key[0].nodeValue.toString()] = res;
      } else{
        //console.warn('Multiple keys or null value is found');
      }
    });
    return Object.keys(obj).length === 0 ? undefined : obj;
  };
  /**
  * @private
  * @desc  Get the attribute according to the key
  * @param  {string} localName            tag name without prefix
  * @param  {string} localNameKey         key associated with tag name
  * @param  {string} attributeTag         tag of the attribute
  */
  private getAttributeKey = function (xmlDoc, localName: string, localNameKey: string, attributeTag: string) {
    let xpathStr = this.createXPath(localName);
    let selection = xpath.select(xpathStr, xmlDoc);
    let data = [];

    selection.forEach(function(_s) {
      let xd = new dom().parseFromString(_s.toString());
      let key = xpath.select("//*[local-name(.)='" + localName + "']/@" + localNameKey, xd);
      let value = xpath.select("//*[local-name(.)='" + localName + "']/@" + attributeTag, xd);

      if (value && value.length == 1 && key && key.length == 1) {
        let obj = {};
        obj[key[0].nodeValue.toString()] = value[0].nodeValue.toString();
        data.push(obj);
      } else {
        //console.warn('Multiple keys or null value is found');
      }
    });
    return data.length === 0 ? undefined : data;
  };
  /**
  * @private
  * @desc Get the entire body according to the XPath
  * @param  {xml} xmlDoc              used xml document
  * @param  {string} localName        tag name without prefix
  * @param  {boolean} isOutputString  output is string format (default is true)
  * @return {string/array}
  */
  private getEntireBody = function (xmlDoc, localName: string, isOutputString?: boolean) {
    let xpathStr = this.createXPath(localName);
    let selection = xpath.select(xpathStr, xmlDoc);
    if (selection.length === 0) {
      return undefined;
    }
    let data = [];
    selection.forEach(function(_s) {
      data.push(utility.convertToString(_s, isOutputString !== false));
    });
    return data.length === 1 ? data[0] : data;
  };
  /**
  * @private
  * @desc  Get the inner xml according to the XPath
  * @param  {xml} xmlDoc          used xml document
  * @param  {string} localName    tag name without prefix
  * @return {string/array} value
  */
  private getInnerText = function (xmlDoc, localName: string) {
    let xpathStr = this.createXPath(localName, true);
    let selection = xpath.select(xpathStr, xmlDoc);
    if (selection.length === 0) {
      return undefined;
    }
    let data = [];
    selection.forEach(function(_s) {
      data.push(_s.nodeValue.toString());
    });
    return data.length === 1 ? data[0] : data;
  };
  /**
  * @private
  * @desc Create XPath
  * @param  {string/object} local     parameters to create XPath
  * @param  {boolean} isExtractAll    define whether returns whole content according to the XPath
  * @return {string} xpath
  */
  public createXPath (local, isExtractAll?: boolean): string {
    if(typeof local == 'object') {
      return "//*[local-name(.)='" + local.name + "']/@" + local.attr;
    }
    return isExtractAll === true ? "//*[local-name(.)='" + local + "']/text()" : "//*[local-name(.)='" + local + "']";
  }
  /**
  * @desc Repalce the tag (e.g. {tag}) inside the raw XML
  * @param  {string} rawXML      raw XML string used to do keyword replacement
  * @param  {array} tagValues    tag values
  * @return {string}
  */
  public replaceTagsByValue (rawXML: string, tagValues: Array<any>): string {
    Object.keys(requestTags).forEach(t => {
      rawXML = rawXML.replace(new RegExp(requestTags[t], 'g'), tagValues[t]);
    });
    return rawXML;
  }
  /**
  * @desc Construct the XML signature for POST binding
  * @param  {string} xmlString            request/response xml string
  * @param  {string} referenceXPath       reference uri
  * @param  {string} keyFile              declares the .pem file storing the private key (e.g. path/privkey.pem)
  * @param  {string} passphrase           passphrase of .pem file [optional]
  * @param  {string} signatureAlgorithm   signature algorithm (SS-1.1)
  * @return {string} base64 encoded string
  */
  public constructSAMLSignature (xmlString: string, referenceXPath: string, x509: string, keyFile: string, passphrase: string, signatureAlgorithm: string, isBase64Output: boolean) {
    let sig = new SignedXml();
    // Add assertion sections as reference
    if (referenceXPath && referenceXPath !== '') {
      sig.addReference(referenceXPath, null, this.getDigestMethod(signatureAlgorithm)); // SS-1.1
    }
    sig.signatureAlgorithm = signatureAlgorithm; // SS-1.1
    sig.keyInfoProvider = new this.getKeyInfo(x509);
    sig.signingKey = utility.readPrivateKeyFromFile(keyFile, passphrase, true);
    sig.computeSignature(xmlString);
    return isBase64Output !== false ? utility.base64Encode(sig.getSignedXml()) : sig.getSignedXml();
  }
  /**
  * @desc Verify the XML signature
  * @param  {string} xml                  xml
  * @param  {signature} signature         context of XML signature
  * @param  {object} opts                 keyFile or cert declares the X509 certificate
  * @return {boolean} verification result
  */
  public verifySignature (xml: string, signature, opts) {
    let options = opts || {};
    let refXPath = options.referenceXPath;
    let signatureAlgorithm = options.signatureAlgorithm || signatureAlgorithms.RSA_SHA1; // SS1.1
    let sig = new SignedXml();
    sig.signatureAlgorithm = signatureAlgorithm; // SS1.1
    // Add assertion sections as reference
    if (options.keyFile) {
      sig.keyInfoProvider = new FileKeyInfo(options.keyFile);
    } else if (options.cert) {
      sig.keyInfoProvider = new this.getKeyInfo(options.cert.getX509Certificate(certUsage.SIGNING));
    } else {
      throw new Error('Undefined certificate or keyfile in \'opts\' object');
    }
    sig.loadSignature(signature.toString());
    let res = sig.checkSignature(xml);
    if (!res) {
      throw new Error(sig.validationErrors);
    } else {
      return true;
    }
  }
  /**
  * @desc High-level XML extractor
  * @param  {string} xmlString
  * @param  {object} fields
  */
  public extractor (xmlString: string, fields) {
    let doc = new dom().parseFromString(xmlString);
    let meta = {};
    fields.forEach(function(field) {
      let objKey;
      let res;
      if (typeof field === 'string') {
        meta[field.toLowerCase()] = this.getInnerText(doc, field);
      } else if (typeof field === 'object') {
        let localName = field.localName;
        let extractEntireBody  = field.extractEntireBody === true;
        let attributes  = field.attributes || [];
        let customKey  = field.customKey || '';

        if (typeof localName === 'string') {
          objKey = localName;
          if (extractEntireBody ) {
            res = this.getEntireBody(doc, localName);
          } else {
            if (attributes.length !== 0) {
              res = this.getAttributes(doc, localName, attributes );
            } else {
              res = this.getInnerText(doc,localName);
            }
          }
        } else {
          objKey = localName.tag;
          if (field.attributeTag) {
            res = this.getAttributeKey(doc, objKey, localName.key, field.attributeTag);
          } else if (field.valueTag) {
            res = this.getInnerTextWithOuterKey(doc, objKey, localName.key, field.valueTag);
          }
        }
        meta[customKey  === '' ? objKey.toLowerCase() : customKey ] = res;
      }
    });
    return <ExtractorResultInterface>meta;
  }
  /**
  * @desc Helper function to create the key section in metadata (abstraction for signing and encrypt use)
  * @param  {string} use          type of certificate (e.g. signing, encrypt)
  * @param  {string} certFile     declares the .cer file (e.g. path/certificate.cer)
  * @return {object} object used in xml module
  */
  public createKeySection (use: string, certFile: string) {
    return {
      KeyDescriptor:[{
        _attr: {
          use: use
        }
      },{
        KeyInfo: [{
          _attr: {
            'xmlns:ds':'http://www.w3.org/2000/09/xmldsig#'
          }
        },{
          X509Data: [{
            X509Certificate: utility.parseCerFile(certFile)
          }]
        }]
      }]
    };
  }
  /**
  * @desc Constructs SAML message
  * @param  {string} octetString               see "Bindings for the OASIS Security Assertion Markup Language (SAML V2.0)" P.17/46
  * @param  {string} keyFile                   declares the .pem file storing the private key (e.g. path/privkey.pem)
  * @param  {string} passphrase                passphrase of .pem file [optional]
  * @param  {string} signingAlgorithm          signing algorithm (SS-1.1)
  * @return {string} message signature
  */
  public constructMessageSignature (octetString: string, keyFile: string, passphrase: string, isBase64: boolean, signingAlgorithm: string) {
    // Default returning base64 encoded signature
    // Embed with node-rsa module
    let key = new nrsa(utility.readPrivateKeyFromFile(keyFile, passphrase), {
      signingScheme: this.getSigningScheme(signingAlgorithm) // SS-1.1
    });
    let signature = key.sign(octetString);
    // Use private key to sign data
    return isBase64 !== false ? signature.toString('base64') : signature;
  }
  /**
  * @desc Verifies message signature
  * @param  {Metadata} metadata                 metadata object of identity provider or service provider
  * @param  {string} octetString                see "Bindings for the OASIS Security Assertion Markup Language (SAML V2.0)" P.17/46
  * @param  {string} signature                  context of XML signature
  * @param  {string} verifyAlgorithm            algorithm used to verify (SS-1.1)
  * @return {boolean} verification result
  *
  * SS1.1 Code refractoring
  */
  public verifyMessageSignature (metadata, octetString: string, signature: string | Buffer, verifyAlgorithm: string) {
    let key = new nrsa(utility.getPublicKeyPemFromCertificate(metadata.getX509Certificate(certUsage.SIGNING)), {
      signingScheme: this.getSigningScheme(verifyAlgorithm)
    });
    return key.verify(new Buffer(octetString), signature);
  }
  /**
  *
  *
  **/
  public getKey (keyInfo) {}
  /**
  * @desc Get the public key in string format
  * @param  {string} x509Certificate          certificate
  * @return {string} public key
  *
  * SS1.1 Code refractoring
  */
  public getKeyInfo (x509Certificate: string) {
    this.getKeyInfo = function(key) {
      return '<X509Data><X509Certificate>' + x509Certificate + '</X509Certificate></X509Data>';
    };
    this.getKey = function(keyInfo) {
      return utility.getPublicKeyPemFromCertificate(x509Certificate).toString();
    };
  }
  /**
  * @desc Encrypt the assertion section in Response
  * @param  {Entity} sourceEntity             source entity
  * @param  {Entity} targetEntity             target entity
  * @param {string} entireXML                 response in xml string format
  * @return {function} a callback to receive the finalized xml
  *
  * SS1.1
  */
  public encryptAssertion (sourceEntity, targetEntity, entireXML: string, callback) {
    // Implement encryption after signature if it has
    if (entireXML) {
      let sourceEntitySetting = sourceEntity.entitySetting;
      let targetEntitySetting = targetEntity.entitySetting;
      let sourceEntityMetadata = sourceEntity.entityMeta;
      let targetEntityMetadata = targetEntity.entityMeta;
      let assertionNode = this.getEntireBody(new dom().parseFromString(entireXML), 'Assertion');
      let assertion = assertionNode !== undefined ? utility.parseString(assertionNode.toString()) : '';

      if (assertion === '') throw new Error('Undefined assertion or invalid syntax');
      // Perform encryption depends on the setting, default is false
      if (sourceEntitySetting.isAssertionEncrypted) {
        // callback should be function (res) { ... }
        xmlenc.encrypt(assertion, {
          // use xml-encryption module
          rsa_pub: new Buffer(utility.getPublicKeyPemFromCertificate(targetEntityMetadata.getX509Certificate(certUsage.ENCRYPT)).replace(/\r?\n|\r/g, '')), // public key from certificate
          pem: new Buffer('-----BEGIN CERTIFICATE-----' + targetEntityMetadata.getX509Certificate(certUsage.ENCRYPT) + '-----END CERTIFICATE-----'),
          encryptionAlgorithm: sourceEntitySetting.dataEncryptionAlgorithm,
          keyEncryptionAlgorighm: sourceEntitySetting.keyEncryptionAlgorithm // typo in xml-encryption
        }, function(err, res) {
          if (err) throw new Error('Exception in encrpytedAssertion ' + err);
          if (res) {
            callback(utility.base64Encode(entireXML.replace(assertion, '<saml:EncryptedAssertion>' + res + '</saml:EncryptedAssertion>')));
          } else {
            throw new Error('Undefined encrypted assertion');
          }
        });
      } else {
        callback(utility.base64Encode(entireXML)); // No need to do encrpytion
      }
    } else {
      throw new Error('Empty or undefined xml string');
    }
  }
  /**
  * @desc Decrypt the assertion section in Response
  * @param  {string} type             only accept SAMLResponse to proceed decryption
  * @param  {Entity} here             this entity
  * @param  {Entity} from             from the entity where the message is sent
  * @param {string} entireXML         response in xml string format
  * @return {function} a callback to get back the entire xml with decrypted assertion
  *
  * SS1.1
  */
  public decryptAssertion (type: string, here, from, entireXML: string | Buffer, callback) {
    // Implement decryption first then check the signature
    if (entireXML) {
      // Perform encryption depends on the setting of where the message is sent, default is false
      if (type === 'SAMLResponse' && from.entitySetting.isAssertionEncrypted) {
        let hereSetting = here.entitySetting;
        // callback should be function (res) { ... }
        let parseEntireXML = new dom().parseFromString(String(entireXML));
        let encryptedDataNode = this.getEntireBody(parseEntireXML, 'EncryptedData');
        let encryptedData = encryptedDataNode !== undefined ? utility.parseString(encryptedDataNode.toString()) : '';

        if (encryptedData === '') throw new Error('Undefined assertion or invalid syntax');
        xmlenc.decrypt(encryptedData, {
          key: utility.readPrivateKeyFromFile(hereSetting.privateKeyFile, hereSetting.privateKeyFilePass), // use this entity's private to decrypt
        }, function(err, res) {
          if (err) throw new Error('Exception in decryptAssertion ' + err);
          if (res) {
            callback(parseEntireXML.toString().replace('<saml:EncryptedAssertion>', '').replace('</saml:EncryptedAssertion>', '').replace(encryptedData, res));
          } else {
            throw new Error('Undefined encrypted assertion');
          }
        });
      } else {
        callback(entireXML); // No need to do encrpytion
      }
    } else {
      throw new Error('Empty or undefined xml string');
    }
  }
}

const libsaml = new LibSaml();

export default libsaml;
