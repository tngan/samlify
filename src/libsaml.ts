/**
 * @file SamlLib.js
 * @author tngan
 * @desc  A simple library including some common functions
 */
import xml from 'xml'
import utility, {flattenDeep, inflateString, isString} from './utility.js';
import {createSign, createPrivateKey, createVerify} from 'node:crypto';
import {algorithms, namespace, wording} from './urn.js';
import {select} from 'xpath';
import nrsa, {SigningSchemeHash} from 'node-rsa';
import type {MetadataInterface} from './metadata.js';
import {SignedXml} from 'xml-crypto';
import * as xmlenc from 'xml-encryption';
import camelCase from 'camelcase';
import {getContext} from './api.js';
import xmlEscape from 'xml-escape';
import * as fs from 'fs';
import {DOMParser} from '@xmldom/xmldom';

const signatureAlgorithms = algorithms.signature;
const digestAlgorithms = algorithms.digest;
const certUse = wording.certUse;
const urlParams = wording.urlParams;




/**
 * 生成 SAML Attribute 元素（不带 XML 声明头）
 * @param {Array} attributeData - 属性配置数据
 * @returns {string} SAML Attribute XML 字符串
 */


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
  metadata?: MetadataInterface;
  keyFile?: string;
  signatureAlgorithm?: string;
}

export interface ExtractorResult {
  [key: string]: any;

  signature?: string | string[];
  issuer?: string | string[];
  nameID?: string;
  notexist?: boolean;
}

export interface LoginResponseAttribute {
  name: string;
  nameFormat: string; //
  valueXsiType: string; //
  valueTag: string;
  valueXmlnsXs?: string;
  valueXmlnsXsi?: string;
  type?: string | string[];
}

export interface LoginResponseAdditionalTemplates {
  attributeStatementTemplate?: AttributeStatementTemplate;
  attributeTemplate?: AttributeTemplate;
}

export interface BaseSamlTemplate {
  context: string;
}

export interface LoginResponseTemplate extends BaseSamlTemplate {
  attributes?: LoginResponseAttribute[];
  additionalTemplates?: LoginResponseAdditionalTemplates;
}

export interface AttributeStatementTemplate extends BaseSamlTemplate {
}

export interface AttributeTemplate extends BaseSamlTemplate {
}

export interface LoginRequestTemplate extends BaseSamlTemplate {
}

export interface LogoutRequestTemplate extends BaseSamlTemplate {
}

export interface LogoutResponseTemplate extends BaseSamlTemplate {
}

export type KeyUse = 'signing' | 'encryption';

export interface KeyComponent {
  [key: string]: any;
}

export interface LibSamlInterface {
  getQueryParamByType: (type: string) => string;
  createXPath: (local, isExtractAll?: boolean) => string;
  replaceTagsByValue: (rawXML: string, tagValues: any) => string;
  attributeStatementBuilder: (attributes: LoginResponseAttribute[], attributeTemplate: AttributeTemplate, attributeStatementTemplate: AttributeStatementTemplate) => string;
  constructSAMLSignature: (opts: SignatureConstructor) => string;
  verifySignature: (xml: string, opts: SignatureVerifierOptions) => [boolean, any];
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
  defaultAttributeStatementTemplate: AttributeStatementTemplate;
  defaultAttributeTemplate: AttributeTemplate;
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
    // 签名算法映射表
  const nrsaAliasMapping = {
    'http://www.w3.org/2000/09/xmldsig#rsa-sha1': 'pkcs1-sha1',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'pkcs1-sha256',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': 'pkcs1-sha512',
  };
  const nrsaAliasMappingForNode = {
    'http://www.w3.org/2000/09/xmldsig#rsa-sha1': 'RSA-SHA1',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'RSA-SHA256',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': 'RSA-SHA512',
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
    context: '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}"><saml:Issuer>{Issuer}</saml:Issuer><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID></samlp:LogoutRequest>',
  };
  /**
   * @desc Default art  request template
   * @type {LogoutRequestTemplate}
   */
  const defaultArtifactResolveTemplate = {
    context: `<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><saml2p:ArtifactResolve xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}"><saml2:Issuer>{Issuer}</saml2:Issuer><saml2p:Artifact>{Art}</saml2p:Artifact></saml2p:ArtifactResolve></SOAP-ENV:Body></SOAP-ENV:Envelope>`,
  };

  const defaultArtAuthnRequestTemplate = {
    context: `<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header></SOAP-ENV:Header><SOAP-ENV:Body><samlp:ArtifactResponse xmlns="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="{ID}" InResponseTo="{InResponseTo}" Version="2.0" IssueInstant="{IssueInstant}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>{AuthnRequest}</samlp:ArtifactResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>`,
  };
  const defaultSoapResponseFailTemplate = {
    context: `<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header></SOAP-ENV:Header>
<samlp:ArtifactResponse xmlns="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="{ID}"
 InResponseTo="{InResponseTo}" Version="2.0" 
 IssueInstant="{IssueInstant}">
 <saml:Issuer>{Issuer}</saml:Issuer>
 <samlp:Status>
 <samlp:StatusCode Value="{StatusCode}"/>
 </samlp:Status>{Response}</samlp:ArtifactResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>`,
  };
  /**
   * @desc Default AttributeStatement template
   * @type {AttributeStatementTemplate}
   */
  const defaultAttributeStatementTemplate = {
    context: '<saml:AttributeStatement>{Attributes}</saml:AttributeStatement>',
  };

  /**
   * @desc Default Attribute template
   * @type {AttributeTemplate}
   */
  const defaultAttributeTemplate = {
    context: '<saml:Attribute Name="{Name}" NameFormat="{NameFormat}">{AttributeValues}</saml:Attribute>',
  };
  /**
   * @desc Default AttributeValue template
   * @type {AttributeTemplate}
   */
  const defaultAttributeValueTemplate = {
    context: '<saml:AttributeValue xmlns:xs="{ValueXmlnsXs}" xmlns:xsi="{ValueXmlnsXsi}" xsi:type="{ValueXsiType}">{Value}</saml:AttributeValue>',
  };

  /**
   * @desc Default login response template
   * @type {LoginResponseTemplate}
   */
  const defaultLoginResponseTemplate = {
    context: '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AuthnStatement}{AttributeStatement}</saml:Assertion></samlp:Response>',
    attributes: [],
    additionalTemplates: {
      'attributeStatementTemplate': defaultAttributeStatementTemplate,
      'attributeTemplate': defaultAttributeTemplate
    }
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
  function getSigningScheme(sigAlg?: string): SigningSchemeHash {
    if (sigAlg) {
      const algAlias = nrsaAliasMapping[sigAlg];
      if (!(algAlias === undefined)) {
        return algAlias;
      }
    }
    return nrsaAliasMapping[signatureAlgorithms.RSA_SHA1];
  }

  function validateAndInflateSamlResponse(urlEncodedResponse) {
    // 3. 尝试DEFLATE解压（SAML规范要求使用原始DEFLATE）
    let xml = "";
    let compressed = true;

    try {        // 1. URL解码
      const base64Encoded = decodeURIComponent(urlEncodedResponse);
      // 2. Base64解码为Uint8Array
      xml = inflateString(base64Encoded);
    } catch (inflateError) {
      // 4. 解压失败，尝试直接解析为未压缩的XML
      try {
        const base64Encoded = decodeURIComponent(urlEncodedResponse);

        xml = atob(base64Encoded);

        return {compressed: false, xml, error: null};
      } catch (xmlError) {
        return Promise.resolve({compressed: false, xml, error: true})
      }
    }

    return {compressed, xml, error: null};

  }

  function getSigningSchemeForNode(sigAlg?: string) {
    if (sigAlg) {
      const algAlias = nrsaAliasMappingForNode[sigAlg];
      if (!(algAlias === undefined)) {
        return algAlias;
      }
    }
    return nrsaAliasMappingForNode[signatureAlgorithms.RSA_SHA256];
  }

  /**
   * @private
   * @desc Get the signing scheme alias by signature algorithms, used by the node-rsa module
   * @param {string} sigAlg    signature algorithm
   * @return {string/null} signing algorithm short-hand for the module node-rsa
   */

  /**
   * @private
   * @desc Get the digest algorithms by signature algorithms
   * @param {string} sigAlg    signature algorithm
   * @return {string/undefined} digest algorithm
   */
  function getDigestMethod(sigAlg: string): string | undefined {
    return digestAlgorithms[sigAlg];
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
    const camelContent = camelCase(content, {locale: 'en-us'});
    return prefix + camelContent.charAt(0).toUpperCase() + camelContent.slice(1);
  }

  function escapeTag(replacement: unknown): (...args: string[]) => string {
    return (_match: string, quote?: string) => {
      const text: string = (replacement === null || replacement === undefined) ? '' : String(replacement);

      // not having a quote means this interpolation isn't for an attribute, and so does not need escaping
      return quote ? `${quote}${xmlEscape(text)}` : text;
    }
  }

  return {

    createXPath,
    getQueryParamByType,
    defaultLoginRequestTemplate,
    defaultArtAuthnRequestTemplate,
    defaultArtifactResolveTemplate,
    defaultLoginResponseTemplate,
    defaultSoapResponseFailTemplate,
    defaultAttributeStatementTemplate,
    defaultAttributeTemplate,
    defaultLogoutRequestTemplate,
    defaultLogoutResponseTemplate,
    defaultAttributeValueTemplate,
    validateAndInflateSamlResponse,
    /**
     * @desc Replace the tag (e.g. {tag}) inside the raw XML
     * @param  {string} rawXML      raw XML string used to do keyword replacement
     * @param  {array} tagValues    tag values
     * @return {string}
     */
    replaceTagsByValue(rawXML: string, tagValues: Record<string, unknown>): string {
      Object.keys(tagValues).forEach(t => {
        rawXML = rawXML.replace(
          new RegExp(`("?)\\{${t}\\}`, 'g'),
          escapeTag(tagValues[t])
        );
      });
      return rawXML;
    },
    /**
     * @desc Helper function to build the AttributeStatement tag
     * @param  {LoginResponseAttribute} attributes    an array of attribute configuration
     * @param  {AttributeTemplate} attributeTemplate    the attribute tag template to be used
     * @param  {AttributeStatementTemplate} attributeStatementTemplate    the attributeStatement tag template to be used
     * @return {string}
     */
    /** For Test */
    attributeStatementBuilder(attributeData: any[]): string {
// 构建 XML 元素数组
      // 构建 XML 结构
      const attributeStatement = {
        'saml:AttributeStatement': [
          // 命名空间声明（在 AttributeStatement 上定义）
          {},
          // 遍历生成多个 Attribute
          ...attributeData.map(attr => ({
            'saml:Attribute ': [
              // Attribute 属性
              {
                _attr: {
                  Name: attr.Name,
                  NameFormat: attr.NameFormat
                }
              },
              // 遍历生成多个 AttributeValue
              ...attr.valueArray.map((valueObj: any) => ({
                'saml:AttributeValue ': [
                  // 数据类型（根据 ValueType）
                  {
                    _attr: attr.ValueType === 1
                      ? {'xsi:type': 'xs:string'}
                      : {}
                  },
                  // 值内容
                  valueObj.value
                ]
              }))
            ]
          }))
        ]
      };

      // 生成 XML（关闭自动声明头）
      const xmlString = xml([attributeStatement], {declaration: false});
      if(xmlString.trim() === '<saml:AttributeStatement></saml:AttributeStatement>'){
            return ''
      }
      return xmlString.trim();
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
        signatureAlgorithm = signatureAlgorithms.RSA_SHA512,
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
      const digestAlgorithm = getDigestMethod(signatureAlgorithm);
      if (referenceTagXPath) {
        sig.addReference({
          xpath: referenceTagXPath,
          transforms: transformationAlgorithms,
          digestAlgorithm: digestAlgorithm
        });
      }
      if (isMessageSigned) {
        sig.addReference({
          // reference to the root node
          xpath: '/*',
          transforms: transformationAlgorithms,
          digestAlgorithm
        });
      }
      sig.signatureAlgorithm = signatureAlgorithm;
      sig.publicCert = this.getKeyInfo(signingCert, signatureConfig).getKey();
      sig.getKeyInfoContent = this.getKeyInfo(signingCert, signatureConfig).getKeyInfo;
      sig.privateKey = utility.readPrivateKey(privateKey, privateKeyPass, true);
      sig.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
      if (signatureConfig) {
        sig.computeSignature(rawSamlMessage, signatureConfig);
      } else {
        sig.computeSignature(rawSamlMessage);
      }

      return isBase64Output ? utility.base64Encode(sig.getSignedXml()) : sig.getSignedXml();
    },

    /**
     * @desc Verify the XML signature
     * @param  {string} xml xml
     * @param  {SignatureVerifierOptions} opts cert declares the X509 certificate
     * @return {[boolean, string | null]} - A tuple where:
     *   - The first element is `true` if the signature is valid, `false` otherwise.
     *   - The second element is the cryptographically authenticated assertion node as a string, or `null` if not found.
     */
    // tslint:disable-next-line:no-shadowed-variable
    verifySignature(xml: string, opts: SignatureVerifierOptions) {
      const {dom} = getContext();
      const doc = dom.parseFromString(xml, 'application/xml');

      const docParser = new DOMParser();
      // In order to avoid the wrapping attack, we have changed to use absolute xpath instead of naively fetching the signature element

      const LogoutResponseSignatureXpath = "/*[local-name()='LogoutResponse']/*[local-name()='Signature']";
      const logoutRequestSignatureXpath = "/*[local-name()='LogoutRequest']/*[local-name()='Signature']";
      // message signature (logout response / saml response)
      const messageSignatureXpath = "/*[contains(local-name(), 'Response') or contains(local-name(), 'Request')]/*[local-name(.)='Signature']";
      // assertion signature (logout response / saml response)
      const assertionSignatureXpath = "/*[contains(local-name(), 'Response') or contains(local-name(), 'Request')]/*[local-name(.)='Assertion']/*[local-name(.)='Signature']";
      // check if there is a potential malicious wrapping signature
      const wrappingElementsXPath = "/*[contains(local-name(), 'Response')]/*[local-name(.)='Assertion']/*[local-name(.)='Subject']/*[local-name(.)='SubjectConfirmation']/*[local-name(.)='SubjectConfirmationData']//*[local-name(.)='Assertion' or local-name(.)='Signature']";

      // const wrappingElementsXPath = "/*[contains(local-name(), 'Response')]/*[local-name(.)='Assertion']/*[local-name(.)='Subject']/*[local-name(.)='SubjectConfirmation']/*[local-name(.)='SubjectConfirmationData']//*[local-name(.)='Assertion' or local-name(.)='Signature']";
      // @ts-expect-error misssing Node properties are not needed
      const encryptedAssertions = select("/*[contains(local-name(), 'Response')]/*[local-name(.)='EncryptedAssertion']", doc) as Node[];

      const encAssertionNode = encryptedAssertions[0];
      // select the signature node
      let selection: any = [];
      // @ts-expect-error misssing Node properties are not needed
      const messageSignatureNode = select(messageSignatureXpath, doc);
      // @ts-expect-error misssing Node properties are not needed
      const assertionSignatureNode = select(assertionSignatureXpath, doc);
      // @ts-expect-error misssing Node properties are not needed
      const wrappingElementNode = select(wrappingElementsXPath, doc);
      // @ts-expect-error misssing Node properties are not needed
      const LogoutResponseSignatureElementNode = select(LogoutResponseSignatureXpath, doc);
      // try to catch potential wrapping attack
      if (wrappingElementNode.length !== 0) {
        throw new Error('ERR_POTENTIAL_WRAPPING_ATTACK');
      }
      // 优先检测 LogoutRequest 签名
// @ts-expect-error missing Node properties
      const logoutRequestSignature = select(logoutRequestSignatureXpath, doc);
      if (logoutRequestSignature.length > 0) {
        selection = selection.concat(logoutRequestSignature);
      }

      selection = selection.concat(messageSignatureNode);

      selection = selection.concat(assertionSignatureNode);
      selection = selection.concat(LogoutResponseSignatureElementNode);


      // guarantee to have a signature in saml response
      if (selection.length === 0) {
        /** 判断有没有加密如果没有加密返回 [false, null]*/
        if(encryptedAssertions.length > 0){
          if (!Array.isArray(encryptedAssertions) || encryptedAssertions.length === 0) {
            return [false, null, false, true]; // we return false now
          }
          if (encryptedAssertions.length > 1) {
            throw new Error('ERR_MULTIPLE_ASSERTION');
          }
          return [false, null, true, true]; // return encryptedAssert
        }

      }
      if (selection.length !== 0) {
        /** 判断有没有加密如果没有加密返回 [false, null]*/
        if(logoutRequestSignature.length === 0 && LogoutResponseSignatureElementNode.length === 0  && encryptedAssertions.length > 0){
          if (!Array.isArray(encryptedAssertions) || encryptedAssertions.length === 0) {
            return [false, null, true, false]; // we return false now
          }
          if (encryptedAssertions.length > 1) {
            throw new Error('ERR_MULTIPLE_ASSERTION');
          }
          return [false, null, true, false]; // return encryptedAssert
        }


      }
      // need to refactor later on
      for (const signatureNode of selection) {
        const sig = new SignedXml();
        let verified = false;
        sig.signatureAlgorithm = opts.signatureAlgorithm!;
        if (!opts.keyFile && !opts.metadata) {
          throw new Error('ERR_UNDEFINED_SIGNATURE_VERIFIER_OPTIONS');
        }

        if (opts.keyFile) {
          sig.publicCert = fs.readFileSync(opts.keyFile)
        }

        if (opts.metadata) {
          const certificateNode = select(".//*[local-name(.)='X509Certificate']", signatureNode) as any;
          // certificate in metadata
          let metadataCert: any = opts.metadata.getX509Certificate(certUse.signing);
          // flattens the nested array of Certificates from each KeyDescriptor
          if (Array.isArray(metadataCert)) {
            metadataCert = flattenDeep(metadataCert);
          } else if (typeof metadataCert === 'string') {
            metadataCert = [metadataCert];
          }
          // normalise the certificate string
          metadataCert = metadataCert.map(utility.normalizeCerString);

          // no certificate in node  response nor metadata
          if (certificateNode.length === 0 && metadataCert.length === 0) {
            throw new Error('NO_SELECTED_CERTIFICATE');
          }

          // certificate node in response
          if (certificateNode.length !== 0) {
            const x509CertificateData = certificateNode[0].firstChild.data;
            const x509Certificate = utility.normalizeCerString(x509CertificateData);
            if (
              metadataCert.length >= 1 &&
              !metadataCert.find(cert => cert.trim() === x509Certificate.trim())
            ) {
              // keep this restriction for rolling certificate usage
              // to make sure the response certificate is one of those specified in metadata
              throw new Error('ERROR_UNMATCH_CERTIFICATE_DECLARATION_IN_METADATA');
            }

            sig.publicCert = this.getKeyInfo(x509Certificate).getKey();

          } else {
            // Select first one from metadata
            sig.publicCert = this.getKeyInfo(metadataCert[0]).getKey();

          }
        }

        sig.loadSignature(signatureNode);
        verified = sig.checkSignature(doc.toString());

        // immediately throw error when any one of the signature is failed to get verified
        if (!verified) {
          throw new Error('ERR_FAILED_TO_VERIFY_SIGNATURE');
        }

        // attempt is made to get the signed Reference as a string();
        // note, we don't have access to the actual signedReferences API unfortunately
        // mainly a sanity check here for SAML. (Although ours would still be secure, if multiple references are used)
        if (!(sig.getSignedReferences().length >= 1)) {
          throw new Error('NO_SIGNATURE_REFERENCES')
        }
        const signedVerifiedXML = sig.getSignedReferences()[0];
        const rootNode = docParser.parseFromString(signedVerifiedXML, 'application/xml').documentElement;
        // process the verified signature:
        // case 1, rootSignedDoc is a response:
        if (rootNode?.localName === 'Response') {

          // try getting the Xml from the first assertion
          const EncryptedAssertions = select(
            "./*[local-name()='EncryptedAssertion']",
            // @ts-expect-error misssing Node properties are not needed
            rootNode
          );
          const assertions = select(
            "./*[local-name()='Assertion']",
            // @ts-expect-error misssing Node properties are not needed
            rootNode
          );
          /**第三个参数代表是否加密*/
          // now we can process the assertion as an assertion
          if (EncryptedAssertions.length === 1) {
            /** 已加密*/
            return [true, EncryptedAssertions[0].toString(), true, false];
          }

          if (assertions.length === 1) {

            return [true, assertions[0].toString(), false, false];
          }

        } else if (rootNode?.localName === 'Assertion') {
          return [true, rootNode.toString(), false, false];
        } else if (rootNode?.localName === 'EncryptedAssertion') {
          return [true, rootNode.toString(), true, false];
        } else if (rootNode?.localName === 'LogoutRequest'){
          return [true, rootNode.toString(), false, false];
        }  else if (rootNode?.localName === 'LogoutResponse'){
          return [true, rootNode.toString(), false, false];
        } else {
          return [true, null, false, false]; // signature is valid. But there is no assertion node here. It could be metadata node, hence return null
        }
      }
      // something has gone seriously wrong if we are still here
      return [false, null, false, true]; // return encryptedAssert
   /*   throw new Error('ERR_ZERO_SIGNATURE');*/
    },

  /*  verifySignatureSoap(xml: string, opts: SignatureVerifierOptions & { isAssertion?: boolean }) {
      const {dom} = getContext();
      const doc = dom.parseFromString(xml, 'application/xml');
      const docParser = new DOMParser();

      let selection: any = [];

      if (opts.isAssertion) {
        // 断言模式下的专用逻辑
        const assertionSignatureXpath = "./!*[local-name()='Signature']";
        // @ts-expect-error misssing Node properties are not needed
        const signatureNode = select(assertionSignatureXpath, doc.documentElement);

        if (signatureNode.length === 0) {
          throw new Error('ERR_ASSERTION_SIGNATURE_NOT_FOUND');
        }

        selection = selection.concat(signatureNode);
      } else {
        // 原始的SOAP响应验证逻辑
        const messageSignatureXpath =
          "/!*[local-name()='Envelope']/!*[local-name()='Body']" +
          "/!*[local-name()='ArtifactResponse']/!*[local-name()='Signature'] | " +
          "/!*[local-name()='Envelope']/!*[local-name()='Body']" +
          "/!*[local-name()='ArtifactResponse']/!*[local-name()='Response']/!*[local-name()='Signature']";

        const assertionSignatureXpath =
          "/!*[local-name()='Envelope']/!*[local-name()='Body']" +
          "/!*[local-name()='ArtifactResponse']/!*[local-name()='Response']" +
          "/!*[local-name()='Assertion']/!*[local-name()='Signature'] | " +
          "/!*[local-name()='Envelope']/!*[local-name()='Body']" +
          "/!*[local-name()='ArtifactResponse']/!*[local-name()='Response']" +
          "/!*[local-name()='EncryptedAssertion']";

        const wrappingElementsXPath =
          "/!*[local-name()='Envelope']/!*[local-name()='Body']" +
          "/!*[local-name()='ArtifactResponse']/!*[local-name()='Response']" +
          "/!*[local-name()='Assertion']/!*[local-name()='Subject']" +
          "/!*[local-name()='SubjectConfirmation']" +
          "/!*[local-name()='SubjectConfirmationData']" +
          "//!*[local-name()='Assertion' or local-name()='Signature']";

// @ts-expect-error misssing Node properties are not needed
        const messageSignatureNode = select(messageSignatureXpath, doc);
        // @ts-expect-error misssing Node properties are not needed
        const assertionSignatureNode = select(assertionSignatureXpath, doc);
        // @ts-expect-error misssing Node properties are not needed
        const wrappingElementNode = select(wrappingElementsXPath, doc);

        // 检测包装攻击
        if (wrappingElementNode.length !== 0) {
          throw new Error('ERR_POTENTIAL_WRAPPING_ATTACK');
        }

        // 保证响应中至少有一个签名
        if (messageSignatureNode.length === 0 && assertionSignatureNode.length === 0) {
          throw new Error('ERR_ZERO_SIGNATURE');
        }

        selection = selection.concat(messageSignatureNode, assertionSignatureNode);
      }

      for (const signatureNode of selection) {
        const sig = new SignedXml();
        let verified = false;

        sig.signatureAlgorithm = opts.signatureAlgorithm!;

        if (!opts.keyFile && !opts.metadata) {
          throw new Error('ERR_UNDEFINED_SIGNATURE_VERIFIER_OPTIONS');
        }

        if (opts.keyFile) {
          sig.publicCert = fs.readFileSync(opts.keyFile, 'utf-8');
        }

        if (opts.metadata) {
          const certificateNodes = select(".//!*[local-name(.)='X509Certificate']", signatureNode) as any[];

          // 获取元数据中的证书
          let metadataCert: any = opts.metadata.getX509Certificate(certUse.signing);

          // 规范化元数据证书
          if (Array.isArray(metadataCert)) {
            metadataCert = flattenDeep(metadataCert);
          } else if (typeof metadataCert === 'string') {
            metadataCert = [metadataCert];
          }

          metadataCert = metadataCert.map(utility.normalizeCerString);

          // 检查证书可用性
          if (certificateNodes.length === 0 && metadataCert.length === 0) {
            throw new Error('NO_SELECTED_CERTIFICATE');
          }

          // 响应中有证书节点
          if (certificateNodes.length !== 0) {
            // 安全获取证书数据
            let x509CertificateData = '';
            if (certificateNodes[0].firstChild) {
              x509CertificateData = certificateNodes[0].firstChild.data;
            } else if (certificateNodes[0].textContent) {
              x509CertificateData = certificateNodes[0].textContent;
            }

            const x509Certificate = utility.normalizeCerString(x509CertificateData);

            // 验证证书匹配
            if (
              metadataCert.length >= 1 &&
              !metadataCert.find(cert => cert.trim() === x509Certificate.trim())
            ) {
              throw new Error('ERROR_UNMATCH_CERTIFICATE_DECLARATION_IN_METADATA');
            }

            sig.publicCert = this.getKeyInfo(x509Certificate).getKey();
          } else {
            // 使用元数据中的第一个证书
            sig.publicCert = this.getKeyInfo(metadataCert[0]).getKey();
          }
        }

        // 加载签名
        sig.loadSignature(signatureNode);
        // 使用原始 XML 进行验证
        verified = sig.checkSignature(xml);

        if (!verified) {
          throw new Error('ERR_FAILED_TO_VERIFY_SIGNATURE');
        }

        // 检查签名引用
        if (!(sig.getSignedReferences().length >= 1)) {
          throw new Error('NO_SIGNATURE_REFERENCES');
        }

        const signedVerifiedXML = sig.getSignedReferences()[0];
        const verifiedDoc = docParser.parseFromString(signedVerifiedXML, 'application/xml');
        const rootNode = verifiedDoc.documentElement;


        // 断言模式专用返回逻辑
        if (opts.isAssertion) {
          if (rootNode?.localName === 'Assertion') {
            return [true, rootNode.toString(), false];
          } else {
            throw new Error('ERR_INVALID_ASSERTION_SIGNATURE');
          }
        }

        // 处理已验证的签名
        // @ts-expect-error misssing Node properties are not needed
        if (rootNode.localName === 'ArtifactResponse') {
          // 在 ArtifactResponse 中查找 Response
          // @ts-expect-error misssing Node properties are not needed
          const responseNodes = select(
            "./!*[local-name()='Response']",
            // @ts-expect-error misssing Node properties are not needed
            rootNode
          ) as Element[];

          if (responseNodes.length === 0) {
            continue;
          }

          const responseNode = responseNodes[0];

          // 在 Response 中查找断言
          const encryptedAssertions = select(
            "./!*[local-name()='EncryptedAssertion']",
            responseNode
          ) as Element[];

          const assertions = select(
            "./!*[local-name()='Assertion']",
            responseNode
          ) as Element[];

          if (encryptedAssertions.length === 1) {
            return [true, encryptedAssertions[0].toString(), true];
          }

          if (assertions.length === 1) {
            return [true, assertions[0].toString(), false];
          }
        }
        // 直接处理 Response

        else if (rootNode?.localName === 'Response') {
          // @ts-expect-error misssing Node properties are not needed
          const encryptedAssertions = select(
            "./!*[local-name()='EncryptedAssertion']",
            // @ts-expect-error misssing Node properties are not needed
            rootNode
          ) as Element[];
          // @ts-expect-error misssing Node properties are not needed
          const assertions = select(
            "./!*[local-name()='Assertion']",
            // @ts-expect-error misssing Node properties are not needed
            rootNode
          ) as Element[];

          if (encryptedAssertions.length === 1) {
            return [true, encryptedAssertions[0].toString(), true];
          }

          if (assertions.length === 1) {
            return [true, assertions[0].toString(), false];
          }
        }
        // 直接处理 Assertion
        else if (rootNode?.localName === 'Assertion') {
          return [true, rootNode.toString(), false];
        }
        // 直接处理 EncryptedAssertion
        else if (rootNode?.localName === 'EncryptedAssertion') {
          return [true, rootNode.toString(), true];
        } else {

          console.warn("未知的根节点类型:", rootNode?.localName);
        }
      }

      throw new Error('ERR_ZERO_SIGNATURE');
    },*/
  verifySignatureSoap(xml: string, opts: SignatureVerifierOptions) {
    const {dom} = getContext();
    const doc = dom.parseFromString(xml, 'application/xml');
    const docParser = new DOMParser();

    // 为 SOAP 消息定义 XPath
    const artifactResolveXpath = "/*[local-name()='Envelope']/*[local-name()='Body']/*[local-name()='ArtifactResolve']";
    const artifactResponseXpath = "/*[local-name()='Envelope']/*[local-name()='Body']/*[local-name()='ArtifactResponse']";

    // 检测 ArtifactResolve 或 ArtifactResponse 的存在
    // @ts-expect-error
    const artifactResolveNodes = select(artifactResolveXpath, doc);
    // @ts-expect-error
    const artifactResponseNodes = select(artifactResponseXpath, doc);

    // 根据消息类型选择合适的 XPath
    let basePath = "";
    if (artifactResolveNodes.length > 0) {
      basePath = "/*[local-name()='Envelope']/*[local-name()='Body']/*[local-name()='ArtifactResolve']";
    } else if (artifactResponseNodes.length > 0) {
      basePath = "/*[local-name()='Envelope']/*[local-name()='Body']/*[local-name()='ArtifactResponse']";
    } else {
      throw new Error('ERR_UNSUPPORTED_SOAP_MESSAGE_TYPE');
    }

    // 基于 SOAP 结构重新定义 XPath
    const messageSignatureXpath = `${basePath}/*[local-name(.)='Signature']`;
    const assertionSignatureXpath = `${basePath}/*[local-name(.)='Response']/*[local-name(.)='Assertion']/*[local-name(.)='Signature']`;
    const wrappingElementsXPath = `${basePath}/*[local-name(.)='Response']/*[local-name(.)='Assertion']/*[local-name(.)='Subject']/*[local-name(.)='SubjectConfirmation']/*[local-name(.)='SubjectConfirmationData']//*[local-name(.)='Assertion' or local-name(.)='Signature']`;
    const encryptedAssertionsXpath = `${basePath}/*[local-name(.)='Response']/*[local-name(.)='EncryptedAssertion']`;

    // 包装攻击检测
    // @ts-expect-error
    const wrappingElementNode = select(wrappingElementsXPath, doc);
    if (wrappingElementNode.length !== 0) {
      throw new Error('ERR_POTENTIAL_WRAPPING_ATTACK');
    }

    // @ts-expect-error
    const encryptedAssertions = select(encryptedAssertionsXpath, doc);
    // @ts-expect-error
    const messageSignatureNode = select(messageSignatureXpath, doc);
    // @ts-expect-error
    const assertionSignatureNode = select(assertionSignatureXpath, doc);

    let selection: any[] = [];

    if (messageSignatureNode.length > 0) {
      selection = selection.concat(messageSignatureNode);
    }
    if (assertionSignatureNode.length > 0) {
      selection = selection.concat(assertionSignatureNode);
    }

    // 处理加密断言的情况
    if (selection.length === 0) {
      if (encryptedAssertions.length > 0) {
        if (encryptedAssertions.length > 1) {
          throw new Error('ERR_MULTIPLE_ASSERTION');
        }
        return [false, null, true, true];
      }
    }

    if (selection.length === 0) {
      throw new Error('ERR_ZERO_SIGNATURE');
    }

    // 尝试所有签名节点
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
        const certificateNode = select(".//*[local-name(.)='X509Certificate']", signatureNode) as any;

        // 证书处理逻辑
        let metadataCert: any = opts.metadata.getX509Certificate(certUse.signing);
        if (Array.isArray(metadataCert)) {
          metadataCert = flattenDeep(metadataCert);
        } else if (typeof metadataCert === 'string') {
          metadataCert = [metadataCert];
        }
        metadataCert = metadataCert.map(utility.normalizeCerString);

        // 没有证书的情况
        if (certificateNode.length === 0 && metadataCert.length === 0) {
          throw new Error('NO_SELECTED_CERTIFICATE');
        }

        if (certificateNode.length !== 0) {
          const x509CertificateData = certificateNode[0].firstChild.data;
          const x509Certificate = utility.normalizeCerString(x509CertificateData);

          if (metadataCert.length >= 1 && !metadataCert.includes(x509Certificate)) {
            throw new Error('ERROR_UNMATCH_CERTIFICATE_DECLARATION_IN_METADATA');
          }

          sig.publicCert = this.getKeyInfo(x509Certificate).getKey();
        } else {
          sig.publicCert = this.getKeyInfo(metadataCert[0]).getKey();
        }
      }

      sig.loadSignature(signatureNode);
      verified = sig.checkSignature(xml); // 使用原始XML验证

      if (!verified) {
        throw new Error('ERR_FAILED_TO_VERIFY_SIGNATURE');
      }

      if (sig.getSignedReferences().length < 1) {
        throw new Error('NO_SIGNATURE_REFERENCES');
      }
      const signedVerifiedXML = sig.getSignedReferences()[0];
      const rootNode = docParser.parseFromString(signedVerifiedXML, 'application/xml').documentElement;

      // 处理签名的内容
      switch(rootNode?.localName) {
        case 'Response':
          // @ts-expect-error
          const encryptedAssert = select("./*[local-name()='EncryptedAssertion']", rootNode);
          // @ts-expect-error
          const assertions = select("./*[local-name()='Assertion']", rootNode);

          if (encryptedAssert.length === 1) {
            return [true, encryptedAssert[0].toString(), true, false];
          }

          if (assertions.length === 1) {
            return [true, assertions[0].toString(), false, false];
          }
          return [true, null, false, true]; // 签名验证成功但未找到断言

        case 'Assertion':
          return [true, rootNode.toString(), false, false];

        case 'EncryptedAssertion':
          return [true, rootNode.toString(), true, false];

        case 'ArtifactResolve':
        case 'ArtifactResponse':
          // 提取SOAP消息内部的实际内容
          return [true, rootNode.toString(), false, false];

        default:
          return [true, null, false, true]; // 签名验证成功但未找到可识别的内容
      }
    }

    return [false, null, encryptedAssertions.length > 0, false];
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
            _attr: {use},
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
     * SAML 消息签名 (符合 SAML V2.0 绑定规范)
     * @param octetString - 要签名的原始数据 (OCTET STRING)
     * @param key - PEM 格式私钥
     * @param passphrase - 私钥密码 (如果有加密)
     * @param isBase64 - 是否返回 base64 编码 (默认 true)
     * @param signingAlgorithm - 签名算法 (默认 'rsa-sha256')
     * @returns 消息签名
     */



    constructMessageSignature(
      octetString: string,
      key: string,
      passphrase?: string,
      isBase64?: boolean,
      signingAlgorithm?: string
    ) {
      // Default returning base64 encoded signature
      // Embed with node-rsa module
      const decryptedKey = new nrsa(
        utility.readPrivateKey(key, passphrase),
        undefined,
        {
          signingScheme: getSigningScheme(signingAlgorithm),
        }
      );
      const signature = decryptedKey.sign(octetString);
      // Use private key to sign data
      return isBase64 !== false ? signature.toString('base64') : signature;
    },
    /*    verifyMessageSignature(
          metadata,
          octetString: string,
          signature: string | Buffer,
          verifyAlgorithm?: string
        ) {
          const signCert = metadata.getX509Certificate(certUse.signing);
          const signingScheme = getSigningSchemeForNode(verifyAlgorithm);
          const verifier = createVerify(signingScheme);
          verifier.update(octetString);
          const isValid = verifier.verify(utility.getPublicKeyPemFromCertificate(signCert), Buffer.isBuffer(signature) ? signature : Buffer.from(signature, 'base64'));
          return isValid

        },*/

    /**
     * @desc Verifies message signature
     * @param  {Metadata} metadata                 metadata object of identity provider or service provider
     * @param  {string} octetString                see "Bindings for the OASIS Security Assertion Markup Language (SAML V2.0)" P.17/46
     * @param  {string} signature                  context of XML signature
     * @param  {string} verifyAlgorithm            algorithm used to verify
     * @return {boolean} verification result
     */
    verifyMessageSignature(
      metadata,
      octetString: string,
      signature: string | Buffer,
      verifyAlgorithm?: string
    ) {
      const signCert = metadata.getX509Certificate(certUse.signing);
      const signingScheme = getSigningScheme(verifyAlgorithm);
      const key = new nrsa(utility.getPublicKeyPemFromCertificate(signCert), 'public', {signingScheme});
      return key.verify(Buffer.from(octetString), Buffer.from(signature));
    },
    /**
     * @desc Get the public key in string format
     * @param  {string} x509Certificate certificate
     * @return {string} public key
     */
    getKeyInfo(x509Certificate: string, signatureConfig: any = {}) {
      const prefix = signatureConfig.prefix ? `${signatureConfig.prefix}:` : '';
      return {
        getKeyInfo: () => {
          return `<${prefix}X509Data><${prefix}X509Certificate>${x509Certificate}</${prefix}X509Certificate></${prefix}X509Data>`;
        },
        getKey: () => {
          return utility.getPublicKeyPemFromCertificate(x509Certificate).toString();
        },
      };
    },
    /**
     * @desc Encrypt the assertion section in Response
     * @param  {Entity} sourceEntity             source entity
     * @param  {Entity} targetEntity             target entity
     * @param  {string} xml                      response in xml string format
     * @return {Promise} a promise to resolve the finalized xml
     */
    // tslint:disable-next-line:no-shadowed-variable
    encryptAssertion(sourceEntity, targetEntity, xml?: string) {
      // Implement encryption after signature if it has
      return new Promise<string>((resolve, reject) => {

        if (!xml) {
          return reject(new Error('ERR_UNDEFINED_ASSERTION'));
        }

        const sourceEntitySetting = sourceEntity.entitySetting;
        const targetEntityMetadata = targetEntity.entityMeta;
        const {dom} = getContext();
        const doc = dom.parseFromString(xml, 'application/xml');
        // @ts-expect-error misssing Node properties are not needed
        const assertions = select("//*[local-name(.)='Assertion']", doc) as Node[];
        if (!Array.isArray(assertions) || assertions.length === 0) {
          throw new Error('ERR_NO_ASSERTION');
        }
        if (assertions.length > 1) {
          throw new Error('ERR_MULTIPLE_ASSERTION');
        }
        const rawAssertionNode = assertions[0];
        // Perform encryption depends on the setting, default is false
        if (sourceEntitySetting.isAssertionEncrypted) {

          const publicKeyPem = utility.getPublicKeyPemFromCertificate(targetEntityMetadata.getX509Certificate(certUse.encrypt));

          xmlenc.encrypt(rawAssertionNode.toString(), {
            // use xml-encryption module
            rsa_pub: Buffer.from(publicKeyPem), // public key from certificate
            pem: Buffer.from(`-----BEGIN CERTIFICATE-----${targetEntityMetadata.getX509Certificate(certUse.encrypt)}-----END CERTIFICATE-----`),
            encryptionAlgorithm: sourceEntitySetting.dataEncryptionAlgorithm,
            keyEncryptionAlgorithm: sourceEntitySetting.keyEncryptionAlgorithm,
            /*       keyEncryptionDigest: 'SHA-512',*/
            disallowEncryptionWithInsecureAlgorithm: true,
            warnInsecureAlgorithm: true
          }, (err, res) => {
            if (err) {
              return reject(new Error('ERR_EXCEPTION_OF_ASSERTION_ENCRYPTION'));
            }
            if (!res) {
              return reject(new Error('ERR_UNDEFINED_ENCRYPTED_ASSERTION'));
            }
            const {encryptedAssertion: encAssertionPrefix} = sourceEntitySetting.tagPrefix;

            const encryptAssertionDoc = dom.parseFromString(`<${encAssertionPrefix}:EncryptedAssertion xmlns:${encAssertionPrefix}="${namespace.names.assertion}">${res}</${encAssertionPrefix}:EncryptedAssertion>`, 'application/xml');
            // @ts-expect-error misssing Node properties are not needed
            doc.documentElement.replaceChild(encryptAssertionDoc.documentElement, rawAssertionNode);
            return resolve(utility.base64Encode(doc.toString()));
          });
        } else {
          return resolve(utility.base64Encode(xml)); // No need to do encryption
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
        const {dom} = getContext();
        const doc = dom.parseFromString(entireXML, 'application/xml');
        // @ts-expect-error misssing Node properties are not needed

        const encryptedAssertions = select("/*[contains(local-name(), 'Response')]/*[local-name(.)='EncryptedAssertion']", doc) as Node[];
        if (!Array.isArray(encryptedAssertions) || encryptedAssertions.length === 0) {
          throw new Error('ERR_UNDEFINED_ENCRYPTED_ASSERTION');
        }
        if (encryptedAssertions.length > 1) {
          throw new Error('ERR_MULTIPLE_ASSERTION');
        }
        const encAssertionNode = encryptedAssertions[0];
        return xmlenc.decrypt(encAssertionNode.toString(), {
          key: utility.readPrivateKey(hereSetting.encPrivateKey, hereSetting.encPrivateKeyPass),
        }, (err, res) => {
          if (err) {
            return reject(new Error('ERR_EXCEPTION_OF_ASSERTION_DECRYPTION'));
          }
          if (!res) {
            return reject(new Error('ERR_UNDEFINED_ENCRYPTED_ASSERTION'));
          }
          const rawAssertionDoc = dom.parseFromString(res, 'application/xml');
          // @ts-ignore
          doc.documentElement.replaceChild(rawAssertionDoc.documentElement, encAssertionNode);
          return resolve([doc.toString(), res]);
        });
      });
    },

    /**
     * 解密 SOAP 响应中的加密断言
     * @param self 当前实体（SP 或 IdP）
     * @param entireXML 完整的 SOAP XML 响应
     * @returns [解密后的完整 SOAP XML, 解密后的断言 XML]
     */
    async decryptAssertionSoap(self: any, entireXML: string): Promise<[string, string]> {
      const {dom} = getContext();

      try {
        // 1. 解析 XML
        // @ts-ignore
        const doc = dom.parseFromString(entireXML, 'application/xml');

        // 2. 定位加密断言
        const encryptedAssertions = select(
          "/*[local-name()='Envelope']/*[local-name()='Body']" +
          "/*[local-name()='ArtifactResponse']/*[local-name()='Response']" +
          "/*[local-name()='EncryptedAssertion']",
          // @ts-ignore
          doc
        ) as Node[];

        if (!encryptedAssertions || encryptedAssertions.length === 0) {
          throw new Error('ERR_ENCRYPTED_ASSERTION_NOT_FOUND');
        }

        if (encryptedAssertions.length > 1) {
          console.warn('发现多个加密断言，仅处理第一个');
        }

        const encAssertionNode = encryptedAssertions[0];

        // 3. 准备解密密钥
        const privateKey = utility.readPrivateKey(
          self.entitySetting.encPrivateKey,
          self.entitySetting.encPrivateKeyPass
        );

        // 4. 解密断言
        const decryptedAssertion = await new Promise<string>((resolve, reject) => {
          xmlenc.decrypt(
            encAssertionNode.toString(),
            {key: privateKey},
            (err, result) => {
              if (err) {
                return reject(new Error('ERR_ASSERTION_DECRYPTION_FAILED'));
              }
              if (!result) {
                return reject(new Error('ERR_EMPTY_DECRYPTED_ASSERTION'));
              }
              resolve(result);
            }
          );
        });

        // 5. 创建解密断言的 DOM
        // @ts-ignore
        const decryptedDoc = dom.parseFromString(decryptedAssertion, 'application/xml');
        const decryptedAssertionNode = decryptedDoc.documentElement;

        // 6. 替换加密断言为解密后的断言
        const parentNode = encAssertionNode.parentNode;
        if (!parentNode) {
          throw new Error('ERR_NO_PARENT_NODE_FOR_ENCRYPTED_ASSERTION');
        }
        // @ts-ignore
        parentNode.replaceChild(decryptedAssertionNode, encAssertionNode);

        // 7. 序列化更新后的文档
        const updatedSoapXml = doc.toString();

        return [updatedSoapXml, decryptedAssertion];
      } catch (error) {
        throw new Error('ERR_SOAP_ASSERTION_DECRYPTION');
      }
    },
    /**
     * @desc Check if the xml string is valid and bounded
     */
    async isValidXml(input: string,soap: boolean = false) {

      // check if global api contains the validate function
      const {validate} = getContext();

      /**
       * user can write a validate function that always returns
       * a resolved promise and skip the validator even in
       * production, user will take the responsibility if
       * they intend to skip the validation
       */
      if (!validate) {

        // otherwise, an error will be thrown
        return Promise.reject('Your application is potentially vulnerable because no validation function found. Please read the documentation on how to setup the validator. (https://github.com/tngan/samlify#installation)');

      }

      try {
        return await validate(input,soap);
      } catch (e) {
        throw e;
      }

    },


  };
};

export default libSaml();
