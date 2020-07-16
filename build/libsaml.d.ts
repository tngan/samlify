/**
 * @file SamlLib.js
 * @author tngan
 * @desc  A simple library including some common functions
 */
/// <reference types="node" />
import { MetadataInterface } from "./metadata";
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
    nameid?: string;
    notexist?: boolean;
}
export interface LoginResponseAttribute {
    name: string;
    nameFormat: string;
    valueXsiType: string;
    valueTag: string;
    valueXmlnsXs?: string;
    valueXmlnsXsi?: string;
}
export interface BaseSamlTemplate {
    context: string;
}
export interface LoginResponseTemplate extends BaseSamlTemplate {
    attributes?: LoginResponseAttribute[];
}
export interface LoginRequestTemplate extends BaseSamlTemplate {
}
export interface LogoutRequestTemplate extends BaseSamlTemplate {
}
export interface LogoutResponseTemplate extends BaseSamlTemplate {
}
export declare type KeyUse = "signing" | "encryption";
export interface KeyComponent {
    [key: string]: any;
}
export interface LibSamlInterface {
    getQueryParamByType: (type: string) => string;
    createXPath: (local: any, isExtractAll?: boolean) => string;
    replaceTagsByValue: (rawXML: string, tagValues: any) => string;
    attributeStatementBuilder: (attributes: LoginResponseAttribute[]) => string;
    constructSAMLSignature: (opts: SignatureConstructor) => string;
    verifySignature: (xml: string, opts: any) => [boolean, any];
    createKeySection: (use: KeyUse, cert: string | Buffer) => {};
    constructMessageSignature: (octetString: string, key: string, passphrase?: string, isBase64?: boolean, signingAlgorithm?: string) => string;
    verifyMessageSignature: (metadata: any, octetString: string, signature: string | Buffer, verifyAlgorithm?: string) => boolean;
    getKeyInfo: (x509Certificate: string, signatureConfig?: any) => void;
    encryptAssertion: (sourceEntity: any, targetEntity: any, entireXML: string) => Promise<string>;
    decryptAssertion: (here: any, entireXML: string) => Promise<[string, any]>;
    getSigningScheme: (sigAlg: string) => string | null;
    getDigestMethod: (sigAlg: string) => string | null;
    nrsaAliasMapping: any;
    defaultLoginRequestTemplate: LoginRequestTemplate;
    defaultLoginResponseTemplate: LoginResponseTemplate;
    defaultLogoutRequestTemplate: LogoutRequestTemplate;
    defaultLogoutResponseTemplate: LogoutResponseTemplate;
}
declare const _default: {
    createXPath: (local: any, isExtractAll?: boolean | undefined) => string;
    getQueryParamByType: (type: string) => "SAMLRequest" | "SAMLResponse";
    defaultLoginRequestTemplate: {
        context: string;
    };
    defaultLoginResponseTemplate: {
        context: string;
        attributes: never[];
    };
    defaultLogoutRequestTemplate: {
        context: string;
    };
    defaultLogoutResponseTemplate: {
        context: string;
    };
    /**
     * @desc Repalce the tag (e.g. {tag}) inside the raw XML
     * @param  {string} rawXML      raw XML string used to do keyword replacement
     * @param  {array} tagValues    tag values
     * @return {string}
     */
    replaceTagsByValue(rawXML: string, tagValues: any): string;
    /**
     * @desc Helper function to build the AttributeStatement tag
     * @param  {LoginResponseAttribute} attributes    an array of attribute configuration
     * @return {string}
     */
    attributeStatementBuilder(attributes: LoginResponseAttribute[]): string;
    /**
     * @desc Construct the XML signature for POST binding
     * @return {string} base64 encoded string
     * @param opts
     */
    constructSAMLSignature(opts: SignatureConstructor): string;
    /**
     * @desc Verify the XML signature
     * @param  {string} xml xml
     * @param  {SignatureVerifierOptions} opts cert declares the X509 certificate
     * @return {boolean} verification result
     */
    verifySignature(xml: string, opts?: SignatureVerifierOptions | undefined): (string | boolean | null)[];
    /**
     * @desc Helper function to create the key section in metadata (abstraction for signing and encrypt use)
     * @param  {string} use          type of certificate (e.g. signing, encrypt)
     * @param  {string} certString    declares the certificate String
     * @return {object} object used in xml module
     */
    createKeySection(use: KeyUse, certString: string | Buffer): KeyComponent;
    /**
     * @desc Constructs SAML message
     * @param  {string} octetString               see "Bindings for the OASIS Security Assertion Markup Language (SAML V2.0)" P.17/46
     * @param  {string} key                       declares the pem-formatted private key
     * @param  {string} passphrase                passphrase of private key [optional]
     * @param isBase64
     * @param  {string} signingAlgorithm          signing algorithm
     * @return {string} message signature
     */
    constructMessageSignature(octetString: string, key: string, passphrase?: string | undefined, isBase64?: boolean | undefined, signingAlgorithm?: string | undefined): string | Buffer;
    /**
     * @desc Verifies message signature
     * @param  {Metadata} metadata                 metadata object of identity provider or service provider
     * @param  {string} octetString                see "Bindings for the OASIS Security Assertion Markup Language (SAML V2.0)" P.17/46
     * @param  {string} signature                  context of XML signature
     * @param  {string} verifyAlgorithm            algorithm used to verify
     * @return {boolean} verification result
     */
    verifyMessageSignature(metadata: any, octetString: string, signature: string | Buffer, verifyAlgorithm?: string | undefined): boolean;
    /**
     * @desc Get the public key in string format
     * @param  {string} x509Certificate certificate
     * @param signatureConfig
     * @return {string} public key
     */
    getKeyInfo(x509Certificate: string, signatureConfig?: any): void;
    /**
     * @desc Encrypt the assertion section in Response
     * @param  {Entity} sourceEntity             source entity
     * @param  {Entity} targetEntity             target entity
     * @param  {string} xml                      response in xml string format
     * @return {Promise} a promise to resolve the finalized xml
     */
    encryptAssertion(sourceEntity: any, targetEntity: any, xml?: string | undefined): Promise<string>;
    /**
     * @desc Decrypt the assertion section in Response
     * @param  {Entity} here             this entity
     * @param {string} entireXML         response in xml string format
     * @return {function} a promise to get back the entire xml with decrypted assertion
     */
    decryptAssertion(here: any, entireXML: string): Promise<[string, any]>;
    /**
     * @desc Check if the xml string is valid and bounded
     */
    isValidXml(input: string): Promise<any>;
};
export default _default;
