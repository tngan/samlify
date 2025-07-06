import type { MetadataInterface } from './metadata.js';
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
    nameFormat: string;
    valueXsiType: string;
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
    createXPath: (local: any, isExtractAll?: boolean) => string;
    replaceTagsByValue: (rawXML: string, tagValues: any) => string;
    attributeStatementBuilder: (attributes: LoginResponseAttribute[], attributeTemplate: AttributeTemplate, attributeStatementTemplate: AttributeStatementTemplate) => string;
    constructSAMLSignature: (opts: SignatureConstructor) => string;
    verifySignature: (xml: string, opts: SignatureVerifierOptions) => [boolean, any];
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
    defaultAttributeStatementTemplate: AttributeStatementTemplate;
    defaultAttributeTemplate: AttributeTemplate;
    defaultLogoutRequestTemplate: LogoutRequestTemplate;
    defaultLogoutResponseTemplate: LogoutResponseTemplate;
}
declare const _default: {
    createXPath: (local: any, isExtractAll?: boolean) => string;
    getQueryParamByType: (type: string) => "SAMLRequest" | "SAMLResponse";
    defaultLoginRequestTemplate: {
        context: string;
    };
    defaultArtAuthnRequestTemplate: {
        context: string;
    };
    defaultArtifactResolveTemplate: {
        context: string;
    };
    defaultLoginResponseTemplate: {
        context: string;
        attributes: never[];
        additionalTemplates: {
            attributeStatementTemplate: {
                context: string;
            };
            attributeTemplate: {
                context: string;
            };
        };
    };
    defaultAttributeStatementTemplate: {
        context: string;
    };
    defaultAttributeTemplate: {
        context: string;
    };
    defaultLogoutRequestTemplate: {
        context: string;
    };
    defaultLogoutResponseTemplate: {
        context: string;
    };
    defaultAttributeValueTemplate: {
        context: string;
    };
    validateAndInflateSamlResponse: (urlEncodedResponse: any) => Promise<{
        compressed: boolean;
        xml: string;
        error: boolean;
    }> | {
        compressed: boolean;
        xml: string;
        error: null;
    };
    /**
     * @desc Replace the tag (e.g. {tag}) inside the raw XML
     * @param  {string} rawXML      raw XML string used to do keyword replacement
     * @param  {array} tagValues    tag values
     * @return {string}
     */
    replaceTagsByValue(rawXML: string, tagValues: Record<string, unknown>): string;
    /**
     * @desc Helper function to build the AttributeStatement tag
     * @param  {LoginResponseAttribute} attributes    an array of attribute configuration
     * @param  {AttributeTemplate} attributeTemplate    the attribute tag template to be used
     * @param  {AttributeStatementTemplate} attributeStatementTemplate    the attributeStatement tag template to be used
     * @return {string}
     */
    /** For Test */
    attributeStatementBuilder(attributeData: any[]): string;
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
    constructSAMLSignature(opts: SignatureConstructor): string;
    /**
     * @desc Verify the XML signature
     * @param  {string} xml xml
     * @param  {SignatureVerifierOptions} opts cert declares the X509 certificate
     * @return {[boolean, string | null]} - A tuple where:
     *   - The first element is `true` if the signature is valid, `false` otherwise.
     *   - The second element is the cryptographically authenticated assertion node as a string, or `null` if not found.
     */
    verifySignature(xml: string, opts: SignatureVerifierOptions): (string | boolean)[] | (boolean | null)[];
    verifySignatureSoap(xml: string, opts: SignatureVerifierOptions & {
        isAssertion?: boolean;
    }): (string | boolean)[];
    /**
     * @desc Helper function to create the key section in metadata (abstraction for signing and encrypt use)
     * @param  {string} use          type of certificate (e.g. signing, encrypt)
     * @param  {string} certString    declares the certificate String
     * @return {object} object used in xml module
     */
    createKeySection(use: KeyUse, certString: string | Buffer): KeyComponent;
    /**
     * SAML 消息签名 (符合 SAML V2.0 绑定规范)
     * @param octetString - 要签名的原始数据 (OCTET STRING)
     * @param key - PEM 格式私钥
     * @param passphrase - 私钥密码 (如果有加密)
     * @param isBase64 - 是否返回 base64 编码 (默认 true)
     * @param signingAlgorithm - 签名算法 (默认 'rsa-sha256')
     * @returns 消息签名
     */
    constructMessageSignature(octetString: string | Buffer, key: string | Buffer, passphrase?: string, isBase64?: boolean, signingAlgorithm?: string): string | Buffer;
    verifyMessageSignature(metadata: any, octetString: string, signature: string | Buffer, verifyAlgorithm?: string): boolean;
    /**
     * @desc Get the public key in string format
     * @param  {string} x509Certificate certificate
     * @return {string} public key
     */
    getKeyInfo(x509Certificate: string, signatureConfig?: any): {
        getKeyInfo: () => string;
        getKey: () => string;
    };
    /**
     * @desc Encrypt the assertion section in Response
     * @param  {Entity} sourceEntity             source entity
     * @param  {Entity} targetEntity             target entity
     * @param  {string} xml                      response in xml string format
     * @return {Promise} a promise to resolve the finalized xml
     */
    encryptAssertion(sourceEntity: any, targetEntity: any, xml?: string): Promise<string>;
    /**
     * @desc Decrypt the assertion section in Response
     * @param  {string} type             only accept SAMLResponse to proceed decryption
     * @param  {Entity} here             this entity
     * @param  {Entity} from             from the entity where the message is sent
     * @param {string} entireXML         response in xml string format
     * @return {function} a promise to get back the entire xml with decrypted assertion
     */
    decryptAssertion(here: any, entireXML: string): Promise<[string, any]>;
    /**
     * 解密 SOAP 响应中的加密断言
     * @param self 当前实体（SP 或 IdP）
     * @param entireXML 完整的 SOAP XML 响应
     * @returns [解密后的完整 SOAP XML, 解密后的断言 XML]
     */
    decryptAssertionSoap(self: any, entireXML: string): Promise<[string, string]>;
    /**
     * @desc Check if the xml string is valid and bounded
     */
    isValidXml(input: string): Promise<any>;
};
export default _default;
//# sourceMappingURL=libsaml.d.ts.map