/**
 * @file urn.ts
 * @author tngan
 * @desc  Includes all keywords need in samlify
 */

export enum BindingNamespace {
  Redirect = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
  Post = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
  SimpleSign = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign',
  Artifact = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'
}

export enum MessageSignatureOrder {
  STE = 'sign-then-encrypt',
  ETS = 'encrypt-then-sign'
}

export enum StatusCode {
  // top-tier
  Success = 'urn:oasis:names:tc:SAML:2.0:status:Success',
  Requester = 'urn:oasis:names:tc:SAML:2.0:status:Requester',
  Responder = 'urn:oasis:names:tc:SAML:2.0:status:Responder',
  VersionMismatch = 'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch',
  // second-tier to provide more information
  AuthFailed = 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed',
  InvalidAttrNameOrValue = 'urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue',
  InvalidNameIDPolicy = 'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy',
  NoAuthnContext = 'urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext',
  NoAvailableIDP = 'urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP',
  NoPassive = 'urn:oasis:names:tc:SAML:2.0:status:NoPassive',
  NoSupportedIDP = 'urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP',
  PartialLogout = 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout',
  ProxyCountExceeded = 'urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded',
  RequestDenied = 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied',
  RequestUnsupported = 'urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported',
  RequestVersionDeprecated = 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated',
  RequestVersionTooHigh = 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh',
  RequestVersionTooLow = 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow',
  ResourceNotRecognized = 'urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized',
  TooManyResponses = 'urn:oasis:names:tc:SAML:2.0:status:TooManyResponses',
  UnknownAttrProfile = 'urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile',
  UnknownPrincipal = 'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal',
  UnsupportedBinding = 'urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding',
}

const namespace = {
  binding: {
    redirect: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    post: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    simpleSign: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign',
    artifact: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact',
    soap: 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP',
  },
  names: {
    protocol: 'urn:oasis:names:tc:SAML:2.0:protocol',
    assertion: 'urn:oasis:names:tc:SAML:2.0:assertion',
    metadata: 'urn:oasis:names:tc:SAML:2.0:metadata',
    userLogout: 'urn:oasis:names:tc:SAML:2.0:logout:user',
    adminLogout: 'urn:oasis:names:tc:SAML:2.0:logout:admin',
  },
  authnContextClassRef: {
    password: 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password',
    passwordProtectedTransport: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
  },
  format: {
    emailAddress: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    persistent: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    transient: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
    entity: 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
    unspecified: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    kerberos: 'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos',
    windowsDomainQualifiedName: 'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName',
    x509SubjectName: 'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName',
  },
  statusCode: {
    // permissible top-level status codes
    success: 'urn:oasis:names:tc:SAML:2.0:status:Success',
    requester: 'urn:oasis:names:tc:SAML:2.0:status:Requester',
    responder: 'urn:oasis:names:tc:SAML:2.0:status:Responder',
    versionMismatch: 'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch',
    // second-level status codes
    authFailed: 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed',
    invalidAttrNameOrValue: 'urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue',
    invalidNameIDPolicy: 'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy',
    noAuthnContext: 'urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext',
    noAvailableIDP: 'urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP',
    noPassive: 'urn:oasis:names:tc:SAML:2.0:status:NoPassive',
    noSupportedIDP: 'urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP',
    partialLogout: 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout',
    proxyCountExceeded: 'urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded',
    requestDenied: 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied',
    requestUnsupported: 'urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported',
    requestVersionDeprecated: 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated',
    requestVersionTooHigh: 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh',
    requestVersionTooLow: 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow',
    resourceNotRecognized: 'urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized',
    tooManyResponses: 'urn:oasis:names:tc:SAML:2.0:status:TooManyResponses',
    unknownAttrProfile: 'urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile',
    unknownPrincipal: 'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal',
    unsupportedBinding: 'urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding',
  },
};

const tags = {
  request: {
    AllowCreate: '{AllowCreate}',
    AssertionConsumerServiceURL: '{AssertionConsumerServiceURL}',
    AuthnContextClassRef: '{AuthnContextClassRef}',
    AssertionID: '{AssertionID}',
    Audience: '{Audience}',
    AuthnStatement: '{AuthnStatement}',
    AttributeStatement: '{AttributeStatement}',
    ConditionsNotBefore: '{ConditionsNotBefore}',
    ConditionsNotOnOrAfter: '{ConditionsNotOnOrAfter}',
    Destination: '{Destination}',
    EntityID: '{EntityID}',
    ID: '{ID}',
    Issuer: '{Issuer}',
    IssueInstant: '{IssueInstant}',
    InResponseTo: '{InResponseTo}',
    NameID: '{NameID}',
    NameIDFormat: '{NameIDFormat}',
    ProtocolBinding: '{ProtocolBinding}',
    SessionIndex: '{SessionIndex}',
    SubjectRecipient: '{SubjectRecipient}',
    SubjectConfirmationDataNotOnOrAfter: '{SubjectConfirmationDataNotOnOrAfter}',
    StatusCode: '{StatusCode}',
  },
  xmlTag: {
    loginRequest: 'AuthnRequest',
    logoutRequest: 'LogoutRequest',
    loginResponse: 'Response',
    logoutResponse: 'LogoutResponse',
  },
};

const messageConfigurations = {
  signingOrder: {
    SIGN_THEN_ENCRYPT: 'sign-then-encrypt',
    ENCRYPT_THEN_SIGN: 'encrypt-then-sign',
  },
};

const algorithms = {
  // 1. 签名算法定义 (SignatureMethod)
  signature: {
    // ❌ 原文错误修正：ECDSA 不能用 rsa-sha256 的 URI
    ECDSA_SHA256: 'http://www.w3.org/2007/05/xmldsig-more#ecdsa-sha256',
    ECDSA_SHA384: 'http://www.w3.org/2007/05/xmldsig-more#ecdsa-sha384',
    ECDSA_SHA512: 'http://www.w3.org/2007/05/xmldsig-more#ecdsa-sha512',

    DSA_SHA1:      'http://www.w3.org/2000/09/xmldsig#dsa-sha1',

    RSA_SHA1:      'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    RSA_SHA224:    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224',
    RSA_SHA256:    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', // 推荐
    RSA_SHA384:    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
    RSA_SHA512:    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',

    // XML Signature 1.1 PSS 填充 (更安全)
    RSA_PSS_SHA256: 'http://www.w3.org/2007/05/xmldsig-more#rsa-pss-sha256',

    // EdDSA (Ed25519)
    EDDSA_ED25519: 'http://www.w3.org/2007/05/xmldsig-more#eddsa-ed25519'
  },

  // 2. 摘要算法定义 (DigestMethod)
  // 注意：这里直接使用标准推荐的 URI，SHA-2xx 系列推荐使用 xmlenc 命名空间
  digest: {
    SHA1:   'http://www.w3.org/2000/09/xmldsig#sha1',
    SHA224: 'http://www.w3.org/2001/04/xmldsig-more#sha224', // 较少见，有时也用 xmlenc 但 xmldsig-more 更准确对应
    SHA256: 'http://www.w3.org/2001/04/xmlenc#sha256',       // ✅ 标准推荐
    SHA384: 'http://www.w3.org/2001/04/xmlenc#sha384',       // ✅ 标准推荐
    SHA512: 'http://www.w3.org/2001/04/xmlenc#sha512'        // ✅ 标准推荐
  },

  // 3. 映射关系表：给定一个签名算法 URI，它应该配合哪个摘要算法 URI？
  // 这修复了你原代码中 digest 字段作为 "Map" 的意图
  signatureToDigestMap: {
    'http://www.w3.org/2000/09/xmldsig#rsa-sha1':      'http://www.w3.org/2000/09/xmldsig#sha1',
    'http://www.w3.org/2000/09/xmldsig#dsa-sha1':      'http://www.w3.org/2000/09/xmldsig#sha1',

    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224': 'http://www.w3.org/2001/04/xmldsig-more#sha224',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384': 'http://www.w3.org/2001/04/xmlenc#sha384',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': 'http://www.w3.org/2001/04/xmlenc#sha512',

    'http://www.w3.org/2007/05/xmldsig-more#ecdsa-sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
    'http://www.w3.org/2007/05/xmldsig-more#ecdsa-sha384': 'http://www.w3.org/2001/04/xmlenc#sha384',
    'http://www.w3.org/2007/05/xmldsig-more#ecdsa-sha512': 'http://www.w3.org/2001/04/xmlenc#sha512',

    'http://www.w3.org/2007/05/xmldsig-more#rsa-pss-sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',

    // EdDSA 比较特殊，它内部硬编码了 SHA-512，但在 XML 结构中如果需要显式声明 DigestMethod，通常指向 SHA-512
    'http://www.w3.org/2007/05/xmldsig-more#eddsa-ed25519': 'http://www.w3.org/2001/04/xmlenc#sha512'
  },

  encryption: {
    data: {
// --- CBC 模式 (XML Enc 1.0 - 兼容性最好) ---
      AES_128_CBC: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
      AES_192_CBC: 'http://www.w3.org/2001/04/xmlenc#aes192-cbc',
      AES_256_CBC: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',

      // --- GCM 模式 (XML Enc 1.1 - 推荐，提供完整性保护) ---
      AES_128_GCM: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
      AES_192_GCM: 'http://www.w3.org/2009/xmlenc11#aes192-gcm',
      AES_256_GCM: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',

      // --- CTR 模式 (XML Enc 1.1) ---
      AES_128_CTR: 'http://www.w3.org/2009/xmlenc11#aes128-ctr',
      AES_192_CTR: 'http://www.w3.org/2009/xmlenc11#aes192-ctr',
      AES_256_CTR: 'http://www.w3.org/2009/xmlenc11#aes256-ctr',

      // --- 旧算法 (不推荐，仅用于遗留系统) ---
      TRIPLE_DES: 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'

    },
    /**
     * 密钥加密算法 (用于加密生成的 AES 会话密钥)
     * 这里包含了 RSA-OAEP 和 AES Key Wrap
     */
    key: {
      // --- RSA OAEP (推荐) ---
      // 默认使用 SHA-1 的 OAEP (XML Enc 1.0)
      RSA_OAEP_MGF1P: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',

      // XML Enc 1.1 的通用 OAEP (通常配合 DigestMethod 参数使用 SHA-256)
      RSA_OAEP:       'http://www.w3.org/2009/xmlenc11#rsa-oaep',

      // --- RSA PKCS#1 v1.5 (旧标准，不推荐，但广泛存在) ---
      RSA_1_5:        'http://www.w3.org/2001/04/xmlenc#rsa-1_5',

      // --- AES Key Wrap (用于对称密钥加密对称密钥的场景) ---
      AES_128_KW:     'http://www.w3.org/2001/04/xmlenc#kw-aes128',
      AES_192_KW:     'http://www.w3.org/2001/04/xmlenc#kw-aes192',
      AES_256_KW:     'http://www.w3.org/2001/04/xmlenc#kw-aes256',

      // --- AES GCM Key Wrap (XML Enc 1.1) ---
      AES_128_GCM_KW: 'http://www.w3.org/2009/xmlenc11#aes128-gcmkw',
      AES_192_GCM_KW: 'http://www.w3.org/2009/xmlenc11#aes192-gcmkw',
      AES_256_GCM_KW: 'http://www.w3.org/2009/xmlenc11#aes256-gcmkw',

    },
  },
};

// 使用示例：
// 如果你选择了 RSA_SHA256 签名
const selectedSigAlg = algorithms.signature.RSA_SHA256;
// 自动获取对应的摘要算法
const requiredDigestAlg = algorithms.signatureToDigestMap[selectedSigAlg];

console.log(`Signature: ${selectedSigAlg}`);
console.log(`Required Digest: ${requiredDigestAlg}`);
// 输出:
// Signature: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
// Required Digest: http://www.w3.org/2001/04/xmlenc#sha256

export enum ParserType {
  SAMLRequest = 'SAMLRequest',
  SAMLResponse = 'SAMLResponse',
  LogoutRequest = 'LogoutRequest',
  LogoutResponse = 'LogoutResponse'
}

const wording = {
  urlParams: {
    samlRequest: 'SAMLRequest',
    samlResponse: 'SAMLResponse',
    logoutRequest: 'LogoutRequest',
    logoutResponse: 'LogoutResponse',
    sigAlg: 'SigAlg',
    signature: 'Signature',
    relayState: 'RelayState',
  },
  binding: {
    redirect: 'redirect',
    post: 'post',
    simpleSign: 'simpleSign',
    artifact: 'artifact',
    soap: 'soap',
  },
  certUse: {
    signing: 'signing',
    encrypt: 'encryption',
  },
  metadata: {
    sp: 'metadata-sp',
    idp: 'metadata-idp',
  },
};

// https://wiki.shibboleth.net/confluence/display/CONCEPT/MetadataForSP
// some idps restrict the order of elements in entity descriptors
const elementsOrder = {
  default: ['KeyDescriptor', 'NameIDFormat', 'ArtifactResolutionService', 'SingleLogoutService', 'AssertionConsumerService', 'AttributeConsumingService'],
  onelogin: ['KeyDescriptor', 'NameIDFormat', 'ArtifactResolutionService', 'SingleLogoutService', 'AssertionConsumerService', 'AttributeConsumingService'],
  shibboleth: ['KeyDescriptor', 'ArtifactResolutionService', 'SingleLogoutService', 'NameIDFormat', 'AssertionConsumerService', 'AttributeConsumingService',],
};

export {namespace, tags, algorithms, wording, elementsOrder, messageConfigurations};
