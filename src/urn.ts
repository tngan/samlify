/**
 * @file urn.ts
 * @author tngan
 * @desc  Includes all keywords need in samlify
 */
export enum BindingNamespace {
	Redirect = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
	Post = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
	Artifact = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact',
}

export enum MessageSignatureOrder {
	STE = 'sign-then-encrypt',
	ETS = 'encrypt-then-sign',
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

export const names = {
	protocol: 'urn:oasis:names:tc:SAML:2.0:protocol',
	assertion: 'urn:oasis:names:tc:SAML:2.0:assertion',
	metadata: 'urn:oasis:names:tc:SAML:2.0:metadata',
	logout: {
		user: 'urn:oasis:names:tc:SAML:2.0:logout:user',
		admin: 'urn:oasis:names:tc:SAML:2.0:logout:admin',
	},
	// authnContextClassRef
	ac: {
		Password: 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password',
		PasswordProtectedTransport: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
		unspecified: 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified',
	},
	nameidFormat: {
		emailAddress: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
		persistent: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
		transient: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
		entity: 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
		unspecified: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
		kerberos: 'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos',
		WindowsDomainQualifiedName: 'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName',
		X509SubjectName: 'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName',
	},
	attrnameFormat: {
		basic: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
		unspecified: 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified',
	},
} as const;

export const tags = {
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
} as const;

export const messageConfigurations = {
	signingOrder: {
		SIGN_THEN_ENCRYPT: 'sign-then-encrypt',
		ENCRYPT_THEN_SIGN: 'encrypt-then-sign',
	},
} as const;

export const algorithms = {
	signature: {
		RSA_SHA1: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
		RSA_SHA256: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
		RSA_SHA512: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
	},
	encryption: {
		data: {
			AES_128: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
			AES_256: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
			TRI_DEC: 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc',
			AES_128_GCM: 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
		},
		key: {
			RSA_OAEP_MGF1P: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
			RSA_1_5: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5', // no longer the default
		},
	},
	digest: {
		'http://www.w3.org/2000/09/xmldsig#rsa-sha1': 'http://www.w3.org/2000/09/xmldsig#sha1',
		'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
		'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': 'http://www.w3.org/2001/04/xmlenc#sha512', // support hashing algorithm sha512 in xml-crypto after 0.8.0
	},
} as const;

export enum ParserType {
	SAMLRequest = 'SAMLRequest',
	SAMLResponse = 'SAMLResponse',
	LogoutRequest = 'LogoutRequest',
	LogoutResponse = 'LogoutResponse',
}

export const wording = {
	urlParams: {
		samlRequest: 'SAMLRequest',
		samlResponse: 'SAMLResponse',
		logoutRequest: 'LogoutRequest',
		logoutResponse: 'LogoutResponse',
		sigAlg: 'SigAlg',
		signature: 'Signature',
		relayState: 'RelayState',
	},
	certUse: {
		signing: 'signing',
		encrypt: 'encryption',
	},
} as const;

// https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf (P.16, 18)
export interface MetaElement {
	AssertionConsumerService?: any[];
	AttributeConsumingService?: any[];
	KeyDescriptor?: any[];
	NameIDFormat?: any[];
	SingleLogoutService?: any[];
}

// https://wiki.shibboleth.net/confluence/display/CONCEPT/MetadataForSP
// some idps restrict the order of elements in entity descriptors
export const elementsOrder = {
	default: [
		'KeyDescriptor',
		'NameIDFormat',
		'SingleLogoutService',
		'AssertionConsumerService',
	] as (keyof MetaElement)[],
	onelogin: [
		'KeyDescriptor',
		'NameIDFormat',
		'SingleLogoutService',
		'AssertionConsumerService',
	] as (keyof MetaElement)[],
	shibboleth: [
		'KeyDescriptor',
		'SingleLogoutService',
		'NameIDFormat',
		'AssertionConsumerService',
		'AttributeConsumingService',
	] as (keyof MetaElement)[],
} as const;
