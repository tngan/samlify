import type { SignedXml } from 'xml-crypto';
import type { EncryptionAlgorithm, KeyEncryptionAlgorithm } from 'xml-encryption';
import type { LoginResponseTemplate, LogoutResponseTemplate } from './libsaml';
import type { BindingNamespace, MessageSignatureOrder } from './urn';

interface SSOService {
	isDefault?: boolean;
	Binding: BindingNamespace;
	Location: string;
}

export type RequestSignatureAlgorithm =
	| 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
	| 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
	| 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';

// https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf (P.16, 18)
export interface MetaElement {
	AssertionConsumerService?: any[];
	AttributeConsumingService?: any[];
	KeyDescriptor?: any[];
	NameIDFormat?: any[];
	SingleLogoutService?: any[];
}

interface MetadataOptions {
	encryptCert?: string | Buffer;
	entityID?: string;
	nameIDFormat?: string[];
	signingCert?: string | Buffer;
	singleLogoutService?: SSOService[];
	singleSignOnService?: SSOService[];
}

interface MetadataIdpOptions extends MetadataOptions {
	requestSignatureAlgorithm?: RequestSignatureAlgorithm;
	wantAuthnRequestsSigned?: boolean;
}

interface MetadataSpOptions extends MetadataOptions {
	assertionConsumerService?: SSOService[];
	authnRequestsSigned?: boolean;
	elementsOrder?: (keyof MetaElement)[];
	// TODO: Not sure if this is used. Consider removing.
	signatureConfig?: Record<string, any>;
	wantAssertionsSigned?: boolean;
	wantMessageSigned?: boolean;
}

type MetadataFile = string | Buffer;

export type MetadataIdpConstructorOptions = MetadataIdpOptions | MetadataFile;
export type MetadataSpConstructorOptions = MetadataSpOptions | MetadataFile;

export interface SAMLDocumentTemplate {
	context?: string;
}

export type SignatureConfig = Parameters<SignedXml['computeSignature']>[1];

export interface EntitySettings {
	metadata?: string | Buffer;
	entityID?: string;
	assertionConsumerService?: SSOService[];
	singleLogoutService?: SSOService[];

	authnRequestsSigned?: boolean;
	isAssertionEncrypted?: boolean;

	/** signature algorithm */
	requestSignatureAlgorithm?: RequestSignatureAlgorithm;
	dataEncryptionAlgorithm?: EncryptionAlgorithm;
	keyEncryptionAlgorithm?: KeyEncryptionAlgorithm;

	messageSigningOrder?: MessageSignatureOrder;
	signatureConfig?: SignatureConfig;
	transformationAlgorithms?: string[];
	wantAssertionsSigned?: boolean;
	wantLogoutRequestSigned?: boolean;
	wantLogoutResponseSigned?: boolean;
	wantMessageSigned?: boolean;

	signingCert?: string | Buffer;
	privateKey?: string | Buffer;
	privateKeyPass?: string;

	encryptCert?: string | Buffer;
	encPrivateKey?: string | Buffer;
	encPrivateKeyPass?: string;

	/** template of login request */
	loginRequestTemplate?: SAMLDocumentTemplate;
	/** template of logout request */
	logoutRequestTemplate?: SAMLDocumentTemplate;
	/** template of logout response */
	logoutResponseTemplate?: LogoutResponseTemplate;

	nameIDFormat?: string[];
	allowCreate?: boolean;
	// will be deprecated soon
	relayState?: string;
	// https://github.com/tngan/samlify/issues/337
	clockDrifts?: [number, number];
	/** customized function used for generating request ID */
	generateID?: () => string;

	/** Declare the tag of specific xml document node. `TagPrefixKey` currently supports `encryptedAssertion` only */
	tagPrefix?: { encryptedAssertion?: string };
}

export interface ServiceProviderSettings extends EntitySettings {
	authnRequestsSigned?: boolean;
	wantAssertionsSigned?: boolean;
	wantMessageSigned?: boolean;
	assertionConsumerService?: SSOService[];
	loginRequestTemplate?: SAMLDocumentTemplate;
	logoutRequestTemplate?: SAMLDocumentTemplate;
	transformationAlgorithms?: string[];
	allowCreate?: boolean;
	// will be deprecated soon
	relayState?: string;
	// https://github.com/tngan/samlify/issues/337
	clockDrifts?: [number, number];
}

export interface IdentityProviderSettings extends EntitySettings {
	/** template of login response */
	loginResponseTemplate?: LoginResponseTemplate;

	singleSignOnService?: SSOService[];
	wantAuthnRequestsSigned?: boolean;
	wantLogoutRequestSignedResponseSigned?: boolean;
}

export interface ParsedLoginRequest {
	authnContextClassRef?: string;
	issuer?: string;
	nameIDPolicy?: { format?: string; allowCreate?: string };
	request?: { id?: string; issueInstant?: string; destination?: string; assertionConsumerServiceUrl?: string };
	signature?: string;
}
export interface ParsedLoginResponse {
	attributes?: Record<string, string>;
	audience?: string;
	conditions?: { notBefore: string; notOnOrAfter: string };
	issuer?: string;
	nameID?: string;
	response?: { id?: string; issueInstant?: string; destination?: string; inResponseTo?: string };
	sessionIndex?: { authnInstant?: string; sessionNotOnOrAfter?: string; sessionIndex?: string };
}
export interface ParsedLogoutRequest {
	request?: { id?: string; issueInstant?: string; destination?: string };
	issuer?: string;
	nameID?: string;
	signature?: string;
}
export interface ParsedLogoutResponse {
	response?: { id?: string; destination?: string; inResponseTo?: string };
	issuer?: string;
	signature?: string;
}
