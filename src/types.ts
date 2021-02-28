import type { EncryptionAlgorithm, KeyEncryptionAlgorithm } from 'xml-encryption';
import type { LoginResponseTemplate, LogoutResponseTemplate } from './libsaml';
import type { BindingNamespace } from './urn';

export { IdentityProvider as IdentityProviderConstructor } from './entity-idp';
export { ServiceProvider as ServiceProviderConstructor } from './entity-sp';
export { MetadataIdp as IdentityProviderMetadata } from './metadata-idp';
export { MetadataSp as ServiceProviderMetadata } from './metadata-sp';

export type MetadataFile = string | Buffer;

type SSOService = {
	isDefault?: boolean;
	Binding: BindingNamespace;
	Location: string;
};

export type RequestSignatureAlgorithm =
	| 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
	| 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
	| 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';

export interface MetadataIdpOptions {
	entityID?: string;
	signingCert?: string | Buffer;
	encryptCert?: string | Buffer;
	wantAuthnRequestsSigned?: boolean;
	nameIDFormat?: string[];
	singleSignOnService?: SSOService[];
	singleLogoutService?: SSOService[];
	requestSignatureAlgorithm?: RequestSignatureAlgorithm;
}

export type MetadataIdpConstructorOptions = MetadataIdpOptions | MetadataFile;

// https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf (P.16, 18)
export interface MetaElement {
	KeyDescriptor?: any[];
	NameIDFormat?: any[];
	SingleLogoutService?: any[];
	AssertionConsumerService?: any[];
	AttributeConsumingService?: any[];
}

export interface MetadataSpOptions {
	entityID?: string;
	signingCert?: string | Buffer;
	encryptCert?: string | Buffer;
	authnRequestsSigned?: boolean;
	wantAssertionsSigned?: boolean;
	wantMessageSigned?: boolean;
	signatureConfig?: { [key: string]: any };
	nameIDFormat?: string[];
	singleSignOnService?: SSOService[];
	singleLogoutService?: SSOService[];
	assertionConsumerService?: SSOService[];
	elementsOrder?: (keyof MetaElement)[];
}

export type MetadataSpConstructorOptions = MetadataSpOptions | MetadataFile;

export type EntitySetting = ServiceProviderSettings & IdentityProviderSettings;

export interface SignatureConfig {
	prefix?: string;
	location?: {
		reference?: string;
		action?: 'append' | 'prepend' | 'before' | 'after';
	};
}

export interface SAMLDocumentTemplate {
	context?: string;
}

export type ServiceProviderSettings = {
	metadata?: string | Buffer;
	entityID?: string;
	authnRequestsSigned?: boolean;
	wantAssertionsSigned?: boolean;
	wantMessageSigned?: boolean;
	wantLogoutResponseSigned?: boolean;
	wantLogoutRequestSigned?: boolean;
	privateKey?: string | Buffer;
	privateKeyPass?: string;
	isAssertionEncrypted?: boolean;
	requestSignatureAlgorithm?: RequestSignatureAlgorithm;
	encPrivateKey?: string | Buffer;
	encPrivateKeyPass?: string | Buffer;
	assertionConsumerService?: SSOService[];
	singleLogoutService?: SSOService[];
	signatureConfig?: SignatureConfig;
	loginRequestTemplate?: SAMLDocumentTemplate;
	logoutRequestTemplate?: SAMLDocumentTemplate;
	signingCert?: string | Buffer;
	encryptCert?: string | Buffer;
	transformationAlgorithms?: string[];
	nameIDFormat?: string[];
	allowCreate?: boolean;
	// will be deprecated soon
	relayState?: string;
	// https://github.com/tngan/samlify/issues/337
	clockDrifts?: [number, number];
};

export type IdentityProviderSettings = {
	metadata?: string | Buffer;

	/** signature algorithm */
	requestSignatureAlgorithm?: RequestSignatureAlgorithm;
	dataEncryptionAlgorithm?: EncryptionAlgorithm;
	keyEncryptionAlgorithm?: KeyEncryptionAlgorithm;

	/** template of login response */
	loginResponseTemplate?: LoginResponseTemplate;

	/** template of logout response */
	logoutResponseTemplate?: LogoutResponseTemplate;

	/** customized function used for generating request ID */
	generateID?: () => string;

	entityID?: string;
	privateKey?: string | Buffer;
	privateKeyPass?: string;
	signingCert?: string | Buffer;
	encryptCert?: string | Buffer /** todo */;
	nameIDFormat?: string[];
	singleSignOnService?: SSOService[];
	singleLogoutService?: SSOService[];
	isAssertionEncrypted?: boolean;
	encPrivateKey?: string | Buffer;
	encPrivateKeyPass?: string;
	messageSigningOrder?: string;
	wantLogoutRequestSigned?: boolean;
	wantLogoutResponseSigned?: boolean;
	wantAuthnRequestsSigned?: boolean;
	wantLogoutRequestSignedResponseSigned?: boolean;
	tagPrefix?: { [key: string]: string };
};
