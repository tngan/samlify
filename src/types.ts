export { IdentityProvider as IdentityProviderConstructor } from './entity-idp';
export { IdpMetadata as IdentityProviderMetadata } from './metadata-idp';

export { ServiceProvider as ServiceProviderConstructor } from './entity-sp';
export { SpMetadata as ServiceProviderMetadata } from './metadata-sp';

export type MetadataFile = string | Buffer;

export interface MetadataIdpOptions {
  entityID?: string;
  signingCert?: string;
  encryptCert?: string;
  wantAuthnRequestsSigned?: boolean;
  nameIDFormat?: string[];
  singleSignOnService?: Array<{ isDefault?: boolean, Binding: string, Location: string }>;
  singleLogoutService?: Array<{ isDefault?: boolean, Binding: string, Location: string }>;
  requestSignatureAlgorithm?: string;
}

export type MetadataIdpConstructor =
  | MetadataIdpOptions
  | MetadataFile;

export interface MetadataSpOptions {
  entityID?: string;
  signingCert?: string;
  encryptCert?: string;
  authnRequestsSigned?: boolean;
  wantAssertionsSigned?: boolean;
  wantMessageSigned?: boolean;
  signatureConfig?: { [key: string]: any };
  nameIDFormat?: string[];
  singleLogoutService?: Array<{ isDefault?: boolean, Binding: string, Location: string }>;
  assertionConsumerService?: Array<{ isDefault?: boolean, Binding: string, Location: string }>;
  elementsOrder?: string[];
}

export type MetadataSpConstructor =
  | MetadataSpOptions
  | MetadataFile;

export interface EntitySetting {
  wantAuthnRequestsSigned?: boolean;
  authnRequestsSigned?: boolean;
  wantLogoutResponseSigned?: boolean;
  wantLogoutRequestSigned?: boolean;
  wantAssertionsSigned?: boolean;
  relayState?: any;
}

export interface ServiceProviderSettings {
  metadata?: string | Buffer;
  authnRequestsSigned?: boolean;
  wantAssertionsSigned?: boolean;
  wantMessageSigned?: boolean;
  privateKey?: string | Buffer;
  privateKeyPass?: string;
  isAssertionEncrypted?: boolean;
  encPrivateKey?: string | Buffer;
  encPrivateKeyPass?: string | Buffer;
  assertionConsumerService?: Array<{ Binding: string, Location: string }>;
  singleLogoutService?: Array<{ Binding: string, Location: string }>;
}

export interface IdentityProviderSettings {
  metadata?: string | Buffer;

  /** signature algorithm */
  requestSignatureAlgotithm?: string;

  /** template of login response */
  loginResponseTemplate?: { [key: string]: any };

  /** template of login response */
  logoutRequestTemplate?: { [key: string]: any };

  /** customized function used for generating request ID */
  generateID?: () => string;

  entityID?: string;
  privateKey?: string | Buffer;
  privateKeyPass?: string;
  signingCert?: string;
  encrpytCert?: string; /** todo */
  nameIDFormat?: string[];
  singleSignOnService?: Array<{ [key: string]: string }>;
  singleLogoutService?: Array<{ [key: string]: string }>;
  isAssertionEncrypted?: boolean;
  encPrivateKey?: string | Buffer;
  encPrivateKeyPass?: string;
  messageSigningOrder?: string;
  wantLogoutRequestSigned?: boolean;
  wantLogoutResponseSigned?: boolean;
  wantAuthnRequestsSigned?: boolean;
  wantLogoutRequestSignedResponseSigned?: boolean;
  tagPrefix?: { [key: string]: string };
}
