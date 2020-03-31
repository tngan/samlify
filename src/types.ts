import { LoginResponseTemplate } from './libsaml';

export { IdentityProvider as IdentityProviderConstructor } from './entity-idp';
export { IdpMetadata as IdentityProviderMetadata } from './metadata-idp';

export { ServiceProvider as ServiceProviderConstructor } from './entity-sp';
export { SpMetadata as ServiceProviderMetadata } from './metadata-sp';

export type MetadataFile = string | Buffer;

export interface MetadataIdpOptions {
  entityID?: string;
  signingCert?: string | Buffer;
  encryptCert?: string | Buffer;
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
  signingCert?: string | Buffer;
  encryptCert?: string | Buffer;
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
  requestSignatureAlgorithm?: string;
  encPrivateKey?: string | Buffer;
  encPrivateKeyPass?: string | Buffer;
  assertionConsumerService?: Array<{ Binding: string, Location: string }>;
  singleLogoutService?: Array<{ isDefault?: boolean, Binding: string, Location: string }>;
  signatureConfig?: SignatureConfig;
  loginRequestTemplate?: SAMLDocumentTemplate;
  logoutRequestTemplate?: SAMLDocumentTemplate;
  signingCert?: string | Buffer;
  encryptCert?: string | Buffer;
  transformationAlgorithms?: string[];
  nameIDFormat?: string[];
  // will be deprecated soon
  relayState?: string;
  // https://github.com/tngan/samlify/issues/337
  clockDrifts?: [number, number];
};

export type IdentityProviderSettings = {
  metadata?: string | Buffer;

  /** signature algorithm */
  requestSignatureAlgorithm?: string;

  /** template of login response */
  loginResponseTemplate?: LoginResponseTemplate;

  /** template of logout request */
  logoutRequestTemplate?: SAMLDocumentTemplate;

  /** customized function used for generating request ID */
  generateID?: () => string;

  entityID?: string;
  privateKey?: string | Buffer;
  privateKeyPass?: string;
  signingCert?: string | Buffer;
  encryptCert?: string | Buffer; /** todo */
  nameIDFormat?: string[];
  singleSignOnService?: Array<{ isDefault?: boolean, Binding: string, Location: string }>;
  singleLogoutService?: Array<{ isDefault?: boolean, Binding: string, Location: string }>;
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
