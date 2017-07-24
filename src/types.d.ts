export { IdentityProvider } from './entity-idp';
export { IdpMetadata as IdentityProviderMetadata } from './metadata-idp';

export { ServiceProvider } from './entity-sp';
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
