/**
 * Define the identity provider interface, construction and feature
 * 
 * Usage:
 * 
 * const idp = create(props);
 * const sp = create(props);
 * 
 * // Perform the validation and pre-operation check before running into problem
 * // during runtime
 * 
 * const app = bind(idp, sp);
 * 
 * app.createLoginRequest();
 * app.createLogoutRequest();
 * app.processLoginRequest();
 * app.processLogoutRequest();
 * 
 */

import { v4 } from "uuid";
import { z } from "zod";
import { extract } from "./extractor";
import libsaml from "./libsaml";
import xml from 'xml';
import { namespace } from "./urn";

const SSOServiceConfig = (minConfig: number = 1) => z.array(z.object({
  isDefault: z.boolean().optional().default(false),
  binding: z.string(),
  location: z.string()
})).refine((arg) => arg.length >= minConfig);

export const CreateProps = z.object({
  // required
  wantAuthnRequestsSigned: z.boolean().default(false),
  // optional
  entityID: z.string().optional().default(v4()),
  signingCert: z.string().or(z.instanceof(Buffer)).optional(),
  encryptCert: z.string().or(z.instanceof(Buffer)).optional(),
  requestSignatureAlgorithm: z.string().optional(),
  nameIDFormat: z.array(z.string()).optional().default([]),
  singleSignOnService: SSOServiceConfig(1),
  singleLogoutService: SSOServiceConfig(0)
});

export type CreateProps = z.infer<typeof CreateProps>;

export const LoadProps = z.object({
  metadata: z.string().startsWith('http').or(z.string()),
  extractions: z.array(
    z.object({
      key: z.string(),
      localPath: z.array(z.string()),
      attributes: z.array(z.string()),
      index: z.array(z.string()).optional(),
      attributePath: z.array(z.string()).optional(),
      context: z.boolean().optional()
    })
  ).default([])
});

export type LoadProps = z.infer<typeof LoadProps>;

export interface IdentityProvider {
  id: string,
  metadata: Metadata;
  rawMetadata: string;
};

export interface Metadata {
  wantAuthnRequestsSigned?: boolean;
  sharedCertificate?: any;
  entityDescriptor?: any;
  singleSignOnService?: any;
  singleLogoutService?: any;
  entityID?: any;
  certificate?: any;
  nameIDFormat?: any;
}

/**
 * Easier interface to get access to essential props defined in metadata
 * 
 * @param xmlString 
 * @returns 
 */
const fetchEssentials = (xmlString: string): Metadata => {
  return extract(xmlString, [
    {
      key: 'wantAuthnRequestsSigned',
      localPath: ['EntityDescriptor', 'IDPSSODescriptor'],
      attributes: ['WantAuthnRequestsSigned'],
    },
    {
      key: 'singleSignOnService',
      localPath: ['EntityDescriptor', 'IDPSSODescriptor', 'SingleSignOnService'],
      index: ['Binding'],
      attributePath: [],
      attributes: ['Location']
    },
    {
      key: 'entityDescriptor',
      localPath: ['EntityDescriptor'],
      attributes: [],
      context: true
    },
    {
      key: 'entityID',
      localPath: ['EntityDescriptor'],
      attributes: ['entityID']
    },
    {
      // shared certificate for both encryption and signing
      key: 'sharedCertificate',
      localPath: ['EntityDescriptor', '~SSODescriptor', 'KeyDescriptor', 'KeyInfo', 'X509Data', 'X509Certificate'],
      attributes: []
    },
    {
      // explicit certificate declaration for encryption and signing
      key: 'certificate',
      localPath: ['EntityDescriptor', '~SSODescriptor', 'KeyDescriptor'],
      index: ['use'],
      attributePath: ['KeyInfo', 'X509Data', 'X509Certificate'],
      attributes: []
    },
    {
      key: 'singleLogoutService',
      localPath: ['EntityDescriptor', '~SSODescriptor', 'SingleLogoutService'],
      attributes: ['Binding', 'Location']
    },
    {
      key: 'nameIDFormat',
      localPath: ['EntityDescriptor', '~SSODescriptor', 'NameIDFormat'],
      attributes: [],
    }
  ]);

};

/**
 * Create function and returns a set of helper functions
 * 
 * @param props 
 * @returns 
 */
export const create = (props: CreateProps): IdentityProvider => {

  props = CreateProps.parse(props);

  // Prepare the payload for metadata construction
  const entityDescriptors: any = [{
    _attr: {
      WantAuthnRequestsSigned: String(props.wantAuthnRequestsSigned),
      protocolSupportEnumeration: namespace.names.protocol,
    },
  }];

  if (props.signingCert) {
    entityDescriptors.push(libsaml.createKeySection('signing', props.signingCert));
  }

  if (props.encryptCert) {
    entityDescriptors.push(libsaml.createKeySection('encryption', props.encryptCert));
  }

  if (props.nameIDFormat.length > 0) {
    props.nameIDFormat.forEach(f => entityDescriptors.push({ NameIDFormat: f }));
  }

  // TODO: throw ERR_IDP_METADATA_MISSING_SINGLE_SIGN_ON_SERVICE
  props.singleSignOnService.forEach((a, indexCount) => {
    entityDescriptors.push({
      SingleSignOnService: [{
        _attr: {
          Binding: a.binding,
          Location: a.location,
          isDefault: a.isDefault
        }
      }]
    });
  });

  // 
  props.singleLogoutService.forEach((a, indexCount) => {
    entityDescriptors.push({
      SingleLogoutService: [{
        _attr: {
          Binding: a.binding,
          Location: a.location,
          isDefault: a.isDefault
        }
      }]
    });
  });

  // Build the metadata xml based on the pass-in props
  const metadataXml = xml([{
    EntityDescriptor: [{
      _attr: {
        'xmlns': namespace.names.metadata,
        'xmlns:assertion': namespace.names.assertion,
        'xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
        props.entityID,
      },
    }, { IDPSSODescriptor: entityDescriptors }],
  }]);

  return {
    id: props.entityID,
    metadata: fetchEssentials(metadataXml.toString()),
    rawMetadata: metadataXml.toString()
  };

}

/**
 * Create an idp by import a metadata, we separate the creation via metadata or create via object
 * 
 * @param props 
 * @returns 
 */
export const load = (props: LoadProps): IdentityProvider => {

  props = LoadProps.parse(props);

  // Load from url or file
  const online = props.metadata.startsWith('http');

  let xmlString: string = '';

  // Get the metadata file from online
  if (online) {
    // TODO
  }

  // Load the metadata file as xml string
  if (!online) {
    xmlString = props.metadata.toString();
  }

  // Fetch essential from its metadata
  const metadata: Metadata = fetchEssentials(xmlString);

  return {
    id: metadata.entityID,
    metadata: metadata,
    rawMetadata: xmlString
  }

};