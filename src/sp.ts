/**
 * Define the service provider interface, construction and feature
 */
import { v4 } from "uuid";
import { z } from "zod";
import { extract } from "./extractor";
import libsaml from "./libsaml";
import { SSOServiceConfig } from "./types";
import { namespace } from "./urn";
import xml from 'xml';

const SignatureConfig = z.object({
  prefix: z.string().optional(),
  location: z.object({
    reference: z.string().optional(),
    action: z.enum(['append', 'prepend', 'before', 'after']).optional()
  }).optional()
}).optional();

export type SignatureConfig = z.infer<typeof SignatureConfig>;

export const CreateProps = z.object({
  authnRequestsSigned: z.boolean().default(false),
  wantAssertionsSigned: z.boolean().default(false),
  wantMessageSigned: z.boolean().default(false),
  entityId: z.string().optional().default(v4()),
  signingCert: z.string().or(z.instanceof(Buffer)).optional(),
  encryptCert: z.string().or(z.instanceof(Buffer)).optional(),
  nameIDFormat: z.array(z.string()).optional().default([
    namespace.format.emailAddress
  ]),
  assertionConsumerService: SSOServiceConfig(1),
  singleLogoutService: SSOServiceConfig(0),
  signatureConfig: SignatureConfig,
  elementsOrder: z.array(z.string()).optional().default([])
});

export type CreateProps = z.infer<typeof CreateProps>;

const LoadProps = z.object({
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

export interface Metadata {
  wantAuthnRequestsSigned?: boolean;
  entityDescriptor?: any;
  singleSignOnService?: any;
  singleLogoutService?: any;
  entityID?: any;
  sharedCertificate?: any;
  certificate?: {
    signing: string;
    encryption: string;
  };
  nameIDFormat?: any;
}

/**
 * Easier interface to get access to essential props defined in metadata
 * 
 * @param xmlString 
 * @returns 
 */
const fetchEssentials = (xmlString: string): Metadata => {
  const metadata: Metadata = extract(xmlString, [
    {
      key: 'spSSODescriptor',
      localPath: ['EntityDescriptor', 'SPSSODescriptor'],
      attributes: ['WantAssertionsSigned', 'AuthnRequestsSigned'],
    },
    {
      key: 'assertionConsumerService',
      localPath: ['EntityDescriptor', 'SPSSODescriptor', 'AssertionConsumerService'],
      attributes: ['Binding', 'Location', 'isDefault', 'index'],
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

  if (metadata.sharedCertificate)  {
    metadata.certificate = {
      signing: metadata.sharedCertificate,
      encryption: metadata.sharedCertificate
    };
  }

  return metadata;

};

export interface ServiceProvider {
  id: string;
  metadata: Metadata;
  rawMetadata: string;
};

/**
 * Create function and returns a set of helper functions
 * 
 * @param props 
 * @returns 
 */
export const create = (props: CreateProps): ServiceProvider => {

  props = CreateProps.parse(props);

  // Prepare the payload for metadata construction
  let entityDescriptors: any = [{
    _attr: {
      AuthnRequestsSigned: String(props.authnRequestsSigned),
      WantAssertionsSigned: String(props.wantAssertionsSigned),
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

  props.assertionConsumerService.forEach((a, indexCount) => {
    entityDescriptors.push({
      AssertionConsumerService: [{
        _attr: {
          index: indexCount,
          Binding: a.binding,
          Location: a.location,
          isDefault: a.isDefault
        }
      }]
    });
  });

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

  // Logic to reorder the elements
  let reorderedEntityDescriptors = entityDescriptors;
  for (let element of props.elementsOrder) {
    const section = Object.keys(entityDescriptors)[element];
    if (section) {
      reorderedEntityDescriptors.push(entityDescriptors[element]);
    }
  }
  entityDescriptors = reorderedEntityDescriptors;

  // Build the metadata xml based on the pass-in props
  const metadataXml = xml([{
    EntityDescriptor: [{
      _attr: {
        entityID: props.entityId,
        'xmlns': namespace.names.metadata,
        'xmlns:assertion': namespace.names.assertion,
        'xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
      },
    }, { SPSSODescriptor: entityDescriptors }],
  }]);

  return {
    id: props.entityId,
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
export const load = (props: LoadProps): ServiceProvider => {

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