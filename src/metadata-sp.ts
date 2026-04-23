/**
 * @file metadata-sp.ts
 * @author tngan
 * @desc Metadata of a service provider (SP). Accepts either a raw XML
 * document or a structured options object and presents a normalised API.
 */
import Metadata, { MetadataInterface } from './metadata';
import {
  MetadataSpConstructor,
  MetadataSpOptions,
  XmlElementArray,
  XmlAttributeMap,
} from './types';
import { namespace, elementsOrder as order } from './urn';
import libsaml from './libsaml';
import { castArrayOpt, isNonEmptyArray, isString } from './utility';
import xml from 'xml';

/** Public interface exposed by SP metadata instances. */
export interface SpMetadataInterface extends MetadataInterface {
}

/**
 * Element slots used to enforce the SP descriptor ordering permitted by
 * the SAML metadata schema.
 * @see https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf (P.16, 18)
 */
interface MetaElement {
  KeyDescriptor: XmlElementArray;
  NameIDFormat: XmlElementArray;
  SingleLogoutService: XmlElementArray;
  AssertionConsumerService: XmlElementArray;
  AttributeConsumingService: XmlElementArray;
}

/**
 * Factory returning a new {@link SpMetadata} instance.
 *
 * @param meta XML metadata document or structured options
 * @returns fresh SpMetadata
 */
export default function (meta: MetadataSpConstructor): SpMetadata {
  return new SpMetadata(meta);
}

/**
 * SP metadata abstraction — constructs a valid EntityDescriptor/SPSSODescriptor
 * from options, and exposes inspection helpers used by the flow layer.
 */
export class SpMetadata extends Metadata {

  /**
   * Build SP metadata from XML or programmatic options.
   *
   * @param meta XML string/Buffer or {@link MetadataSpOptions}
   */
  constructor(meta: MetadataSpConstructor) {
    const isFile = isString(meta) || meta instanceof Buffer;

    if (!isFile) {
      const {
        elementsOrder = order.default,
        entityID,
        signingCert,
        encryptCert,
        authnRequestsSigned = false,
        wantAssertionsSigned = false,
        wantMessageSigned = false,
        signatureConfig,
        nameIDFormat = [],
        singleLogoutService = [],
        assertionConsumerService = [],
      } = meta as MetadataSpOptions;

      const descriptors: MetaElement = {
        KeyDescriptor: [],
        NameIDFormat: [],
        SingleLogoutService: [],
        AssertionConsumerService: [],
        AttributeConsumingService: [],
      };

      const SPSSODescriptor: XmlElementArray = [{
        _attr: {
          AuthnRequestsSigned: String(authnRequestsSigned),
          WantAssertionsSigned: String(wantAssertionsSigned),
          protocolSupportEnumeration: namespace.names.protocol,
        },
      }];

      if (wantMessageSigned && signatureConfig === undefined) {
        console.warn('Construct service provider - missing signatureConfig');
      }

      for (const cert of castArrayOpt(signingCert)) {
        const section = libsaml.createKeySection('signing', cert) as { KeyDescriptor: XmlElementArray };
        descriptors.KeyDescriptor.push(section.KeyDescriptor);
      }

      for (const cert of castArrayOpt(encryptCert)) {
        const section = libsaml.createKeySection('encryption', cert) as { KeyDescriptor: XmlElementArray };
        descriptors.KeyDescriptor.push(section.KeyDescriptor);
      }

      if (isNonEmptyArray(nameIDFormat)) {
        nameIDFormat.forEach(f => descriptors.NameIDFormat.push(f));
      } else {
        descriptors.NameIDFormat.push(namespace.format.emailAddress);
      }

      if (isNonEmptyArray(singleLogoutService)) {
        singleLogoutService.forEach(a => {
          const attr: XmlAttributeMap = {
            Binding: a.Binding,
            Location: a.Location,
          };
          if (a.isDefault) {
            attr.isDefault = true;
          }
          descriptors.SingleLogoutService.push([{ _attr: attr }]);
        });
      }

      if (isNonEmptyArray(assertionConsumerService)) {
        let indexCount = 0;
        assertionConsumerService.forEach(a => {
          const attr: XmlAttributeMap = {
            index: String(indexCount++),
            Binding: a.Binding,
            Location: a.Location,
          };
          if (a.isDefault) {
            attr.isDefault = true;
          }
          descriptors.AssertionConsumerService.push([{ _attr: attr }]);
        });
      }

      const existedElements = elementsOrder.filter(name => isNonEmptyArray(descriptors[name as keyof MetaElement]));
      existedElements.forEach(name => {
        (descriptors[name as keyof MetaElement] as XmlElementArray).forEach(e =>
          SPSSODescriptor.push({ [name]: e }),
        );
      });

      meta = xml([{
        EntityDescriptor: [{
          _attr: {
            entityID,
            'xmlns': namespace.names.metadata,
            'xmlns:assertion': namespace.names.assertion,
            'xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
          },
        }, { SPSSODescriptor }],
      }]);
    }

    super(meta as string | Buffer, [
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
    ]);
  }

  /**
   * Return whether the SP requires signed assertions.
   */
  public isWantAssertionsSigned(): boolean {
    return (this.meta as Record<string, Record<string, string>>).spSSODescriptor.wantAssertionsSigned === 'true';
  }

  /**
   * Return whether the SP signs its `AuthnRequest` messages.
   */
  public isAuthnRequestSigned(): boolean {
    return (this.meta as Record<string, Record<string, string>>).spSSODescriptor.authnRequestsSigned === 'true';
  }

  /**
   * Return the AssertionConsumerService endpoint URL(s) for the requested
   * binding.
   *
   * @param binding protocol binding key (`redirect`, `post`, etc.)
   * @returns endpoint URL, list of URLs, or raw service list
   */
  public getAssertionConsumerService(binding: string): string | string[] {
    if (isString(binding)) {
      let location: string | undefined;
      const bindName = namespace.binding[binding];
      const acs = (this.meta as Record<string, unknown>).assertionConsumerService as
        | Array<{ binding: string; location: string }>
        | { binding: string; location: string };
      if (isNonEmptyArray(acs)) {
        (acs as Array<{ binding: string; location: string }>).forEach(obj => {
          if (obj.binding === bindName) {
            location = obj.location;
          }
        });
      } else if ((acs as { binding: string }).binding === bindName) {
        location = (acs as { binding: string; location: string }).location;
      }
      return location as string;
    }
    return (this.meta as Record<string, unknown>).assertionConsumerService as string[];
  }
}
