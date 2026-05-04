/**
 * @file metadata-idp.ts
 * @author tngan
 * @desc Metadata of an identity provider (IdP). Accepts either a raw XML
 * document or a structured options object and presents a normalised API.
 */
import Metadata, { MetadataInterface } from './metadata';
import { MetadataIdpOptions, MetadataIdpConstructor, XmlElementArray, XmlAttributeMap } from './types';
import { namespace } from './urn';
import libsaml from './libsaml';
import { castArrayOpt, isNonEmptyArray, isString } from './utility';
import xml from 'xml';

/** Public interface exposed by IdP metadata instances. */
export interface IdpMetadataInterface extends MetadataInterface {
}

/**
 * Factory returning a new {@link IdpMetadata} instance.
 *
 * @param meta XML metadata document or structured options
 * @returns fresh IdpMetadata
 */
export default function (meta: MetadataIdpConstructor): IdpMetadata {
  return new IdpMetadata(meta);
}

export class IdpMetadata extends Metadata {

  /**
   * Build IdP metadata from XML or programmatic options.
   *
   * @param meta XML string/Buffer or {@link MetadataIdpOptions}
   */
  constructor(meta: MetadataIdpConstructor) {
    const isFile = isString(meta) || meta instanceof Buffer;

    if (!isFile) {
      const {
        entityID,
        signingCert,
        encryptCert,
        wantAuthnRequestsSigned = false,
        nameIDFormat = [],
        singleSignOnService = [],
        singleLogoutService = [],
      } = meta as MetadataIdpOptions;

      const IDPSSODescriptor: XmlElementArray = [{
        _attr: {
          WantAuthnRequestsSigned: String(wantAuthnRequestsSigned),
          protocolSupportEnumeration: namespace.names.protocol,
        },
      }];

      for (const cert of castArrayOpt(signingCert)) {
        IDPSSODescriptor.push(libsaml.createKeySection('signing', cert));
      }

      for (const cert of castArrayOpt(encryptCert)) {
        IDPSSODescriptor.push(libsaml.createKeySection('encryption', cert));
      }

      if (isNonEmptyArray(nameIDFormat)) {
        nameIDFormat.forEach(f => IDPSSODescriptor.push({ NameIDFormat: f }));
      }

      if (isNonEmptyArray(singleSignOnService)) {
        singleSignOnService.forEach(a => {
          const attr: XmlAttributeMap = {
            Binding: a.Binding,
            Location: a.Location,
          };
          if (a.isDefault) {
            attr.isDefault = true;
          }
          IDPSSODescriptor.push({ SingleSignOnService: [{ _attr: attr }] });
        });
      } else {
        throw new Error('ERR_IDP_METADATA_MISSING_SINGLE_SIGN_ON_SERVICE');
      }

      if (isNonEmptyArray(singleLogoutService)) {
        singleLogoutService.forEach(a => {
          const attr: XmlAttributeMap = {};
          if (a.isDefault) {
            attr.isDefault = true;
          }
          attr.Binding = a.Binding;
          attr.Location = a.Location;
          IDPSSODescriptor.push({ SingleLogoutService: [{ _attr: attr }] });
        });
      } else {
        console.warn('Construct identity  provider - missing endpoint of SingleLogoutService');
      }

      meta = xml([{
        EntityDescriptor: [{
          _attr: {
            'xmlns': namespace.names.metadata,
            'xmlns:assertion': namespace.names.assertion,
            'xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
            entityID,
          },
        }, { IDPSSODescriptor }],
      }]);
    }

    super(meta as string | Buffer, [
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
        attributes: ['Location'],
      },
    ]);
  }

  /**
   * Return whether the IdP requires signed `AuthnRequest` messages.
   *
   * @returns true when the metadata advertises `WantAuthnRequestsSigned="true"`
   */
  isWantAuthnRequestsSigned(): boolean {
    const was = (this.meta as Record<string, unknown>).wantAuthnRequestsSigned;
    if (was === undefined) {
      return false;
    }
    return String(was) === 'true';
  }

  /**
   * Return the single sign-on endpoint URL for the given binding, or the
   * full service map when the binding isn't a string.
   *
   * @param binding protocol binding key (`redirect`, `post`, etc.)
   * @returns endpoint URL or raw service map
   */
  getSingleSignOnService(binding: string): string | object {
    if (isString(binding)) {
      const bindName = namespace.binding[binding];
      const services = (this.meta as Record<string, Record<string, string>>).singleSignOnService;
      const service = services && services[bindName];
      if (service) {
        return service;
      }
    }
    return (this.meta as Record<string, unknown>).singleSignOnService as object;
  }
}
