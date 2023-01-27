/**
* @file metadata-idp.ts
* @author tngan
* @desc  Metadata of identity provider
*/
import Metadata, { MetadataInterface } from './metadata';
import { MetadataIdpOptions, MetadataIdpConstructor } from './types';
import {elementsOrder as order, namespace} from './urn';
import libsaml from './libsaml';
import { castArrayOpt, isNonEmptyArray, isString } from './utility';
import xml from 'xml';

export interface IdpMetadataInterface extends MetadataInterface {

}

/*
 * @desc interface function
 */
export default function(meta: MetadataIdpConstructor) {
  return new IdpMetadata(meta);
}

export class IdpMetadata extends Metadata {

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
        organization,
        technicalContact,
        supportContact,
        elementsOrder = order.default,
        customAttributes= []
      } = meta as MetadataIdpOptions;

      const descriptors = {
        KeyDescriptor: [],
        SingleLogoutService: [],
        NameIDFormat: [],
        SingleSignOnService: [],
        AssertionConsumerService: [],
        AttributeConsumingService: [],
        CustomAttributes: []
      } as Record<string, any[]>;

      const IDPSSODescriptor: any[] = [ {
        _attr: {
          WantAuthnRequestsSigned: String(wantAuthnRequestsSigned),
          protocolSupportEnumeration: namespace.names.protocol,
        },
      } ];


      for(const cert of castArrayOpt(signingCert)) {
        descriptors.KeyDescriptor!.push(libsaml.createKeySection('signing', cert).KeyDescriptor);
      }

      for(const cert of castArrayOpt(encryptCert)) {
        descriptors.KeyDescriptor!.push(libsaml.createKeySection('encryption', cert).KeyDescriptor);
      }


      if (isNonEmptyArray(nameIDFormat)) {
        nameIDFormat.forEach(f => descriptors.NameIDFormat!.push(f));
      }

      if (isNonEmptyArray(singleSignOnService)) {
        singleSignOnService.forEach((a, indexCount) => {
          const attr: any = {
            Binding: a.Binding,
            Location: a.Location,
          };
          if (a.isDefault) {
            attr.isDefault = true;
          }
          descriptors.SingleSignOnService!.push([ { _attr: attr } ]);
        });
      } else {
        throw new Error('ERR_IDP_METADATA_MISSING_SINGLE_SIGN_ON_SERVICE');
      }

      if (isNonEmptyArray(singleLogoutService)) {
        singleLogoutService.forEach((a, indexCount) => {
          const attr: any = {};
          if (a.isDefault) {
            attr.isDefault = true;
          }
          attr.Binding = a.Binding;
          attr.Location = a.Location;
          descriptors.SingleLogoutService!.push([ { _attr: attr } ]);
        });
      } else {
        console.warn('Construct identity  provider - missing endpoint of SingleLogoutService');
      }


      // handle element order
      const existedElements = elementsOrder.filter(name => isNonEmptyArray(descriptors[name]));
      existedElements.forEach(name => {
        descriptors[name].forEach(e => IDPSSODescriptor.push({ [name]: e }));
      });

      if (isNonEmptyArray(customAttributes)){
        customAttributes.forEach(attr => {
          IDPSSODescriptor.push({ [attr.name || 'Attribute']: [ { _attr: attr._attr || {} }, attr.value ] });
        });
      }

      const OrgDescriptor = organization ? {
        Organization: [
          { _attr: {} },
          organization.name && { OrganizationName: [ { _attr: { 'xml:lang': 'en-US' } }, organization.name ] } ,
          organization.displayName && { OrganizationDisplayName: [ { _attr: { 'xml:lang': 'en-US' } },organization.displayName ] } ,
          organization.url && { OrganizationURL: [ { _attr: { 'xml:lang': 'en-US' } },organization.url ] }
        ].filter(v => !!v)
      } : {};

      const TechnicalContactDescriptor = technicalContact ? {
        ContactPerson: [
          {
            _attr: { contactType: 'technical' }
          },
          technicalContact.name && { GivenName: technicalContact.name },
          technicalContact.email && { EmailAddress: technicalContact.email }
        ].filter(v => !!v)
      } : {};

      const SupportContactDescriptor = supportContact ? {
        ContactPerson: [
          {
            _attr: { contactType: 'support' }
          },
          supportContact.name && { GivenName: supportContact.name },
          supportContact.email && { EmailAddress: supportContact.email }
        ].filter(v => !!v)
      } : {};
      // Create a new metadata by setting
      meta = xml([ {
        EntityDescriptor: [ {
          _attr: {
            'xmlns': namespace.names.metadata,
            'xmlns:assertion': namespace.names.assertion,
            'xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
            entityID,
          },
        }, {
          IDPSSODescriptor,
        },  OrgDescriptor, TechnicalContactDescriptor, SupportContactDescriptor ],
      } ]);
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
        attributes: ['Location']
      },
    ]);

  }

  /**
  * @desc Get the preference whether it wants a signed request
  * @return {boolean} WantAuthnRequestsSigned
  */
  isWantAuthnRequestsSigned(): boolean {
    const was = this.meta.wantAuthnRequestsSigned;
    if (was === undefined) {
      return false;
    }
    return String(was) === 'true';
  }

  /**
  * @desc Get the entity endpoint for single sign on service
  * @param  {string} binding      protocol binding (e.g. redirect, post)
  * @return {string/object} location
  */
  getSingleSignOnService(binding: string): string | object {
    if (isString(binding)) {
      const bindName = namespace.binding[binding];
      const service = this.meta.singleSignOnService[bindName];
      if (service) {
        return service;
      }
    }
    return this.meta.singleSignOnService;
  }
}
