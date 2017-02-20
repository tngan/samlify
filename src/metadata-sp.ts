/**
* @file metadata-sp.ts
* @author tngan
* @desc  Metadata of service provider
*/
import Metadata, { MetadataInterface } from './metadata';
import { namespace } from './urn';
import libsaml from './libsaml';

const xml = require('xml');

export interface SpMetadataInterface extends MetadataInterface {

}

/*
 * @desc interface function
 */
export default function (meta) {
  return new SpMetadata(meta);
}

/**
* @desc SP Metadata is for creating Service Provider, provides a set of API to manage the actions in SP.
*/
export class SpMetadata extends Metadata {

  /**
  * @param  {object/string} meta (either xml string or configuation in object)
  * @return {object} prototypes including public functions
  */
  constructor(meta) {

    let byMetadata = (typeof meta === 'string' || meta instanceof Buffer);

    if (!byMetadata) {
      let entityID = meta.entityID;
      let authnRequestsSigned = meta.authnRequestsSigned === true;
      let wantAssertionsSigned = meta.wantAssertionsSigned === true;
      let signingCert = meta.signingCert;
      let encryptCert = meta.encryptCert;
      let nameIDFormat = meta.nameIDFormat || [];
      let singleLogoutService = meta.singleLogoutService || [];
      let assertionConsumerService = meta.assertionConsumerService || [];

      let SPSSODescriptor: Array<any> = [{
        _attr: {
          AuthnRequestsSigned: authnRequestsSigned.toString(),
          WantAssertionsSigned: wantAssertionsSigned.toString(),
          protocolSupportEnumeration: namespace.names.protocol
        }
      }];

      if (signingCert) {
        SPSSODescriptor.push(libsaml.createKeySection('signing', signingCert));
      } else {
        //console.warn('Construct service provider - missing signing certificate');
      }

      if (encryptCert) {
        SPSSODescriptor.push(libsaml.createKeySection('encrypt', encryptCert));
      } else {
        //console.warn('Construct service provider - missing encrypt certificate');
      }

      if (nameIDFormat && nameIDFormat.length > 0) {
        nameIDFormat.forEach(f => SPSSODescriptor.push({ NameIDFormat: f }));
      }

      if (singleLogoutService && singleLogoutService.length > 0) {
        let indexCount = 0;
        singleLogoutService.forEach(function (a) {
          let attr: any = {};
          if (a.isDefault) {
            attr.isDefault = true;
          }
          attr.index = (indexCount++).toString();
          attr.Binding = a.Binding;
          attr.Location = a.Location;
          SPSSODescriptor.push({ SingleLogoutService: [{ _attr: attr }] });
        });
      }

      if (assertionConsumerService && assertionConsumerService.length > 0) {
        let indexCount = 0;
        assertionConsumerService.forEach(a => {
          let attr: any = {};
          if (a.isDefault) {
            attr.isDefault = true;
          }
          attr.index = (indexCount++).toString();
          attr.Binding = a.Binding;
          attr.Location = a.Location;
          SPSSODescriptor.push({ AssertionConsumerService: [{ _attr: attr }] });
        });
      } else {
        throw new Error('Missing endpoint of AssertionConsumerService');
      }

      // Create a new metadata by setting
      meta = xml([{
        EntityDescriptor: [{
          _attr: {
            entityID,
            'xmlns:md': namespace.names.metadata,
            'xmlns:assertion': namespace.names.assertion,
            'xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#'
          }
        }, { SPSSODescriptor }]
      }]);
    }
    /**
    * @desc  Initialize with creating a new metadata object
    * @param {string/objects} meta     metadata XML
    * @param {array of Objects}        high-level XML element selector
    */

    super(meta, [{
      localName: 'SPSSODescriptor',
      attributes: ['WantAssertionsSigned', 'AuthnRequestsSigned']
    }, {
      localName: 'AssertionConsumerService',
      attributes: ['Binding', 'Location', 'isDefault', 'index']
    }]);
  }

  /**
  * @desc Get the preference whether it wants a signed assertion response
  * @return {boolean} Wantassertionssigned
  */
  public isWantAssertionsSigned(): boolean {
    return this.meta.spssodescriptor.wantassertionssigned === 'true';
  }
  /**
  * @desc Get the preference whether it signs request
  * @return {boolean} Authnrequestssigned
  */
  public isAuthnRequestSigned(): boolean {
    return this.meta.spssodescriptor.authnrequestssigned === 'true';
  }
  /**
  * @desc Get the entity endpoint for assertion consumer service
  * @param  {string} binding         protocol binding (e.g. redirect, post)
  * @return {string/[string]} URL of endpoint(s)
  */
  public getAssertionConsumerService(binding: string): string | Array<string> {
    if (typeof binding === 'string') {
      let location;
      let bindName = namespace.binding[binding];
      if (this.meta.assertionconsumerservice.length > 0) {
        this.meta.assertionconsumerservice.forEach(obj => {
          if (obj.binding === bindName) {
            location = obj.location;
            return;
          }
        });
      } else {
        if (this.meta.assertionconsumerservice.binding === bindName) {
          location = this.meta.assertionconsumerservice.location;
        }
      }
      return location;
    }
    return this.meta.assertionconsumerservice;
  }
}
