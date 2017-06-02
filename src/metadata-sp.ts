/**
* @file metadata-sp.ts
* @author tngan
* @desc  Metadata of service provider
*/
import Metadata, { MetadataInterface } from './metadata';
import { namespace, elementsOrder as order } from './urn';
import libsaml from './libsaml';
import { isString } from 'lodash';
import { isNonEmptyArray } from './utility';

const xml = require('xml');

export interface SpMetadataInterface extends MetadataInterface {

}

// https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf (P.16, 18)
interface MetaElement {
  KeyDescriptor?: Array<any>;
  NameIDFormat?: Array<any>;
  SingleLogoutService?: Array<any>;
  AssertionConsumerService?: Array<any>;
  AttributeConsumingService?: Array<any>;
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

    let isFile = isString(meta) || meta instanceof Buffer;

    // use object configuation instead of importing metadata file directly
    if (!isFile) {

      const {
        elementsOrder = order.default,
        entityID,
        signingCert,
        encryptCert,
        authnRequestsSigned = false,
        wantAssertionsSigned = false,
        wantMessageSigned = false,
        messageSignatureConfig = undefined,
        nameIDFormat = [],
        singleLogoutService = [],
        assertionConsumerService = []
      } = meta;

      let descriptors: MetaElement = {
        KeyDescriptor: [],
        NameIDFormat: [],
        SingleLogoutService: [],
        AssertionConsumerService: [],
        AttributeConsumingService: []
      };

      let SPSSODescriptor: Array<any> = [{
        _attr: {
          AuthnRequestsSigned: String(authnRequestsSigned),
          WantAssertionsSigned: String(wantAssertionsSigned),
          protocolSupportEnumeration: namespace.names.protocol
        }
      }];

      if (wantMessageSigned && messageSignatureConfig === undefined) {
        console.warn('Construct service provider - missing messageSignatureConfig');
      }

      if (signingCert) {
        descriptors.KeyDescriptor.push(libsaml.createKeySection('signing', signingCert).KeyDescriptor);
      } else {
        //console.warn('Construct service provider - missing signing certificate');
      }

      if (encryptCert) {
        descriptors.KeyDescriptor.push(libsaml.createKeySection('encrypt', encryptCert).KeyDescriptor);
      } else {
        //console.warn('Construct service provider - missing encrypt certificate');
      }

      if (isNonEmptyArray(nameIDFormat)) {
        nameIDFormat.forEach(f => descriptors.NameIDFormat.push(f));
      }

      if (isNonEmptyArray(singleLogoutService)) {
        let indexCount = 0;
        singleLogoutService.forEach(a => {
          let attr: any = {
            index: String(indexCount++),
            Binding: a.Binding,
            Location: a.Location
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
          let attr: any = {
            index: String(indexCount++),
            Binding: a.Binding,
            Location: a.Location
          };
          if (a.isDefault) {
            attr.isDefault = true;
          }
          descriptors.AssertionConsumerService.push([{ _attr: attr }]);
        });
      } else {
        // console.warn('Missing endpoint of AssertionConsumerService');
      }

      // handle element order
      const existedElements = elementsOrder.filter(name => isNonEmptyArray(descriptors[name]));
      existedElements.forEach(name => {
        descriptors[name].forEach(e => SPSSODescriptor.push({ [name]: e }));
      });

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
    if (isString(binding)) {
      let location;
      let bindName = namespace.binding[binding];
      if (isNonEmptyArray(this.meta.assertionconsumerservice)) {
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
