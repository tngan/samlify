/**
* @file metadata-sp.ts
* @author tngan
* @desc  Metadata of service provider
*/
import Metadata, {type MetadataInterface} from './metadata.js';
import   type{  MetadataSpOptions } from './types.js';
import type { MetadataSpConstructor } from './types.js';
import { namespace, elementsOrder as order } from './urn.js';
import libsaml from './libsaml.js';
import { castArrayOpt, isNonEmptyArray, isString } from './utility.js';
import xml from 'xml';
import  type {AttrService,ServiceName,RequestedAttribute,AttributeConsumingService} from './types.js'
export interface SpMetadataInterface extends MetadataInterface {

}

// https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf (P.16, 18)
interface MetaElement {
  KeyDescriptor?: any[];
  NameIDFormat?: any[];
  SingleLogoutService?: any[];
  AssertionConsumerService?: any[];
  AttributeConsumingService?: any[];
  ArtifactResolutionService?: any[];
}

/*
 * @desc interface function
 */
export default function(meta: MetadataSpConstructor) {
  return new SpMetadata(meta);
}

/**
* @desc SP Metadata is for creating Service Provider, provides a set of API to manage the actions in SP.
*/
export class SpMetadata extends Metadata {

  /**
  * @param  {object/string} meta (either xml string or configuration in object)
  * @return {object} prototypes including public functions
  */
  constructor(meta: MetadataSpConstructor) {

    const isFile = isString(meta) || meta instanceof Buffer;

    // use object configuration instead of importing metadata file directly
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
        attributeConsumingService = [],
        artifactResolutionService = []
      } = meta as MetadataSpOptions;

      const descriptors: MetaElement = {
        KeyDescriptor: [],
        NameIDFormat: [],
        SingleLogoutService: [],
        AssertionConsumerService: [],
        AttributeConsumingService: [],
        ArtifactResolutionService:[]
      };

      const SPSSODescriptor: any[] = [{
        _attr: {
          AuthnRequestsSigned: String(authnRequestsSigned),
          WantAssertionsSigned: String(wantAssertionsSigned),
          protocolSupportEnumeration: namespace.names.protocol,
        },
      }];

      if (wantMessageSigned && signatureConfig === undefined) {
        console.warn('Construct service provider - missing signatureConfig');
      }

      for(const cert of castArrayOpt(signingCert)) {
        descriptors.KeyDescriptor!.push(libsaml.createKeySection('signing', cert).KeyDescriptor);
      }

      for(const cert of castArrayOpt(encryptCert)) {
        descriptors.KeyDescriptor!.push(libsaml.createKeySection('encryption', cert).KeyDescriptor);
      }
      if (isNonEmptyArray(artifactResolutionService)) {
        let indexCount = 0;
        artifactResolutionService.forEach(a => {
          const attr: any = {
            index: String(indexCount++),
            Binding: a.Binding,
            Location: a.Location,
          };
          if (a.isDefault) {
            attr.isDefault = true;
          }
          descriptors.ArtifactResolutionService!.push([{ _attr: attr }]);
        });
      }
      if (isNonEmptyArray(singleLogoutService)) {
        singleLogoutService.forEach(a => {
          const attr: any = {
            Binding: a.Binding,
            Location: a.Location,
          };
          /*    if (a.isDefault) {
                attr.isDefault = true;
              }*/
          descriptors.SingleLogoutService!.push([{ _attr: attr }]);
        });
      }
      if (isNonEmptyArray(nameIDFormat)) {
        nameIDFormat.forEach(f => descriptors.NameIDFormat!.push(f));
      } else {
        // default value
        descriptors.NameIDFormat!.push(namespace.format.emailAddress);
      }




      if (isNonEmptyArray(assertionConsumerService)) {
        let indexCount = 0;
        assertionConsumerService.forEach(a => {
          const attr: any = {
            index: String(indexCount++),
            Binding: a.Binding,
            Location: a.Location,
          };
          if (a.isDefault) {
            attr.isDefault = true;
          }
          descriptors.AssertionConsumerService!.push([{ _attr: attr }]);
        });
      } else {
        console.warn('Missing endpoint of AssertionConsumerService');
      }
      // 修改原有处理逻辑
      if (isNonEmptyArray(attributeConsumingService)) {
        attributeConsumingService.forEach((service,index)=> {
          // 1. 构建AttributeConsumingService主元素
          let indexCount = 0;
          let  attrConsumingService: any[] = [{
            _attr: {
              index: String(index + 1),
            }
          }];
          if (service.isDefault) {
            attrConsumingService[0]._attr.isDefault = true;
          }
          // 2. 添加ServiceName子元素
          if (isNonEmptyArray(  service.serviceName)){
            service.serviceName.forEach(({ value, lang }) => {
              attrConsumingService.push({
                ServiceName: [
                  {
                    _attr: lang ? { 'xml:lang': lang } : {},
                  },
                  value
                ]
              });
            });
          }

          if (isNonEmptyArray(  service.serviceDescription)){
            service.serviceDescription.forEach(({ value, lang }) => {
              attrConsumingService.push({
                ServiceDescription: [
                  {
                    _attr: lang ? { 'xml:lang': lang } : {},
                  },
                  value
                ]
              });
            });
          }
          // 3. 添加RequestedAttribute子元素
          if (isNonEmptyArray(service.requestedAttributes)) {
            service.requestedAttributes.forEach(attr => {
              const requestedAttr: any = {
                _attr: {
                  ...(attr.isRequired && { isRequired: String(attr.isRequired) }),
                  Name: attr.name,
                  ...(attr.friendlyName && { FriendlyName: attr.friendlyName }),
                }
              };
/*              // 处理属性值白名单
              if (isNonEmptyArray(attr.attributeValue)) {
                requestedAttr[namespace.tags.attributeValue] = attr.attributeValue.map(val => ({
                  _: val
                }));
              }*/
              attrConsumingService.push({
                RequestedAttribute: [requestedAttr]
              });
            });
          }

          // 4. 将完整元素加入描述符
          descriptors.AttributeConsumingService!.push(attrConsumingService);
        });
      }

      // handle element order
      const existedElements = elementsOrder.filter(name => isNonEmptyArray(descriptors[name]));
      existedElements.forEach(name => {
        descriptors[name].forEach(e => SPSSODescriptor.push({ [name]: e }));
      });
      // Re-assign the meta reference as a XML string|Buffer for use with the parent constructor
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

    // Use the re-assigned meta object reference here
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
      {
        key: 'artifactResolutionService',
        localPath: ['EntityDescriptor', 'SPSSODescriptor', 'ArtifactResolutionService'],
        attributes: ['Binding', 'Location', 'isDefault', 'index'],
      }
    ]);

  }

  /**
  * @desc Get the preference whether it wants a signed assertion response
  * @return {boolean} Wantassertionssigned
  */
  public isWantAssertionsSigned(): boolean {
    return this.meta.spSSODescriptor.wantAssertionsSigned === 'true';
  }
  /**
  * @desc Get the preference whether it signs request
  * @return {boolean} Authnrequestssigned
  */
  public isAuthnRequestSigned(): boolean {
    return this.meta.spSSODescriptor.authnRequestsSigned === 'true';
  }
  /**
  * @desc Get the entity endpoint for assertion consumer service
  * @param  {string} binding         protocol binding (e.g. redirect, post)
  * @return {string/[string]} URL of endpoint(s)
  */
  public getAssertionConsumerService(binding: string): string | string[] {
    if (isString(binding)) {
      let location;
      const bindName = namespace.binding[binding];
      if (isNonEmptyArray(this.meta.assertionConsumerService)) {
        this.meta.assertionConsumerService.forEach(obj => {
          if (obj.binding === bindName) {
            location = obj.location;
            return;
          }
        });
      } else {
        if (this.meta.assertionConsumerService.binding === bindName) {
          location = this.meta.assertionConsumerService.location;
        }
      }
      return location;
    }
    return this.meta.assertionConsumerService;
  }
}
