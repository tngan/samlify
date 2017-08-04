/**
* @file metadata.ts
* @author tngan
* @desc An abstraction for metadata of identity provider and service provider
*/
import libsaml from './libsaml';
import utility from './utility';
import * as fs from 'fs';
import { namespace, wording } from './urn';
import { isString } from 'lodash';

const certUse = wording.certUse;

export interface MetadataInterface {
  xmlString: string;
  getMetadata: () => string;
  exportMetadata: (exportFile: string) => void;
  getEntityID: () => string;
  getX509Certificate: (certType: string) => string;
  getNameIDFormat: () => any[];
  getSingleLogoutService: (binding: string | undefined) => string | object;
  getSupportBindings: (services: string[]) => string[];
}

export default class Metadata implements MetadataInterface {

  xmlString: string;
  meta: any;
  /**
  * @param  {string | Buffer} metadata xml
  * @param  {object} extraParse for custom metadata extractor
  */
  constructor(xml: string | Buffer, extraParse = []) {
    this.xmlString = xml.toString();

    this.meta = libsaml.extractor(this.xmlString, extraParse.concat(['NameIDFormat', {
      localName: 'EntityDescriptor', attributes: ['entityID'],
    }, {
      localName: { tag: 'KeyDescriptor', key: 'use' },
      valueTag: 'X509Certificate',
    }, {
      localName: { tag: 'SingleLogoutService', key: 'Binding' },
      attributeTag: 'Location',
    }]));

    if (!this.meta.entitydescriptor || Array.isArray(this.meta.entitydescriptor)) {
      throw new Error('metadata must contain exactly one entity descriptor');
    }
  }

  /**
  * @desc Get the metadata in xml format
  * @return {string} metadata in xml format
  */
  public getMetadata(): string {
    return this.xmlString;
  }

  /**
  * @desc Export the metadata to specific file
  * @param {string} exportFile is the output file path
  */
  public exportMetadata(exportFile: string): void {
    fs.writeFileSync(exportFile, this.xmlString);
  }

  /**
  * @desc Get the entityID in metadata
  * @return {string} entityID
  */
  public getEntityID(): string {
    return this.meta.entitydescriptor.entityid;
  }

  /**
  * @desc Get the x509 certificate declared in entity metadata
  * @param  {string} use declares the type of certificate
  * @return {string} certificate in string format
  */
  public getX509Certificate(use: string): string {
    if (use === certUse.signing || use === certUse.encrypt) {
      return this.meta.keydescriptor[use];
    }
    throw new Error('undefined use of key in getX509Certificate');
  }

  /**
  * @desc Get the support NameID format declared in entity metadata
  * @return {array} support NameID format
  */
  public getNameIDFormat(): any {
    return this.meta.nameidformat;
  }

  /**
  * @desc Get the entity endpoint for single logout service
  * @param  {string} binding e.g. redirect, post
  * @return {string/object} location
  */
  public getSingleLogoutService(binding: string | undefined): string | object {
    if (isString(binding)) {
      const bindType = namespace.binding[binding];
      const service = this.meta.singlelogoutservice.find(obj => obj[bindType]);
      if (service) {
        return service[bindType];
      }
    }
    return this.meta.singlelogoutservice;
  }

  /**
  * @desc Get the support bindings
  * @param  {[string]} services
  * @return {[string]} support bindings
  */
  public getSupportBindings(services: string[]): string[] {
    const supportBindings = [];
    if (services) {
      services.forEach(service => supportBindings.push(Object.keys(service)[0]));
    }
    return supportBindings;
  }
}
