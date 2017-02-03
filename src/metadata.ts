/**
* @file metadata.ts
* @author tngan
* @desc An abstraction for metadata of identity provider and service provider
*/
import libsaml from './libsaml';
import utility from './utility';
import * as fs from 'fs';
import { namespace, wording } from './urn';

const certUse = wording.certUse;

export interface MetadataInterface {
	xmlString: string;
	meta: any;
	getMetadata: () => string;
	exportMetadata: (exportFile: string) => void;
	getEntityID: () => string;
	getX509Certificate: (certType: string) => string;
	getNameIDFormat: () => Array<any>;
	getSingleLogoutService: (binding: string | undefined) => string | Object;
	getSupportBindings: (services: Array<string>) => Array<string>;
}

export default class Metadata implements MetadataInterface {

	xmlString: string;
	meta: any;
	/**
	* @param  {string} meta is either xmlString or file name
	* @param  {object} extraParse for custom metadata extractor
	* @param  {Boolean} isXml declares whether meta is xmlString or filePath
	*/
	constructor (meta, extraParse, isXml?: boolean) {
		this.xmlString = isXml === true ? String(meta) :　String(fs.readFileSync(meta));
    this.meta = libsaml.extractor(this.xmlString, Array.prototype.concat([{
      localName: 'EntityDescriptor',
      attributes: ['entityID']
    },{
      localName: {
        tag: 'KeyDescriptor',
        key: 'use'
      },
      valueTag: 'X509Certificate'
    },{
      localName: {
        tag: 'SingleLogoutService',
        key: 'Binding'
      },
      attributeTag: 'Location'
    }, 'NameIDFormat'], extraParse || []));
	}
  /**
  * @desc Get the metadata in xml format
  * @return {string} metadata in xml format
  */
  public getMetadata (): string {
    return this.xmlString;
  }
  /**
  * @desc Export the metadata to specific file
  * @param {string} exportFile is the output file path
  */
  public exportMetadata (exportFile: string): void {
    fs.writeFileSync(exportFile, this.xmlString);
  }
  /**
  * @desc Get the entityID in metadata
  * @return {string} entityID
  */
  public getEntityID (): string {
    return this.meta.entitydescriptor.entityid;
  }
  /**
  * @desc Get the x509 certificate declared in entity metadata
  * @param  {string} use declares the type of certificate
  * @return {string} certificate in string format
  */
  public getX509Certificate (use: string): string {
		if (use === certUse.signing || use === certUse.encrypt) {
			return this.meta.keydescriptor[use];
		}
		throw new Error('undefined use of key in getX509Certificate');
  }
  /**
  * @desc Get the support NameID format declared in entity metadata
  * @return {array} support NameID format
  */
  public getNameIDFormat (): Array<any> {
    return this.meta.nameidformat;
  }
  /**
  * @desc Get the entity endpoint for single logout service
  * @param  {string} binding e.g. redirect, post
  * @return {string/object} location
  */
  public getSingleLogoutService (binding: string | undefined): string | Object {
    if (typeof binding === 'string') {
      let location;
      let bindType = namespace.binding[binding];
      this.meta.singlelogoutservice.forEach(obj => {
        if (obj[bindType]) {
          location = obj[bindType];
          return;
        }
      });
      return location;
    }
    return this.meta.singlelogoutservice;
  }
  /**
  * @desc Get the support bindings
  * @param  {[string]} services
  * @return {[string]} support bindings
  */
  public getSupportBindings (services: Array<string>): Array<string> {
    let supportBindings = [];
    if (services) {
      services.forEach(service => supportBindings.push(Object.keys(service)[0]));
    }
    return supportBindings;
  }
}
