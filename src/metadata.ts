/**
 * @file metadata.ts
 * @author tngan
 * @desc Abstraction for SAML entity metadata (IdP and SP share this base).
 */
import * as fs from 'fs';
import { namespace } from './urn';
import { extract } from './extractor';
import { isString } from './utility';
import type { ExtractorFields } from './types';

/** Public interface exposed by every metadata instance. */
export interface MetadataInterface {
  xmlString: string;
  getMetadata: () => string;
  exportMetadata: (exportFile: string) => void;
  getEntityID: () => string;
  getX509Certificate: (certType: string) => string | string[];
  getNameIDFormat: () => string[];
  getSingleLogoutService: (binding: string | undefined) => string | object;
  getSupportBindings: (services: string[]) => string[];
}

/** Parsed metadata bag exposed under `meta`. */
export interface MetadataBag {
  [key: string]: unknown;
  entityDescriptor?: string | string[];
  entityID?: string;
  sharedCertificate?: string;
  certificate?: { signing?: string | string[]; encryption?: string | string[] } | Record<string, string | string[]>;
  singleLogoutService?: Array<{ binding: string; location: string }> | { binding: string; location: string };
  nameIDFormat?: string | string[];
}

export default class Metadata implements MetadataInterface {

  xmlString: string;
  meta: MetadataBag;

  /**
   * Parse a SAML metadata XML document and hydrate a typed `meta` bag.
   *
   * @param xml raw metadata XML (string or Buffer)
   * @param extraParse additional extractor fields merged into the standard set
   */
  constructor(xml: string | Buffer, extraParse: ExtractorFields = []) {
    this.xmlString = xml.toString();
    this.meta = extract(this.xmlString, extraParse.concat([
      {
        key: 'entityDescriptor',
        localPath: ['EntityDescriptor'],
        attributes: [],
        context: true,
      },
      {
        key: 'entityID',
        localPath: ['EntityDescriptor'],
        attributes: ['entityID'],
      },
      {
        // shared certificate for both encryption and signing
        key: 'sharedCertificate',
        localPath: ['EntityDescriptor', '~SSODescriptor', 'KeyDescriptor', 'KeyInfo', 'X509Data', 'X509Certificate'],
        attributes: [],
      },
      {
        // explicit certificate declaration for encryption and signing
        key: 'certificate',
        localPath: ['EntityDescriptor', '~SSODescriptor', 'KeyDescriptor'],
        index: ['use'],
        attributePath: ['KeyInfo', 'X509Data', 'X509Certificate'],
        attributes: [],
      },
      {
        key: 'singleLogoutService',
        localPath: ['EntityDescriptor', '~SSODescriptor', 'SingleLogoutService'],
        attributes: ['Binding', 'Location'],
      },
      {
        key: 'nameIDFormat',
        localPath: ['EntityDescriptor', '~SSODescriptor', 'NameIDFormat'],
        attributes: [],
      },
    ])) as MetadataBag;

    const sharedCertificate = this.meta.sharedCertificate;
    if (typeof sharedCertificate === 'string') {
      this.meta.certificate = {
        signing: sharedCertificate,
        encryption: sharedCertificate,
      };
      delete this.meta.sharedCertificate;
    }

    if (
      Array.isArray(this.meta.entityDescriptor) &&
      this.meta.entityDescriptor.length > 1
    ) {
      throw new Error('ERR_MULTIPLE_METADATA_ENTITYDESCRIPTOR');
    }
  }

  /**
   * Return the underlying metadata XML.
   */
  public getMetadata(): string {
    return this.xmlString;
  }

  /**
   * Write the metadata XML to disk at the given path.
   *
   * @param exportFile absolute file path
   */
  public exportMetadata(exportFile: string): void {
    fs.writeFileSync(exportFile, this.xmlString);
  }

  /**
   * Return the metadata `entityID`.
   */
  public getEntityID(): string {
    return this.meta.entityID as string;
  }

  /**
   * Return the X.509 certificate(s) declared in metadata for a given use.
   *
   * @param use `signing` or `encryption`
   * @returns certificate body or list, or `null` when missing
   */
  public getX509Certificate(use: string): string | string[] {
    const certificate = this.meta.certificate as Record<string, string | string[]> | undefined;
    return (certificate && certificate[use]) || (null as unknown as string);
  }

  /**
   * Return the supported NameID formats declared in metadata.
   */
  public getNameIDFormat(): string[] {
    return this.meta.nameIDFormat as string[];
  }

  /**
   * Return the single-logout service endpoint for the requested binding.
   * When no binding is provided, returns the raw service list.
   *
   * @param binding `redirect`, `post`, etc.
   * @returns endpoint URL or raw service list
   */
  public getSingleLogoutService(binding: string | undefined): string | object {
    if (binding && isString(binding)) {
      const bindType = namespace.binding[binding];
      let singleLogoutService = this.meta.singleLogoutService;
      if (!(singleLogoutService instanceof Array)) {
        singleLogoutService = [singleLogoutService as { binding: string; location: string }];
      }
      const service = singleLogoutService.find(obj => obj.binding === bindType);
      if (service) {
        return service.location;
      }
    }
    return this.meta.singleLogoutService as unknown as object;
  }

  /**
   * Reduce a service descriptor array to the list of bindings it declares.
   *
   * @param services list of service descriptor objects
   * @returns supported binding keys
   */
  public getSupportBindings(services: string[]): string[] {
    const supportBindings: string[] = [];
    if (services) {
      services.forEach(service => {
        const supportBinding = Object.keys(service)[0];
        supportBindings.push(supportBinding);
      });
    }
    return supportBindings;
  }
}
