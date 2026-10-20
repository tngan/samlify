/**
 * @file metadata.ts
 * @author tngan
 * @desc Abstraction for SAML entity metadata (IdP and SP share this base).
 */
import * as fs from 'fs';
import { namespace } from './urn';
import { select } from 'xpath';
import { extract } from './extractor';
import { isString, toCertificateBody } from './utility';
import { parseXml } from './xml';
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
  /** @deprecated no longer populated; use `certificate`. */
  sharedCertificate?: string;
  certificate?: { signing?: string | string[]; encryption?: string | string[] } | Record<string, string | string[]>;
  singleLogoutService?: Array<{ binding: string; location: string }> | { binding: string; location: string };
  nameIDFormat?: string | string[];
}

type CertificateUse = 'signing' | 'encryption';

/**
 * Collect the X.509 certificates of each `<KeyDescriptor>` by its `use`.
 *
 * A key declared `use="signing"` is only for signing and `use="encryption"`
 * only for encryption; a `KeyDescriptor` without `use` serves both, and
 * several keys for the same use are all accepted (saml-metadata §2.4.1.1 as
 * amended by errata E62 and E68). An encryption-only key must never become a
 * signature verification key.
 *
 * `use` is optional in the schema, but the Metadata Interoperability Profile
 * (saml-metadata-iop §2.5.1) requires it, so its absence is logged.
 *
 * For backward compatibility, metadata whose only certificate is a single
 * signing key still exposes it for encryption. This goes beyond E62, which
 * does not make a signing key usable for encryption.
 *
 * @param xml metadata XML
 * @param entityID entity ID used in the missing-`use` warning
 * @returns certificates keyed by use; a single certificate is a string
 */
function extractCertificates(xml: string, entityID?: string): Partial<Record<CertificateUse, string | string[]>> {
  const keyDescriptors = select(
    "/*[local-name(.)='EntityDescriptor']/*[contains(local-name(), 'SSODescriptor')]/*[local-name(.)='KeyDescriptor']",
    parseXml(xml),
  ) as Element[];
  const certs: Record<CertificateUse, string[]> = { signing: [], encryption: [] };

  for (const keyDescriptor of keyDescriptors) {
    const values = (select(
      "./*[local-name(.)='KeyInfo']/*[local-name(.)='X509Data']/*[local-name(.)='X509Certificate']",
      keyDescriptor,
    ) as Element[]).map(node => toCertificateBody(node.textContent ?? ''));
    const use = keyDescriptor.getAttribute('use');
    if (use === 'signing' || use === 'encryption') {
      certs[use].push(...values);
    } else if (!use) {
      if (values.length > 0) {
        console.warn(
          `[samlify] KeyDescriptor without a use attribute in metadata of ${entityID ?? 'unknown entity'}; `
          + 'its certificate is used for both signing and encryption. '
          + 'Declare use="signing" or use="encryption" to restrict it.',
        );
      }
      certs.signing.push(...values);
      certs.encryption.push(...values);
    }
  }

  if (certs.encryption.length === 0 && certs.signing.length === 1) {
    certs.encryption = certs.signing;
  }

  const result: Partial<Record<CertificateUse, string | string[]>> = {};
  (Object.keys(certs) as CertificateUse[]).forEach(use => {
    if (certs[use].length > 0) {
      result[use] = certs[use].length === 1 ? certs[use][0] : certs[use];
    }
  });
  return result;
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

    this.meta.certificate = extractCertificates(this.xmlString, this.meta.entityID);

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
