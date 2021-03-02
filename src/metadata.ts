/**
 * @file metadata.ts
 * @author tngan
 * @desc An abstraction for metadata of identity provider and service provider
 */
import fs from 'fs';
import { SamlifyError, SamlifyErrorCode } from './error';
import { extract } from './extractor';
import type { BindingNamespace } from './urn';
import { isString } from './utility';

export interface SSOService {
	isDefault?: boolean;
	Binding: BindingNamespace;
	Location: string;
}

export interface MetadataOptions {
	encryptCert?: string | Buffer;
	entityID?: string;
	nameIDFormat?: string[];
	signingCert?: string | Buffer;
	singleLogoutService?: SSOService[];
	singleSignOnService?: SSOService[];
}

export type MetadataFile = string | Buffer;

export class Metadata {
	private xmlString: string;
	protected meta: any;

	/**
	 * @param  {string | Buffer} metadata xml
	 * @param  {object} extraParse for custom metadata extractor
	 */
	constructor(xml: MetadataFile, extraParse: any = []) {
		this.xmlString = xml.toString();
		this.meta = extract(
			this.xmlString,
			// eslint-disable-next-line @typescript-eslint/no-unsafe-call
			extraParse.concat([
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
			])
		);

		// get shared certificate
		const sharedCertificate = this.meta.sharedCertificate;
		if (typeof sharedCertificate === 'string') {
			this.meta.certificate = {
				signing: sharedCertificate,
				encryption: sharedCertificate,
			};
			delete this.meta.sharedCertificate;
		}

		if (Array.isArray(this.meta.entityDescriptor) && this.meta.entityDescriptor.length > 1) {
			throw new SamlifyError(SamlifyErrorCode.MultipleMetadataEntityDescriptor);
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
		// eslint-disable-next-line @typescript-eslint/no-unsafe-return
		return this.meta.entityID;
	}

	/**
	 * @desc Get the x509 certificate declared in entity metadata
	 * @param  {string} use declares the type of certificate
	 * @return {string} certificate in string format
	 */
	public getX509Certificate(use: string): string | Buffer {
		// eslint-disable-next-line @typescript-eslint/no-unsafe-return
		return this.meta.certificate[use] || null;
	}

	/**
	 * @desc Get the support NameID format declared in entity metadata
	 * @return {array} support NameID format
	 */
	public getNameIDFormat(): any {
		// eslint-disable-next-line @typescript-eslint/no-unsafe-return
		return this.meta.nameIDFormat;
	}

	/**
	 * @desc Get the entity endpoint for single logout service
	 * @param  {string} protocol e.g. redirect, post
	 * @return {string} location
	 */
	public getSingleLogoutService(protocol: BindingNamespace): string {
		let singleLogoutService = this.meta.singleLogoutService;
		if (!Array.isArray(singleLogoutService)) {
			singleLogoutService = [singleLogoutService];
		}
		// eslint-disable-next-line @typescript-eslint/no-unsafe-call
		const service = singleLogoutService.find((obj: any) => obj.binding === protocol && isString(obj.location));
		if (service) {
			// eslint-disable-next-line @typescript-eslint/no-unsafe-return
			return service.location;
		}
		throw new SamlifyError(SamlifyErrorCode.SingleLogoutLocationNotFound);
	}

	/**
	 * @desc Get the support bindings
	 * @param  {[string]} services
	 * @return {[string]} support bindings
	 */
	public getSupportBindings(services: string[]): string[] {
		let supportBindings = [];
		if (services) {
			supportBindings = services.reduce((acc: any, service) => {
				const supportBinding = Object.keys(service)[0];
				// eslint-disable-next-line
				return acc.push(supportBinding);
			}, []);
		}
		// eslint-disable-next-line @typescript-eslint/no-unsafe-return
		return supportBindings;
	}
}
