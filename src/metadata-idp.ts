/**
 * @file metadata-idp.ts
 * @author tngan
 * @desc  Metadata of identity provider
 */
import xml from 'xml';
import libsaml from './libsaml';
import { Metadata } from './metadata';
import type { MetadataIdpConstructorOptions, MetadataIdpOptions } from './types';
import { BindingNamespace, names } from './urn';
import { isNonEmptyArray, isString } from './utility';

/*
 * @desc interface function
 */
export default function (meta: MetadataIdpConstructorOptions) {
	return new MetadataIdp(meta);
}

export class MetadataIdp extends Metadata {
	constructor(meta: MetadataIdpConstructorOptions) {
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

			const IDPSSODescriptor: any[] = [
				{
					_attr: {
						WantAuthnRequestsSigned: String(wantAuthnRequestsSigned),
						protocolSupportEnumeration: names.protocol,
					},
				},
			];

			if (signingCert) {
				IDPSSODescriptor.push(libsaml.createKeySection('signing', signingCert));
			} else {
				//console.warn('Construct identity provider - missing signing certificate');
			}

			if (encryptCert) {
				IDPSSODescriptor.push(libsaml.createKeySection('encryption', encryptCert));
			} else {
				//console.warn('Construct identity provider - missing encrypt certificate');
			}

			if (isNonEmptyArray(nameIDFormat)) {
				nameIDFormat.forEach((f) => IDPSSODescriptor.push({ NameIDFormat: f }));
			}

			if (isNonEmptyArray(singleSignOnService)) {
				singleSignOnService.forEach((a) => {
					const attr: any = {
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
				singleLogoutService.forEach((a) => {
					const attr: any = {};
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
			// Create a new metadata by setting
			meta = xml([
				{
					EntityDescriptor: [
						{
							_attr: {
								xmlns: names.metadata,
								'xmlns:assertion': names.assertion,
								'xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
								entityID,
							},
						},
						{ IDPSSODescriptor },
					],
				},
			]);
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
	getSingleSignOnService(protocol: BindingNamespace): string {
		const service = this.meta.singleSignOnService[protocol];
		if (isString(service)) {
			return service;
		}
		throw new Error('ERR_SINGLE_SIGN_ON_LOCATION_NOT_FOUND');
	}
}
