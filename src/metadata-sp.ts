/**
 * @file metadata-sp.ts
 * @author tngan
 * @desc  Metadata of service provider
 */
import xml from 'xml';
import { libsaml } from './libsaml';
import { Metadata, MetadataFile, MetadataOptions, SSOService } from './metadata';
import { BindingNamespace, elementsOrder as order, MetaElement, names } from './urn';
import { isNonEmptyArray, isString } from './utility';

interface MetadataSpOptions extends MetadataOptions {
	assertionConsumerService?: SSOService[];
	authnRequestsSigned?: boolean;
	elementsOrder?: (keyof MetaElement)[];
	// TODO: Not sure if this is used. Consider removing.
	signatureConfig?: Record<string, any>;
	wantAssertionsSigned?: boolean;
	wantMessageSigned?: boolean;
}

export type MetadataSpConstructorOptions = MetadataSpOptions | MetadataFile;

/*
 * @desc interface function
 */
export function metadataSp(meta: MetadataSpConstructorOptions) {
	return new MetadataSp(meta);
}

/**
 * @desc SP Metadata is for creating Service Provider, provides a set of API to manage the actions in SP.
 */
export class MetadataSp extends Metadata {
	/**
	 * @param  {object/string} meta (either xml string or configuation in object)
	 * @return {object} prototypes including public functions
	 */
	constructor(meta: MetadataSpConstructorOptions) {
		// use object configuation instead of importing metadata file directly
		if (!(isString(meta) || meta instanceof Buffer)) {
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
			} = meta;

			const descriptors: MetaElement = {
				KeyDescriptor: [],
				NameIDFormat: [],
				SingleLogoutService: [],
				AssertionConsumerService: [],
				AttributeConsumingService: [],
			};

			const SPSSODescriptor: any[] = [
				{
					_attr: {
						AuthnRequestsSigned: String(authnRequestsSigned),
						WantAssertionsSigned: String(wantAssertionsSigned),
						protocolSupportEnumeration: names.protocol,
					},
				},
			];

			if (wantMessageSigned && signatureConfig === undefined) {
				console.warn('Construct service provider - missing signatureConfig');
			}

			if (signingCert) {
				descriptors.KeyDescriptor?.push(libsaml.createKeySection('signing', signingCert).KeyDescriptor);
			} else {
				//console.warn('Construct service provider - missing signing certificate');
			}

			if (encryptCert) {
				descriptors.KeyDescriptor?.push(libsaml.createKeySection('encryption', encryptCert).KeyDescriptor);
			} else {
				//console.warn('Construct service provider - missing encrypt certificate');
			}

			if (isNonEmptyArray(nameIDFormat)) {
				nameIDFormat.forEach((f) => descriptors.NameIDFormat?.push(f));
			} else {
				// default value
				descriptors.NameIDFormat?.push(names.nameidFormat.emailAddress);
			}

			if (isNonEmptyArray(singleLogoutService)) {
				singleLogoutService.forEach((a) => {
					const attr: any = {
						Binding: a.Binding,
						Location: a.Location,
					};
					if (a.isDefault) {
						attr.isDefault = true;
					}
					descriptors.SingleLogoutService?.push([{ _attr: attr }]);
				});
			}

			if (isNonEmptyArray(assertionConsumerService)) {
				let indexCount = 0;
				assertionConsumerService.forEach((a) => {
					const attr: any = {
						index: String(indexCount++),
						Binding: a.Binding,
						Location: a.Location,
					};
					if (a.isDefault) {
						attr.isDefault = true;
					}
					descriptors.AssertionConsumerService?.push([{ _attr: attr }]);
				});
			} else {
				// console.warn('Missing endpoint of AssertionConsumerService');
			}

			// handle element order
			const existedElements = elementsOrder.filter((name) => isNonEmptyArray(descriptors[name]));
			existedElements.forEach((name) => {
				descriptors[name]?.forEach((e) => SPSSODescriptor.push({ [name]: e }));
			});

			// Re-assign the meta reference as a XML string|Buffer for use with the parent constructor
			meta = xml([
				{
					EntityDescriptor: [
						{
							_attr: {
								entityID,
								xmlns: names.metadata,
								'xmlns:assertion': names.assertion,
								'xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
							},
						},
						{ SPSSODescriptor },
					],
				},
			]);
		}

		// Use the re-assigned meta object reference here
		super(meta, [
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
	 * @param  {string} protocol         protocol binding (e.g. redirect, post)
	 * @return {string/[string]} URL of endpoint(s)
	 */
	public getAssertionConsumerService(protocol: BindingNamespace): string | string[] {
		if (isString(protocol)) {
			let location;
			if (isNonEmptyArray(this.meta.assertionConsumerService)) {
				// eslint-disable-next-line @typescript-eslint/no-unsafe-call
				this.meta.assertionConsumerService.forEach((obj: any) => {
					if (obj.binding === protocol) {
						location = obj.location;
						return;
					}
				});
			} else {
				if (this.meta.assertionConsumerService.binding === protocol) {
					location = this.meta.assertionConsumerService.location;
				}
			}
			// eslint-disable-next-line @typescript-eslint/no-unsafe-return
			return location;
		}
		// eslint-disable-next-line @typescript-eslint/no-unsafe-return
		return this.meta.assertionConsumerService;
	}
}
