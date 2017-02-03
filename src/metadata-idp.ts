/**
* @file metadata-idp.ts
* @author tngan
* @desc  Metadata of identity provider
*/
import Metadata, { MetadataInterface } from './metadata';
import { namespace } from './urn';
import libsaml from './libsaml';

const xml = require('xml');

export interface IdpMetadataInterface extends MetadataInterface {

}

/*
 * @desc interface function
 */
export default function (meta) {
	return new IdpMetadata(meta);
}

export class IdpMetadata extends Metadata {

	constructor(meta) {

		const byMetadata = typeof meta === 'string';

		if (!byMetadata) {
			let entityID = meta.entityID;
			let wantAuthnRequestsSigned = meta.wantAuthnRequestsSigned === true;
			let signingCertFile = meta.signingCertFile;
			let encryptCertFile = meta.encryptCertFile;
			let nameIDFormat = meta.nameIDFormat || [];
			let singleSignOnService = meta.singleSignOnService || [];
			let singleLogoutService = meta.singleLogoutService || [];
			let IDPSSODescriptor: Array<any> = [{
				_attr: {
					WantAuthnRequestsSigned: String(wantAuthnRequestsSigned),
					protocolSupportEnumeration: namespace.names.protocol
				}
			}];

			if (signingCertFile) {
				IDPSSODescriptor.push(libsaml.createKeySection('signing', signingCertFile));
			} else {
				console.warn('Construct identity provider - missing signing certificate');
			}

			if (encryptCertFile) {
				IDPSSODescriptor.push(libsaml.createKeySection('encrypt', encryptCertFile));
			} else {
				console.warn('Construct identity provider - missing encrypt certificate');
			}

			if (nameIDFormat && nameIDFormat.length > 0) {
				nameIDFormat.forEach(f => IDPSSODescriptor.push({ NameIDFormat: f }));
			}

			if (singleSignOnService && singleSignOnService.length > 0) {
				singleSignOnService.forEach(a => {
					let attr: any = {};
					let indexCount = 0;
					if (a.isDefault) {
						attr.isDefault = true;
					}
					attr.index = (indexCount++).toString();
					attr.Binding = a.Binding;
					attr.Location = a.Location;
					IDPSSODescriptor.push({
						SingleSignOnService: [{ _attr: attr }]
					});
				});
			} else {
				throw new Error('Missing endpoint of SingleSignOnService');
			}

			if (singleLogoutService && singleLogoutService.length > 0) {
				singleLogoutService.forEach(a => {
					let attr: any = {};
					let indexCount = 0;
					if (a.isDefault) {
						attr.isDefault = true;
					}
					attr.index = (indexCount++).toString();
					attr.Binding = a.Binding;
					attr.Location = a.Location;
					IDPSSODescriptor.push({ SingleLogoutService: [{ _attr: attr }] });
				});
			} else {
				console.warn('Construct identity  provider - missing endpoint of SingleLogoutService');
			}
			// Create a new metadata by setting
			meta = xml([{
				EntityDescriptor: [{
					_attr: {
						'xmlns:md': namespace.names.metadata,
						'xmlns:assertion': namespace.names.assertion,
						'xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
						entityID
					}
				}, { IDPSSODescriptor }]
			}]);
		}

		super(meta, [{
			localName: 'IDPSSODescriptor',
			attributes: ['WantAuthnRequestsSigned']
		}, {
			localName: { tag: 'SingleSignOnService', key: 'Binding' },
			attributeTag: 'Location'
		}], !byMetadata);

	}
  /**
  * @desc Get the preference whether it wants a signed request
  * @return {boolean} WantAuthnRequestsSigned
  */
	isWantAuthnRequestsSigned(): boolean {
		let was = this.meta.idpssodescriptor.wantauthnrequestssigned;
		if (was === undefined) {
			return false;
		}
		return String(was) === 'true';
	};
  /**
  * @desc Get the entity endpoint for single sign on service
  * @param  {string} binding      protocol binding (e.g. redirect, post)
  * @return {string/object} location
  */
	getSingleSignOnService(binding: string): string | Object {
		if (typeof binding === 'string') {
			let location;
			let bindName = namespace.binding[binding];
			this.meta.singlesignonservice.forEach(function (obj) {
				if (obj[bindName]) {
					location = obj[bindName];
					return;
				}
			});
			return location;
		}
		return this.meta.singlesignonservice;
	}
}
