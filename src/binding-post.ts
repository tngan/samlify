/**
 * @file binding-post.ts
 * @author tngan
 * @desc Binding-level API, declare the functions using POST binding
 */

import type { BindingContext, Entity } from './entity';
import type { IdentityProvider } from './entity-idp';
import type { ServiceProvider } from './entity-sp';
import libsaml from './libsaml';
import { BindingNamespace, StatusCode } from './urn';
import { base64Decode, base64Encode, get } from './utility';

/**
 * @desc Generate a base64 encoded login request
 * @param  {string} referenceTagXPath           reference uri
 * @param  {object} entity                      object includes both idp and sp
 * @param  {function} customTagReplacement     used when developers have their own login response template
 */
function base64LoginRequest(
	referenceTagXPath: string,
	entity: { idp: IdentityProvider; sp: ServiceProvider },
	customTagReplacement?: (template: string) => BindingContext
): BindingContext {
	const metadata = { idp: entity.idp.entityMeta, sp: entity.sp.entityMeta };
	const spSetting = entity.sp.entitySetting;
	let id = '';

	if (metadata && metadata.idp && metadata.sp) {
		let rawSaml: string;
		if (spSetting.loginRequestTemplate?.context && customTagReplacement) {
			const info = customTagReplacement(spSetting.loginRequestTemplate.context);
			// @ts-expect-error todo
			id = get(info, 'id', null);
			// @ts-expect-error todo
			rawSaml = get(info, 'context', null);
		} else {
			const nameIDFormat = spSetting.nameIDFormat;
			const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;
			id = entity.sp.generateID();
			rawSaml = libsaml.replaceTagsByValue(libsaml.defaultLoginRequestTemplate.context, {
				ID: id,
				Destination: metadata.idp.getSingleSignOnService(BindingNamespace.Post),
				Issuer: metadata.sp.getEntityID(),
				IssueInstant: new Date().toISOString(),
				AssertionConsumerServiceURL: metadata.sp.getAssertionConsumerService(BindingNamespace.Post),
				EntityID: metadata.sp.getEntityID(),
				AllowCreate: spSetting.allowCreate,
				NameIDFormat: selectedNameIDFormat,
			} as any);
		}
		if (metadata.idp.isWantAuthnRequestsSigned()) {
			const {
				privateKey,
				privateKeyPass,
				requestSignatureAlgorithm: signatureAlgorithm,
				transformationAlgorithms,
			} = spSetting;
			if (!privateKey) {
				throw new Error('ERR_MISSING_PRIVATE_KEY');
			}
			return {
				id,
				context: libsaml.constructSAMLSignature({
					referenceTagXPath,
					privateKey: privateKey.toString(),
					privateKeyPass,
					signatureAlgorithm,
					transformationAlgorithms,
					rawSamlMessage: rawSaml,
					signingCert: metadata.sp.getX509Certificate('signing'),
					signatureConfig: spSetting.signatureConfig || {
						prefix: 'ds',
						location: {
							reference: "/*[local-name(.)='AuthnRequest']/*[local-name(.)='Issuer']",
							action: 'after',
						},
					},
				}),
			};
		}
		// No need to embeded XML signature
		return {
			id,
			context: base64Encode(rawSaml),
		};
	}
	throw new Error('ERR_GENERATE_POST_LOGIN_REQUEST_MISSING_METADATA');
}
/**
 * @desc Generate a base64 encoded login response
 * @param  {object} requestInfo                 corresponding request, used to obtain the id
 * @param  {object} entity                      object includes both idp and sp
 * @param  {object} user                        current logged user (e.g. req.user)
 * @param  {function} customTagReplacement     used when developers have their own login response template
 * @param  {boolean}  encryptThenSign           whether or not to encrypt then sign first (if signing). Defaults to sign-then-encrypt
 */
async function base64LoginResponse(
	requestInfo: Record<string, unknown> = {},
	entity: { idp: IdentityProvider; sp: ServiceProvider },
	user: Record<string, string> = {},
	customTagReplacement?: (template: string) => BindingContext,
	encryptThenSign = false
): Promise<BindingContext> {
	const idpSetting = entity.idp.entitySetting;
	const spSetting = entity.sp.entitySetting;
	const id = entity.idp.generateID();
	const metadata = {
		idp: entity.idp.entityMeta,
		sp: entity.sp.entityMeta,
	};
	const nameIDFormat = idpSetting.nameIDFormat;
	const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;
	if (metadata && metadata.idp && metadata.sp) {
		const base = metadata.sp.getAssertionConsumerService(BindingNamespace.Post);
		let rawSaml: string;
		const nowTime = new Date();
		const spEntityID = metadata.sp.getEntityID();
		const fiveMinutesLaterTime = new Date(nowTime.getTime());
		fiveMinutesLaterTime.setMinutes(fiveMinutesLaterTime.getMinutes() + 5);
		const fiveMinutesLater = fiveMinutesLaterTime.toISOString();
		const now = nowTime.toISOString();
		const acl = metadata.sp.getAssertionConsumerService(BindingNamespace.Post);
		const values: any = {
			ID: id,
			AssertionID: entity.idp.generateID(),
			Destination: base,
			Audience: spEntityID,
			EntityID: spEntityID,
			SubjectRecipient: acl,
			Issuer: metadata.idp.getEntityID(),
			IssueInstant: now,
			AssertionConsumerServiceURL: acl,
			StatusCode: StatusCode.Success,
			// can be customized
			ConditionsNotBefore: now,
			ConditionsNotOnOrAfter: fiveMinutesLater,
			SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater,
			NameIDFormat: selectedNameIDFormat,
			NameID: user.email || '',
			InResponseTo: get(requestInfo, 'extract.request.id', ''),
			AuthnStatement: '',
			AttributeStatement: '',
		};
		if (idpSetting.loginResponseTemplate && customTagReplacement) {
			const template = customTagReplacement(idpSetting.loginResponseTemplate.context);
			// @ts-expect-error todo
			rawSaml = get(template, 'context', null);
		} else {
			rawSaml = libsaml.replaceTagsByValue(libsaml.defaultLoginResponseTemplate.context, values);
		}
		const getConfig = () => {
			const { privateKey, privateKeyPass, requestSignatureAlgorithm: signatureAlgorithm } = idpSetting;
			if (!privateKey) {
				throw new Error('ERR_MISSING_PRIVATE_KEY');
			}
			return {
				privateKey: privateKey?.toString(),
				privateKeyPass,
				signatureAlgorithm,
				signingCert: metadata.idp.getX509Certificate('signing'),
				isBase64Output: false,
			};
		};

		// step: sign assertion ? -> encrypted ? -> sign message ?
		if (metadata.sp.isWantAssertionsSigned()) {
			// console.debug('sp wants assertion signed');
			rawSaml = libsaml.constructSAMLSignature({
				...getConfig(),
				rawSamlMessage: rawSaml,
				transformationAlgorithms: spSetting.transformationAlgorithms,
				referenceTagXPath: "/*[local-name(.)='Response']/*[local-name(.)='Assertion']",
				signatureConfig: {
					prefix: 'ds',
					location: {
						reference: "/*[local-name(.)='Response']/*[local-name(.)='Assertion']/*[local-name(.)='Issuer']",
						action: 'after',
					},
				},
			});
		}

		// console.debug('after assertion signed', rawSaml);

		// SAML response must be signed sign message first, then encrypt
		if (!encryptThenSign && (spSetting.wantMessageSigned || !metadata.sp.isWantAssertionsSigned())) {
			// console.debug('sign then encrypt and sign entire message');
			rawSaml = libsaml.constructSAMLSignature({
				...getConfig(),
				rawSamlMessage: rawSaml,
				isMessageSigned: true,
				transformationAlgorithms: spSetting.transformationAlgorithms,
				signatureConfig: spSetting.signatureConfig || {
					prefix: 'ds',
					location: { reference: "/*[local-name(.)='Response']/*[local-name(.)='Issuer']", action: 'after' },
				},
			});
		}

		// console.debug('after message signed', rawSaml);

		if (idpSetting.isAssertionEncrypted) {
			// console.debug('idp is configured to do encryption');
			const context = await libsaml.encryptAssertion(entity.idp, entity.sp, rawSaml);
			if (encryptThenSign) {
				//need to decode it
				rawSaml = base64Decode(context) as string;
			} else {
				return { id, context };
			}
		}

		//sign after encrypting
		if (encryptThenSign && (spSetting.wantMessageSigned || !metadata.sp.isWantAssertionsSigned())) {
			rawSaml = libsaml.constructSAMLSignature({
				...getConfig(),
				rawSamlMessage: rawSaml,
				isMessageSigned: true,
				transformationAlgorithms: spSetting.transformationAlgorithms,
				signatureConfig: spSetting.signatureConfig || {
					prefix: 'ds',
					location: {
						reference: "/*[local-name(.)='Response']/*[local-name(.)='Issuer']",
						action: 'after',
					},
				},
			});
		}

		return { id: values.ID, context: base64Encode(rawSaml) };
	}
	throw new Error('ERR_GENERATE_POST_LOGIN_RESPONSE_MISSING_METADATA');
}
/**
 * @desc Generate a base64 encoded logout request
 * @param  {object} user                         current logged user (e.g. req.user)
 * @param  {string} referenceTagXPath            reference uri
 * @param  {object} entity                       object includes both idp and sp
 * @param  {function} customTagReplacement      used when developers have their own login response template
 * @return {string} base64 encoded request
 */
function base64LogoutRequest(
	user: Record<string, string>,
	referenceTagXPath: string,
	entity: { init: Entity; target: Entity },
	customTagReplacement?: (template: string) => BindingContext
): BindingContext {
	const metadata = { init: entity.init.entityMeta, target: entity.target.entityMeta };
	const initSetting = entity.init.entitySetting;
	const nameIDFormat = initSetting.nameIDFormat;
	const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;
	let id = '';
	if (metadata && metadata.init && metadata.target) {
		let rawSaml: string;
		if (initSetting.logoutRequestTemplate?.context && customTagReplacement) {
			const template = customTagReplacement(initSetting.logoutRequestTemplate.context);
			// @ts-expect-error todo
			id = get(template, 'id', null);
			// @ts-expect-error todo
			rawSaml = get(template, 'context', null);
		} else {
			id = entity.init.generateID();
			const values: any = {
				ID: id,
				Destination: metadata.target.getSingleLogoutService(BindingNamespace.Redirect),
				Issuer: metadata.init.getEntityID(),
				IssueInstant: new Date().toISOString(),
				EntityID: metadata.init.getEntityID(),
				NameIDFormat: selectedNameIDFormat,
				NameID: user.logoutNameID,
			};
			rawSaml = libsaml.replaceTagsByValue(libsaml.defaultLogoutRequestTemplate.context, values);
		}
		if (entity.target.entitySetting.wantLogoutRequestSigned) {
			// Need to embeded XML signature
			const {
				privateKey,
				privateKeyPass,
				requestSignatureAlgorithm: signatureAlgorithm,
				transformationAlgorithms,
			} = initSetting;
			if (!privateKey) {
				throw new Error('ERR_MISSING_PRIVATE_KEY');
			}
			return {
				id,
				context: libsaml.constructSAMLSignature({
					referenceTagXPath,
					privateKey: privateKey.toString(),
					privateKeyPass,
					signatureAlgorithm,
					transformationAlgorithms,
					rawSamlMessage: rawSaml,
					signingCert: metadata.init.getX509Certificate('signing'),
					signatureConfig: initSetting.signatureConfig || {
						prefix: 'ds',
						location: {
							reference: "/*[local-name(.)='LogoutRequest']/*[local-name(.)='Issuer']",
							action: 'after',
						},
					},
				}),
			};
		}
		return {
			id,
			context: base64Encode(rawSaml),
		};
	}
	throw new Error('ERR_GENERATE_POST_LOGOUT_REQUEST_MISSING_METADATA');
}
/**
 * @desc Generate a base64 encoded logout response
 * @param  {object} requestInfo                 corresponding request, used to obtain the id
 * @param  {string} referenceTagXPath           reference uri
 * @param  {object} entity                      object includes both idp and sp
 * @param  {function} customTagReplacement     used when developers have their own login response template
 */
function base64LogoutResponse(
	requestInfo: Record<string, any> | null,
	entity: { init: Entity; target: Entity },
	customTagReplacement?: (template: string) => BindingContext
): BindingContext {
	const metadata = {
		init: entity.init.entityMeta,
		target: entity.target.entityMeta,
	};
	let id = '';
	const initSetting = entity.init.entitySetting;
	if (metadata && metadata.init && metadata.target) {
		let rawSaml;
		if (initSetting.logoutResponseTemplate && customTagReplacement) {
			const template = customTagReplacement(initSetting.logoutResponseTemplate.context);
			id = template.id;
			rawSaml = template.context;
		} else {
			id = entity.init.generateID();
			const values: any = {
				ID: id,
				Destination: metadata.target.getSingleLogoutService(BindingNamespace.Post),
				EntityID: metadata.init.getEntityID(),
				Issuer: metadata.init.getEntityID(),
				IssueInstant: new Date().toISOString(),
				StatusCode: StatusCode.Success,
				InResponseTo: get(requestInfo, 'extract.request.id', ''),
			};
			rawSaml = libsaml.replaceTagsByValue(libsaml.defaultLogoutResponseTemplate.context, values);
		}
		if (entity.target.entitySetting.wantLogoutResponseSigned) {
			const {
				privateKey,
				privateKeyPass,
				requestSignatureAlgorithm: signatureAlgorithm,
				transformationAlgorithms,
			} = initSetting;
			if (!privateKey) {
				throw new Error('ERR_MISSING_PRIVATE_KEY');
			}
			return {
				id,
				context: libsaml.constructSAMLSignature({
					isMessageSigned: true,
					transformationAlgorithms: transformationAlgorithms,
					// @ts-expect-error todo
					privateKey,
					privateKeyPass,
					signatureAlgorithm,
					rawSamlMessage: rawSaml,
					signingCert: metadata.init.getX509Certificate('signing'),
					signatureConfig: {
						prefix: 'ds',
						location: {
							reference: "/*[local-name(.)='LogoutResponse']/*[local-name(.)='Issuer']",
							action: 'after',
						},
					},
				}),
			};
		}
		return {
			id,
			context: base64Encode(rawSaml),
		};
	}
	throw new Error('ERR_GENERATE_POST_LOGOUT_RESPONSE_MISSING_METADATA');
}

const postBinding = {
	base64LoginRequest,
	base64LoginResponse,
	base64LogoutRequest,
	base64LogoutResponse,
};

export default postBinding;
