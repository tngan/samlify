/**
 * @file binding-post.ts
 * @author tngan
 * @desc Binding-level API, declare the functions using POST binding
 */

import type { BindingContext, Entity } from './entity';
import type { IdentityProvider } from './entity-idp';
import type { ServiceProvider } from './entity-sp';
import { SamlifyError, SamlifyErrorCode } from './error';
import type { FlowResult } from './flow';
import libsaml, { CustomTagReplacement } from './libsaml';
import type { ParsedLoginRequest, ParsedLogoutRequest } from './types';
import { BindingNamespace, StatusCode } from './urn';
import { base64Decode, base64Encode, isNonEmptyArray } from './utility';

/**
 * @desc Generate a base64 encoded login request
 * @param  {string} referenceTagXPath           reference uri
 * @param  {object} entity                      object includes both idp and sp
 * @param  {function} customTagReplacement     used when developers have their own login response template
 */
function base64LoginRequest(
	referenceTagXPath: string,
	entity: { idp: IdentityProvider; sp: ServiceProvider },
	customTagReplacement?: CustomTagReplacement
): BindingContext {
	const metadata = { idp: entity.idp.getEntityMeta(), sp: entity.sp.getEntityMeta() };
	if (!metadata.idp || !metadata.sp) {
		throw new SamlifyError(SamlifyErrorCode.MissingMetadata);
	}
	const spSetting = entity.sp.getEntitySettings();
	const template = spSetting.loginRequestTemplate ?? libsaml.defaultLoginRequestTemplate;

	const nameIDFormat = spSetting.nameIDFormat;
	const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;

	let values: Record<string, any> = {
		ID: entity.sp.generateID(),
		Destination: metadata.idp.getSingleSignOnService(BindingNamespace.Post),
		Issuer: metadata.sp.getEntityID(),
		IssueInstant: new Date().toISOString(),
		AssertionConsumerServiceURL: metadata.sp.getAssertionConsumerService(BindingNamespace.Post),
		EntityID: metadata.sp.getEntityID(),
		AllowCreate: spSetting.allowCreate,
		NameIDFormat: selectedNameIDFormat,
	};

	let rawSaml = template.context ?? '';
	// perform custom replacement
	if (customTagReplacement) {
		[rawSaml = rawSaml, values = values] = customTagReplacement(rawSaml, values);
	}
	// pickup any remaining
	rawSaml = libsaml.replaceTagsByValue(rawSaml, values);

	if (metadata.idp.isWantAuthnRequestsSigned()) {
		const {
			privateKey,
			privateKeyPass,
			requestSignatureAlgorithm: signatureAlgorithm,
			transformationAlgorithms,
		} = spSetting;
		if (!privateKey) {
			throw new SamlifyError(
				SamlifyErrorCode.MissingPrivateKey,
				"IdentityProvider wants AuthnRequests signed, but ServiceProvider did not provide a 'privateKey'."
			);
		}
		return {
			id: values.ID,
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
	return { id: values.ID, context: base64Encode(rawSaml) };
}
/**
 * @desc Generate a base64 encoded login response
 * @param  {Partial<FlowResult>} requestInfo    corresponding request, used to obtain the id
 * @param  {object} entity                      object includes both idp and sp
 * @param  {object} user                        current logged user (e.g. req.user)
 * @param  {function} customTagReplacement      used when developers have their own login response template
 * @param  {boolean}  encryptThenSign           whether or not to encrypt then sign first (if signing). Defaults to sign-then-encrypt
 */
async function base64LoginResponse(
	requestInfo: Partial<FlowResult<ParsedLoginRequest>>,
	entity: { idp: IdentityProvider; sp: ServiceProvider },
	user: Record<string, string> = {},
	customTagReplacement?: CustomTagReplacement,
	encryptThenSign = false
): Promise<BindingContext> {
	const metadata = { idp: entity.idp.getEntityMeta(), sp: entity.sp.getEntityMeta() };
	if (!metadata.idp || !metadata.sp) {
		throw new SamlifyError(SamlifyErrorCode.MissingMetadata);
	}
	const idpSetting = entity.idp.getEntitySettings();
	const template = idpSetting.loginResponseTemplate ?? libsaml.defaultLoginResponseTemplate;
	const attributes = template.attributes;

	const spSetting = entity.sp.getEntitySettings();
	const nameIDFormat = idpSetting.nameIDFormat;
	const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;
	const base = metadata.sp.getAssertionConsumerService(BindingNamespace.Post);
	const nowTime = new Date();
	const spEntityID = metadata.sp.getEntityID();
	const fiveMinutesLaterTime = new Date(nowTime.getTime());
	fiveMinutesLaterTime.setMinutes(fiveMinutesLaterTime.getMinutes() + 5);
	const fiveMinutesLater = fiveMinutesLaterTime.toISOString();
	const now = nowTime.toISOString();
	const acl = metadata.sp.getAssertionConsumerService(BindingNamespace.Post);

	let values: Record<string, any> = {
		ID: entity.idp.generateID(),
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
		InResponseTo: requestInfo.extract?.request?.id ?? '',
		AuthnStatement: '',
		// First fill in attributes
		AttributeStatement: isNonEmptyArray(attributes)
			? libsaml.replaceTagsByValue(
					libsaml.attributeStatementBuilder(attributes),
					libsaml.attributeStatementTagBuilder(attributes, user)
			  )
			: '',
	};

	let rawSaml = template.context;
	// perform custom replacement
	if (customTagReplacement) {
		[rawSaml = rawSaml, values = values] = customTagReplacement(rawSaml, values);
	}
	// pickup any remaining
	rawSaml = libsaml.replaceTagsByValue(rawSaml, values);

	const getConfig = (wantsSigned: string) => {
		const { privateKey, privateKeyPass, requestSignatureAlgorithm: signatureAlgorithm } = idpSetting;
		if (!privateKey) {
			throw new SamlifyError(
				SamlifyErrorCode.MissingPrivateKey,
				`ServiceProvider wants ${wantsSigned} signed, but IdentityProvider did not provide a 'privateKey'.`
			);
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
			...getConfig('Assertions'),
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
			...getConfig('Message'),
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

	// console.debug('after message signed', rawSaml);

	if (idpSetting.isAssertionEncrypted) {
		// console.debug('idp is configured to do encryption');
		const context = await libsaml.encryptAssertion(entity.idp, entity.sp, rawSaml);
		if (encryptThenSign) {
			//need to decode it
			rawSaml = base64Decode(context) as string;
		} else {
			return { id: values.ID, context };
		}
	}

	//sign after encrypting
	if (encryptThenSign && (spSetting.wantMessageSigned || !metadata.sp.isWantAssertionsSigned())) {
		rawSaml = libsaml.constructSAMLSignature({
			...getConfig('Message'),
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
	customTagReplacement?: CustomTagReplacement
): BindingContext {
	const metadata = { init: entity.init.getEntityMeta(), target: entity.target.getEntityMeta() };
	if (!metadata.init || !metadata.target) {
		throw new SamlifyError(SamlifyErrorCode.MissingMetadata);
	}
	const initSetting = entity.init.getEntitySettings();
	const template = initSetting.logoutRequestTemplate ?? libsaml.defaultLogoutRequestTemplate;

	const nameIDFormat = initSetting.nameIDFormat;
	const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;

	let values: Record<string, any> = {
		ID: entity.init.generateID(),
		Destination: metadata.target.getSingleLogoutService(BindingNamespace.Post),
		Issuer: metadata.init.getEntityID(),
		IssueInstant: new Date().toISOString(),
		EntityID: metadata.init.getEntityID(),
		NameIDFormat: selectedNameIDFormat,
		NameID: user.logoutNameID,
	};

	let rawSaml = template.context ?? '';
	// perform custom replacement
	if (customTagReplacement) {
		[rawSaml = rawSaml, values = values] = customTagReplacement(rawSaml, values);
	}
	// pickup any remaining
	rawSaml = libsaml.replaceTagsByValue(rawSaml, values);

	if (entity.target.getEntitySettings().wantLogoutRequestSigned) {
		// Need to embeded XML signature
		const {
			privateKey,
			privateKeyPass,
			requestSignatureAlgorithm: signatureAlgorithm,
			transformationAlgorithms,
		} = initSetting;
		if (!privateKey) {
			throw new SamlifyError(
				SamlifyErrorCode.MissingPrivateKey,
				`${entity.target.constructor.name} wants LogoutRequest signed, but ${entity.init.constructor.name} did not provide a 'privateKey'.`
			);
		}
		return {
			id: values.ID,
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
	return { id: values.ID, context: base64Encode(rawSaml) };
}
/**
 * @desc Generate a base64 encoded logout response
 * @param  {Partial<FlowResult>|null} requestInfo  corresponding request, used to obtain the id
 * @param  {object} entity                         object includes both idp and sp
 * @param  {string} referenceTagXPath              reference uri
 * @param  {function} customTagReplacement         used when developers have their own login response template
 */
function base64LogoutResponse(
	requestInfo: Partial<FlowResult<ParsedLogoutRequest>> | null,
	entity: { init: Entity; target: Entity },
	customTagReplacement?: CustomTagReplacement
): BindingContext {
	const metadata = { init: entity.init.getEntityMeta(), target: entity.target.getEntityMeta() };
	if (!metadata.init || !metadata.target) {
		throw new SamlifyError(SamlifyErrorCode.MissingMetadata);
	}
	const initSetting = entity.init.getEntitySettings();
	const template = initSetting.logoutResponseTemplate ?? libsaml.defaultLogoutResponseTemplate;

	let values: Record<string, any> = {
		ID: entity.init.generateID(),
		Destination: metadata.target.getSingleLogoutService(BindingNamespace.Post),
		EntityID: metadata.init.getEntityID(),
		Issuer: metadata.init.getEntityID(),
		IssueInstant: new Date().toISOString(),
		StatusCode: StatusCode.Success,
		InResponseTo: requestInfo?.extract?.request?.id ?? '',
	};

	let rawSaml = template.context;
	// perform custom replacement
	if (customTagReplacement) {
		[rawSaml = rawSaml, values = values] = customTagReplacement(rawSaml, values);
	}
	// pickup any remaining
	rawSaml = libsaml.replaceTagsByValue(rawSaml, values);

	if (entity.target.getEntitySettings().wantLogoutResponseSigned) {
		const {
			privateKey,
			privateKeyPass,
			requestSignatureAlgorithm: signatureAlgorithm,
			transformationAlgorithms,
		} = initSetting;
		if (!privateKey) {
			throw new SamlifyError(
				SamlifyErrorCode.MissingPrivateKey,
				`${entity.target.constructor.name} wants LogoutResponse signed, but ${entity.init.constructor.name} did not provide a 'privateKey'.`
			);
		}
		return {
			id: values.ID,
			context: libsaml.constructSAMLSignature({
				isMessageSigned: true,
				transformationAlgorithms: transformationAlgorithms,
				privateKey: privateKey.toString(),
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
	return { id: values.ID, context: base64Encode(rawSaml) };
}

const postBinding = {
	base64LoginRequest,
	base64LoginResponse,
	base64LogoutRequest,
	base64LogoutResponse,
};

export default postBinding;
