/**
 * @file binding-redirect.ts
 * @author tngan
 * @desc Binding-level API, declare the functions using Redirect binding
 */
import type { BindingContext } from './binding';
import type { Entity, ParsedLogoutRequest } from './entity';
import type { IdentityProvider } from './entity-idp';
import type { ServiceProvider } from './entity-sp';
import { SamlifyError, SamlifyErrorCode } from './error';
import type { FlowResult } from './flow';
import { CustomTagReplacement, libsaml, RequestSignatureAlgorithm } from './libsaml';
import { BindingNamespace, StatusCode, wording } from './urn';
import { base64Encode, deflateString } from './utility';

const urlParams = wording.urlParams;

interface BuildRedirectConfig {
	baseUrl: string;
	context: string;
	relayState?: string;
	signed?: {
		privateKey: string | Buffer;
		privateKeyPass?: string;
		requestSignatureAlgorithm?: RequestSignatureAlgorithm;
	};
	type: 'SAMLRequest' | 'SAMLResponse' | 'LogoutRequest' | 'LogoutResponse';
}

/**
 * @private
 * @desc Helper of generating URL param/value pair
 * @param  {string} param     key
 * @param  {string} value     value of key
 * @param  {boolean} first    determine whether the param is the starting one in order to add query header '?'
 * @return {string}
 */
function pvPair(param: string, value: string, first?: boolean): string {
	return (first === true ? '?' : '&') + param + '=' + value;
}
/**
 * @private
 * @desc Refractored part of URL generation for login/logout request
 * @param  {string} type
 * @param  {boolean} isSigned
 * @param  {string} rawSaml
 * @param  {Entity} entity
 * @return {string}
 */
function buildRedirectURL(opts: BuildRedirectConfig) {
	const { baseUrl, type, signed, context } = opts;
	let { relayState = '' } = opts;
	const noParams = Array.from(new URL(baseUrl).searchParams).length === 0;
	const queryParam = libsaml.getQueryParamByType(type);
	// In general, this xmlstring is required to do deflate -> base64 -> urlencode
	const samlRequest = encodeURIComponent(base64Encode(deflateString(context)));
	if (relayState !== '') {
		relayState = pvPair(urlParams.relayState, encodeURIComponent(relayState));
	}
	if (signed) {
		const { privateKey, privateKeyPass, requestSignatureAlgorithm = libsaml.defaultSignatureAlgorithm } = signed;
		const sigAlg = pvPair(urlParams.sigAlg, encodeURIComponent(requestSignatureAlgorithm));
		const octetString = samlRequest + relayState + sigAlg;
		const signature = libsaml
			.constructMessageSignature(`${queryParam}=${octetString}`, privateKey, privateKeyPass, requestSignatureAlgorithm)
			.toString('base64');
		return (
			baseUrl + pvPair(queryParam, octetString, noParams) + pvPair(urlParams.signature, encodeURIComponent(signature))
		);
	}
	return baseUrl + pvPair(queryParam, samlRequest + relayState, noParams);
}
/**
 * @desc Redirect URL for login request
 * @param  {object} entity                       object includes both idp and sp
 * @param  {function} customTagReplacement      used when developers have their own login response template
 * @return {string} redirect URL
 */
function loginRequestRedirectURL(
	entity: { idp: IdentityProvider; sp: ServiceProvider },
	customTagReplacement?: CustomTagReplacement
): BindingContext {
	const metadata = { idp: entity.idp.getEntityMeta(), sp: entity.sp.getEntityMeta() };
	if (!metadata.idp || !metadata.sp) {
		throw new SamlifyError(SamlifyErrorCode.MissingMetadata);
	}
	const spSetting = entity.sp.getEntitySettings();
	const template = spSetting.loginRequestTemplate ?? libsaml.defaultLoginRequestTemplate;

	const baseUrl = metadata.idp.getSingleSignOnService(BindingNamespace.Redirect);
	const nameIDFormat = spSetting.nameIDFormat;
	const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;

	let values: Record<string, any> = {
		ID: entity.sp.generateID(),
		Destination: baseUrl,
		Issuer: metadata.sp.getEntityID(),
		IssueInstant: new Date().toISOString(),
		NameIDFormat: selectedNameIDFormat,
		AssertionConsumerServiceURL: metadata.sp.getAssertionConsumerService(BindingNamespace.Post),
		EntityID: metadata.sp.getEntityID(),
		AllowCreate: spSetting.allowCreate,
	};

	let rawSaml = template.context ?? '';
	// perform custom replacement
	if (customTagReplacement) {
		[rawSaml = rawSaml, values = values] = customTagReplacement(rawSaml, values);
	}
	// pickup any remaining
	rawSaml = libsaml.replaceTagsByValue(rawSaml, values);

	const type = urlParams.samlRequest;
	let signed: BuildRedirectConfig['signed'];
	if (metadata.sp.isAuthnRequestSigned()) {
		if (!spSetting.privateKey) {
			throw new SamlifyError(
				SamlifyErrorCode.MissingPrivateKey,
				`${metadata.sp.constructor.name} wants ${type} signed, but it did not provide a 'privateKey'.`
			);
		}
		signed = {
			privateKey: spSetting.privateKey,
			privateKeyPass: spSetting.privateKeyPass,
			requestSignatureAlgorithm: spSetting.requestSignatureAlgorithm,
		};
	}

	return {
		id: values.ID,
		context: buildRedirectURL({ baseUrl, context: rawSaml, relayState: spSetting.relayState, signed, type }),
	};
}
/**
 * @desc Redirect URL for logout request
 * @param  {Record<string, string>} user          current logged user (e.g. req.user)
 * @param  {object} entity                     object includes both idp and sp
 * @param  {function} customTagReplacement     used when developers have their own login response template
 * @return {string} redirect URL
 */
function logoutRequestRedirectURL(
	user: Record<string, string>,
	entity: { init: Entity; target: Entity },
	relayState?: string,
	customTagReplacement?: CustomTagReplacement
): BindingContext {
	const metadata = { init: entity.init.getEntityMeta(), target: entity.target.getEntityMeta() };
	if (!metadata.init || !metadata.target) {
		throw new SamlifyError(SamlifyErrorCode.MissingMetadata);
	}
	const initSetting = entity.init.getEntitySettings();
	const template = initSetting.logoutRequestTemplate ?? libsaml.defaultLogoutRequestTemplate;

	const nameIDFormat = initSetting.nameIDFormat;
	const baseUrl = metadata.target.getSingleLogoutService(BindingNamespace.Redirect);

	let values: Record<string, any> = {
		ID: entity.init.generateID(),
		Destination: baseUrl,
		EntityID: metadata.init.getEntityID(),
		Issuer: metadata.init.getEntityID(),
		IssueInstant: new Date().toISOString(),
		NameIDFormat: Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat,
		NameID: user.logoutNameID,
		SessionIndex: user.sessionIndex,
	};

	let rawSaml = template.context ?? '';
	// perform custom replacement
	if (customTagReplacement) {
		[rawSaml = rawSaml, values = values] = customTagReplacement(rawSaml, values);
	}
	// pickup any remaining
	rawSaml = libsaml.replaceTagsByValue(rawSaml, values);

	const type = urlParams.logoutRequest;
	let signed: BuildRedirectConfig['signed'];
	if (entity.target.getEntitySettings().wantLogoutRequestSigned) {
		if (!initSetting.privateKey) {
			throw new SamlifyError(
				SamlifyErrorCode.MissingPrivateKey,
				`${entity.target.constructor.name} wants ${type} signed, but ${entity.init.constructor.name} did not provide a 'privateKey'.`
			);
		}
		signed = {
			privateKey: initSetting.privateKey,
			privateKeyPass: initSetting.privateKeyPass,
			requestSignatureAlgorithm: initSetting.requestSignatureAlgorithm,
		};
	}

	return { id: values.ID, context: buildRedirectURL({ baseUrl, context: rawSaml, relayState, signed, type }) };
}
/**
 * @desc Redirect URL for logout response
 * @param  {Partial<FlowResult>|null} requescorresponding request, used to obtain the id
 * @param  {object} entity object includes both idp and sp
 * @param  {function} customTagReplacement used when developers have their own login response template
 */
function logoutResponseRedirectURL(
	requestInfo: Partial<FlowResult<ParsedLogoutRequest>> | null,
	entity: { init: Entity; target: Entity },
	relayState?: string,
	customTagReplacement?: CustomTagReplacement
): BindingContext {
	const metadata = { init: entity.init.getEntityMeta(), target: entity.target.getEntityMeta() };
	if (!metadata.init || !metadata.target) {
		throw new SamlifyError(SamlifyErrorCode.MissingMetadata);
	}
	const initSetting = entity.init.getEntitySettings();
	const template = initSetting.logoutResponseTemplate ?? libsaml.defaultLogoutResponseTemplate;

	const baseUrl = metadata.target.getSingleLogoutService(BindingNamespace.Redirect);

	let values: Record<string, any> = {
		ID: entity.init.generateID(),
		Destination: baseUrl,
		Issuer: metadata.init.getEntityID(),
		EntityID: metadata.init.getEntityID(),
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

	const type = urlParams.logoutResponse;
	let signed: BuildRedirectConfig['signed'];
	if (entity.target.getEntitySettings().wantLogoutResponseSigned) {
		if (!initSetting.privateKey) {
			throw new SamlifyError(
				SamlifyErrorCode.MissingPrivateKey,
				`${entity.target.constructor.name} wants ${type} signed, but ${entity.init.constructor.name} did not provide a 'privateKey'.`
			);
		}
		signed = {
			privateKey: initSetting.privateKey,
			privateKeyPass: initSetting.privateKeyPass,
			requestSignatureAlgorithm: initSetting.requestSignatureAlgorithm,
		};
	}

	return { id: values.ID, context: buildRedirectURL({ baseUrl, context: rawSaml, relayState, signed, type }) };
}

const redirectBinding = {
	loginRequestRedirectURL,
	logoutRequestRedirectURL,
	logoutResponseRedirectURL,
};

export default redirectBinding;
