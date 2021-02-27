/**
 * @file binding-redirect.ts
 * @author tngan
 * @desc Binding-level API, declare the functions using Redirect binding
 */
import type { BindingContext, Entity } from './entity';
import type { IdentityProvider } from './entity-idp';
import type { ServiceProvider } from './entity-sp';
import libsaml, { CustomTagReplacement } from './libsaml';
import type { EntitySetting } from './types';
import { BindingNamespace, StatusCode, wording } from './urn';
import { base64Encode, deflateString, get } from './utility';

const urlParams = wording.urlParams;

interface BuildRedirectConfig {
	baseUrl: string;
	type: string;
	isSigned: boolean;
	context: string;
	entitySetting: EntitySetting;
	relayState?: string;
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
 * @param  {object} entitySetting
 * @return {string}
 */
function buildRedirectURL(opts: BuildRedirectConfig) {
	const { baseUrl, type, isSigned, context, entitySetting } = opts;
	let { relayState = '' } = opts;
	const noParams = Array.from(new URL(baseUrl).searchParams).length === 0;
	const queryParam = libsaml.getQueryParamByType(type);
	// In general, this xmlstring is required to do deflate -> base64 -> urlencode
	const samlRequest = encodeURIComponent(base64Encode(deflateString(context)));
	if (relayState !== '') {
		relayState = pvPair(urlParams.relayState, encodeURIComponent(relayState));
	}
	if (isSigned) {
		if (!entitySetting.privateKey) {
			throw new Error('ERR_MISSING_PRIVATE_KEY');
		}
		if (!entitySetting.requestSignatureAlgorithm) {
			throw new Error('ERR_MISSING_REQUEST_SIGNATURE_ALGORITHM');
		}
		const sigAlg = pvPair(urlParams.sigAlg, encodeURIComponent(entitySetting.requestSignatureAlgorithm));
		const octetString = samlRequest + relayState + sigAlg;
		const signature = libsaml
			.constructMessageSignature(
				queryParam + '=' + octetString,
				entitySetting.privateKey,
				entitySetting.privateKeyPass,
				entitySetting.requestSignatureAlgorithm
			)
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
	const metadata = {
		idp: entity.idp.entityMeta,
		sp: entity.sp.entityMeta,
	};
	if (metadata && metadata.idp && metadata.sp) {
		const spSetting = entity.sp.entitySetting;
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

		return {
			id: values.ID,
			context: buildRedirectURL({
				context: rawSaml,
				type: urlParams.samlRequest,
				isSigned: metadata.sp.isAuthnRequestSigned(),
				entitySetting: spSetting,
				baseUrl,
				relayState: spSetting.relayState,
			}),
		};
	}
	throw new Error('ERR_GENERATE_REDIRECT_LOGIN_REQUEST_MISSING_METADATA');
}
/**
 * @desc Redirect URL for logout request
 * @param  {object} user                        current logged user (e.g. req.user)
 * @param  {object} entity                      object includes both idp and sp
 * @param  {function} customTagReplacement     used when developers have their own login response template
 * @return {string} redirect URL
 */
function logoutRequestRedirectURL(
	user: Record<string, any>,
	entity: { init: Entity; target: Entity },
	relayState?: string,
	customTagReplacement?: CustomTagReplacement
): BindingContext {
	const metadata = {
		init: entity.init.entityMeta,
		target: entity.target.entityMeta,
	};
	if (metadata && metadata.init && metadata.target) {
		const initSetting = entity.init.entitySetting;
		const template = initSetting.logoutRequestTemplate ?? libsaml.defaultLogoutRequestTemplate;

		const nameIDFormat = initSetting.nameIDFormat;
		const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;
		const baseUrl = metadata.target.getSingleLogoutService(BindingNamespace.Redirect);

		let values: Record<string, any> = {
			ID: entity.init.generateID(),
			Destination: baseUrl,
			EntityID: metadata.init.getEntityID(),
			Issuer: metadata.init.getEntityID(),
			IssueInstant: new Date().toISOString(),
			NameIDFormat: selectedNameIDFormat,
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

		return {
			id: values.ID,
			context: buildRedirectURL({
				context: rawSaml,
				relayState,
				type: urlParams.logoutRequest,
				isSigned: entity.target.entitySetting.wantLogoutRequestSigned ?? false,
				entitySetting: initSetting,
				baseUrl,
			}),
		};
	}
	throw new Error('ERR_GENERATE_REDIRECT_LOGOUT_REQUEST_MISSING_METADATA');
}
/**
 * @desc Redirect URL for logout response
 * @param  {Record<string, unknown>|null} requescorresponding request, used to obtain the id
 * @param  {object} entity object includes both idp and sp
 * @param  {function} customTagReplacement used when developers have their own login response template
 */
function logoutResponseRedirectURL(
	requestInfo: Record<string, any> | null,
	entity: { init: Entity; target: Entity },
	relayState?: string,
	customTagReplacement?: CustomTagReplacement
): BindingContext {
	const metadata = {
		init: entity.init.entityMeta,
		target: entity.target.entityMeta,
	};
	if (metadata && metadata.init && metadata.target) {
		const initSetting = entity.init.entitySetting;
		const template = initSetting.logoutResponseTemplate ?? libsaml.defaultLogoutResponseTemplate;

		const baseUrl = metadata.target.getSingleLogoutService(BindingNamespace.Redirect);

		let values: Record<string, any> = {
			ID: entity.init.generateID(),
			Destination: baseUrl,
			Issuer: metadata.init.getEntityID(),
			EntityID: metadata.init.getEntityID(),
			IssueInstant: new Date().toISOString(),
			StatusCode: StatusCode.Success,
			InResponseTo: get(requestInfo, 'extract.logoutRequest.id', ''),
		};

		let rawSaml = template.context;
		// perform custom replacement
		if (customTagReplacement) {
			[rawSaml = rawSaml, values = values] = customTagReplacement(rawSaml, values);
		}
		// pickup any remaining
		rawSaml = libsaml.replaceTagsByValue(rawSaml, values);

		return {
			id: values.ID,
			context: buildRedirectURL({
				baseUrl,
				type: urlParams.logoutResponse,
				isSigned: entity.target.entitySetting.wantLogoutResponseSigned ?? false,
				context: rawSaml,
				entitySetting: initSetting,
				relayState,
			}),
		};
	}
	throw new Error('ERR_GENERATE_REDIRECT_LOGOUT_RESPONSE_MISSING_METADATA');
}

const redirectBinding = {
	loginRequestRedirectURL,
	logoutRequestRedirectURL,
	logoutResponseRedirectURL,
};

export default redirectBinding;
