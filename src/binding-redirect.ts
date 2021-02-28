/**
 * @file binding-redirect.ts
 * @author tngan
 * @desc Binding-level API, declare the functions using Redirect binding
 */
import type { BindingContext, Entity } from './entity';
import type { IdentityProvider } from './entity-idp';
import type { ServiceProvider } from './entity-sp';
import libsaml from './libsaml';
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
	customTagReplacement?: (template: string) => BindingContext
): BindingContext {
	const metadata = { idp: entity.idp.entityMeta, sp: entity.sp.entityMeta };
	if (metadata && metadata.idp && metadata.sp) {
		const spSetting = entity.sp.entitySetting;
		let id = '';

		const baseUrl = metadata.idp.getSingleSignOnService(BindingNamespace.Redirect);
		let rawSaml: string;
		if (spSetting.loginRequestTemplate?.context && customTagReplacement) {
			const info = customTagReplacement(spSetting.loginRequestTemplate.context);
			// @ts-expect-error todo
			id = get(info, 'id', null);
			// @ts-expect-error ttodo
			rawSaml = get(info, 'context', null);
		} else {
			const nameIDFormat = spSetting.nameIDFormat;
			const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;
			id = entity.sp.generateID();
			rawSaml = libsaml.replaceTagsByValue(libsaml.defaultLoginRequestTemplate.context, {
				ID: id,
				Destination: baseUrl,
				Issuer: metadata.sp.getEntityID(),
				IssueInstant: new Date().toISOString(),
				NameIDFormat: selectedNameIDFormat,
				AssertionConsumerServiceURL: metadata.sp.getAssertionConsumerService(BindingNamespace.Post),
				EntityID: metadata.sp.getEntityID(),
				AllowCreate: spSetting.allowCreate,
			} as any);
		}
		return {
			id,
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
	customTagReplacement?: (template: string, tags: Record<string, unknown>) => BindingContext
): BindingContext {
	const metadata = { init: entity.init.entityMeta, target: entity.target.entityMeta };
	const initSetting = entity.init.entitySetting;
	let id: string = entity.init.generateID();
	const nameIDFormat = initSetting.nameIDFormat;
	const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;

	if (metadata && metadata.init && metadata.target) {
		const baseUrl = metadata.target.getSingleLogoutService(BindingNamespace.Redirect);
		let rawSaml = '';
		const requiredTags = {
			ID: id,
			Destination: baseUrl,
			EntityID: metadata.init.getEntityID(),
			Issuer: metadata.init.getEntityID(),
			IssueInstant: new Date().toISOString(),
			NameIDFormat: selectedNameIDFormat,
			NameID: user.logoutNameID,
			SessionIndex: user.sessionIndex,
		};
		if (initSetting.logoutRequestTemplate?.context && customTagReplacement) {
			const info = customTagReplacement(initSetting.logoutRequestTemplate.context, requiredTags);
			// @ts-expect-error todo
			id = get(info, 'id', null);
			// @ts-expect-error todo
			rawSaml = get(info, 'context', null);
		} else {
			rawSaml = libsaml.replaceTagsByValue(libsaml.defaultLogoutRequestTemplate.context, requiredTags as any);
		}
		return {
			id,
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
 * @param  {object} entity                      object includes both idp and sp
 * @param  {function} customTagReplacement     used when developers have their own login response template
 */
function logoutResponseRedirectURL(
	requestInfo: Record<string, any> | null,
	entity: { init: Entity; target: Entity },
	relayState?: string,
	customTagReplacement?: (template: string) => BindingContext
): BindingContext {
	const metadata = {
		init: entity.init.entityMeta,
		target: entity.target.entityMeta,
	};
	const initSetting = entity.init.entitySetting;
	let id: string = entity.init.generateID();
	if (metadata && metadata.init && metadata.target) {
		const baseUrl = metadata.target.getSingleLogoutService(BindingNamespace.Redirect);
		let rawSaml: string;
		if (initSetting.logoutResponseTemplate?.context && customTagReplacement) {
			const template = customTagReplacement(initSetting.logoutResponseTemplate.context);
			// @ts-expect-error todo
			id = get(template, 'id', null);
			// @ts-expect-error todo
			rawSaml = get(template, 'context', null);
		} else {
			const values: any = {
				ID: id,
				Destination: baseUrl,
				Issuer: metadata.init.getEntityID(),
				EntityID: metadata.init.getEntityID(),
				IssueInstant: new Date().toISOString(),
				StatusCode: StatusCode.Success,
				InResponseTo: get(requestInfo, 'extract.logoutRequest.id', ''),
			};
			rawSaml = libsaml.replaceTagsByValue(libsaml.defaultLogoutResponseTemplate.context, values);
		}
		return {
			id,
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
