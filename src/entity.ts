/**
 * @file entity.ts
 * @author tngan
 * @desc  An abstraction for identity provider and service provider.
 */
import { v4 as uuid } from 'uuid';
import postBinding from './binding-post';
import redirectBinding from './binding-redirect';
import { flow } from './flow';
import metadataIdp, { MetadataIdp } from './metadata-idp';
import metadataSp, { MetadataSp } from './metadata-sp';
import type { EntitySetting, MetadataIdpConstructorOptions, MetadataSpConstructorOptions } from './types';
import { algorithms, BindingNamespace, messageConfigurations, ParserType } from './urn';
import { isNonEmptyArray, isString } from './utility';

const dataEncryptionAlgorithm = algorithms.encryption.data;
const keyEncryptionAlgorithm = algorithms.encryption.key;
const signatureAlgorithms = algorithms.signature;
const messageSigningOrders = messageConfigurations.signingOrder;

const defaultEntitySetting = {
	wantLogoutResponseSigned: false,
	messageSigningOrder: messageSigningOrders.SIGN_THEN_ENCRYPT,
	wantLogoutRequestSigned: false,
	allowCreate: false,
	isAssertionEncrypted: false,
	requestSignatureAlgorithm: signatureAlgorithms.RSA_SHA256,
	dataEncryptionAlgorithm: dataEncryptionAlgorithm.AES_256,
	keyEncryptionAlgorithm: keyEncryptionAlgorithm.RSA_OAEP_MGF1P,
	generateID: (): string => `_${uuid()}`,
	relayState: '',
} as const;

export interface ESamlHttpRequest {
	query?: any;
	body?: any;
	octetString?: string;
}

export interface BindingContext {
	context: string;
	id: string;
}

export interface PostBindingContext extends BindingContext {
	relayState?: string;
	entityEndpoint: string;
	type: 'SAMLRequest' | 'SAMLResponse';
}

export interface ParseResult {
	samlContent: string;
	extract: any;
	sigAlg: string;
}

export type EntityConstructorOptions = (MetadataIdpConstructorOptions | MetadataSpConstructorOptions) & {
	metadata?: string | Buffer;
};

export class Entity {
	entitySetting: EntitySetting;
	entityMeta: MetadataIdp | MetadataSp;

	/**
	 * @param entitySetting
	 * @param entityMeta is the entity metadata, deprecated after 2.0
	 */
	constructor(entitySetting: EntityConstructorOptions, public entityType: 'idp' | 'sp') {
		this.entitySetting = Object.assign({}, defaultEntitySetting, entitySetting);
		const metadata = entitySetting.metadata || entitySetting;
		switch (entityType) {
			case 'idp':
				this.entityMeta = metadataIdp(metadata);
				// setting with metadata has higher precedence
				this.entitySetting.wantAuthnRequestsSigned = this.entityMeta.isWantAuthnRequestsSigned();
				this.entitySetting.nameIDFormat = this.entityMeta.getNameIDFormat() || this.entitySetting.nameIDFormat;
				break;
			case 'sp':
				this.entityMeta = metadataSp(metadata);
				// setting with metadata has higher precedence
				this.entitySetting.authnRequestsSigned = this.entityMeta.isAuthnRequestSigned();
				this.entitySetting.wantAssertionsSigned = this.entityMeta.isWantAssertionsSigned();
				this.entitySetting.nameIDFormat = this.entityMeta.getNameIDFormat() || this.entitySetting.nameIDFormat;
				break;
			default:
				throw new Error('ERR_UNDEFINED_ENTITY_TYPE');
		}
	}
	/**
	 * @desc  Returns the setting of entity
	 * @return {object}
	 */
	generateID() {
		if (this.entitySetting.generateID) return this.entitySetting.generateID();
		return defaultEntitySetting.generateID();
	}
	/**
	 * @desc  Returns the setting of entity
	 * @return {object}
	 */
	getEntitySetting() {
		return this.entitySetting;
	}
	/**
	 * @desc  Returns the xml string of entity metadata
	 * @return {string}
	 */
	getMetadata(): string {
		return this.entityMeta.getMetadata();
	}

	/**
	 * @desc  Exports the entity metadata into specified folder
	 * @param  {string} exportFile indicates the file name
	 */
	exportMetadata(exportFile: string) {
		return this.entityMeta.exportMetadata(exportFile);
	}

	/** * @desc  Verify fields with the one specified in metadata
	 * @param  {string/[string]} field is a string or an array of string indicating the field value in SAML message
	 * @param  {string} metaField is a string indicating the same field specified in metadata
	 * @return {boolean} True/False
	 */
	verifyFields(field: string | string[], metaField: string): boolean {
		if (isString(field)) {
			return field === metaField;
		}
		if (isNonEmptyArray(field)) {
			let res = true;
			field.forEach((f) => {
				if (f !== metaField) {
					res = false;
					return;
				}
			});
			return res;
		}
		return false;
	}
	/** @desc   Generates the logout request for developers to design their own method
	 * @param  {ServiceProvider} sp     object of service provider
	 * @param  {string}   binding       protocol binding
	 * @param  {object}   user          current logged user (e.g. user)
	 * @param  {string} relayState      the URL to which to redirect the user when logout is complete
	 * @param  {function} customTagReplacement     used when developers have their own login response template
	 */
	createLogoutRequest(
		targetEntity: Entity,
		protocol: BindingNamespace,
		user: Record<string, any>,
		relayState = '',
		customTagReplacement?: (template: string) => BindingContext
	): BindingContext | PostBindingContext {
		if (protocol === BindingNamespace.Redirect) {
			return redirectBinding.logoutRequestRedirectURL(
				user,
				{
					init: this,
					target: targetEntity,
				},
				relayState,
				customTagReplacement
			);
		}
		if (protocol === BindingNamespace.Post) {
			const entityEndpoint = targetEntity.entityMeta.getSingleLogoutService(protocol);
			const context = postBinding.base64LogoutRequest(
				user,
				"/*[local-name(.)='LogoutRequest']",
				{ init: this, target: targetEntity },
				customTagReplacement
			);
			return {
				...context,
				relayState,
				entityEndpoint,
				type: 'SAMLRequest',
			};
		}
		// Will support artifact in the next release
		throw new Error('ERR_UNDEFINED_BINDING');
	}

	/**
	 * @desc  Generates the logout response for developers to design their own method
	 * @param  {IdentityProvider} idp               object of identity provider
	 * @param  {object|null} requestInfo            corresponding request, used to obtain the id
	 * @param  {string} relayState                  the URL to which to redirect the user when logout is complete.
	 * @param  {string} binding                     protocol binding
	 * @param  {function} customTagReplacement                 used when developers have their own login response template
	 */
	createLogoutResponse(
		target: Entity,
		requestInfo: Record<string, any> | null,
		protocol: BindingNamespace,
		relayState = '',
		customTagReplacement?: (template: string) => BindingContext
	): BindingContext | PostBindingContext {
		if (protocol === BindingNamespace.Redirect) {
			return redirectBinding.logoutResponseRedirectURL(
				requestInfo,
				{
					init: this,
					target,
				},
				relayState,
				customTagReplacement
			);
		}
		if (protocol === BindingNamespace.Post) {
			const context = postBinding.base64LogoutResponse(
				requestInfo,
				{
					init: this,
					target,
				},
				customTagReplacement
			);
			return {
				...context,
				relayState,
				entityEndpoint: target.entityMeta.getSingleLogoutService(protocol),
				type: 'SAMLResponse',
			};
		}
		throw new Error('ERR_CREATE_LOGOUT_RESPONSE_UNDEFINED_BINDING');
	}

	/**
	 * @desc   Validation of the parsed the URL parameters
	 * @param  {IdentityProvider} idp        object of identity provider
	 * @param  {BindingNamespace} protocol   protocol binding
	 * @param  {request}   req               request
	 * @return {Promise}
	 */
	parseLogoutRequest(from: Entity, protocol: BindingNamespace, request: ESamlHttpRequest) {
		return flow({
			from: from,
			self: this,
			type: 'logout',
			parserType: ParserType.LogoutRequest,
			checkSignature: this.entitySetting.wantLogoutRequestSigned,
			binding: protocol,
			request: request,
		});
	}
	/**
	 * @desc   Validation of the parsed the URL parameters
	 * @param  {object}           config     config for the parser
	 * @param  {BindingNamespace} protocol   protocol binding
	 * @param  {ESamlHttpRequest} req        request
	 * @return {Promise}
	 */
	parseLogoutResponse(from: Entity, protocol: BindingNamespace, request: ESamlHttpRequest) {
		return flow({
			from: from,
			self: this,
			type: 'logout',
			parserType: ParserType.LogoutResponse,
			checkSignature: this.entitySetting.wantLogoutResponseSigned,
			binding: protocol,
			request: request,
		});
	}
}
