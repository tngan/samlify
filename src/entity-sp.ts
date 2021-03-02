/**
 * @file entity-sp.ts
 * @author tngan
 * @desc  Declares the actions taken by service provider
 */
import type { BindingContext, ESamlHttpRequest, PostBindingContext } from './binding';
import postBinding from './binding-post';
import redirectBinding from './binding-redirect';
import { Entity, EntitySettings } from './entity';
import type { IdentityProvider } from './entity-idp';
import { SamlifyError, SamlifyErrorCode } from './error';
import { flow, FlowResult } from './flow';
import type { CustomTagReplacement, SAMLDocumentTemplate } from './libsaml';
import type { SSOService } from './metadata';
import { metadataSp, MetadataSp } from './metadata-sp';
import { BindingNamespace, ParserType } from './urn';

export interface ServiceProviderSettings extends EntitySettings {
	authnRequestsSigned?: boolean;
	wantAssertionsSigned?: boolean;
	wantMessageSigned?: boolean;
	assertionConsumerService?: SSOService[];

	/** template of login request */
	loginRequestTemplate?: SAMLDocumentTemplate;

	allowCreate?: boolean;
	// will be deprecated soon
	relayState?: string;
}

export interface ParsedLoginResponse {
	attributes?: Record<string, string>;
	audience?: string;
	conditions?: { notBefore: string; notOnOrAfter: string };
	issuer?: string;
	nameID?: string;
	response?: { id?: string; issueInstant?: string; destination?: string; inResponseTo?: string };
	sessionIndex?: { authnInstant?: string; sessionNotOnOrAfter?: string; sessionIndex?: string };
}

/*
 * @desc interface function
 */
export function serviceProvider(props: ServiceProviderSettings) {
	return new ServiceProvider(props);
}

/**
 * @desc Service provider can be configured using either metadata importing or spSetting
 * @param  {object} spSettingimport { FlowResult } from '../types/src/flow.d';
 */
export class ServiceProvider extends Entity<ServiceProviderSettings, MetadataSp> {
	/**
	 * @desc  Inherited from Entity
	 * @param {object} spSettings settings of service provider
	 */
	constructor(spSettings: ServiceProviderSettings) {
		const entitySettings = Object.assign(
			{
				authnRequestsSigned: false,
				wantAssertionsSigned: false,
				wantMessageSigned: false,
			},
			spSettings
		);
		const entityMeta = metadataSp(entitySettings.metadata || entitySettings);
		// setting with metadata has higher precedence
		entitySettings.authnRequestsSigned = entityMeta.isAuthnRequestSigned();
		entitySettings.wantAssertionsSigned = entityMeta.isWantAssertionsSigned();
		super(entitySettings, entityMeta);
	}

	/**
	 * @desc  Generates the login request for developers to design their own method
	 * @param  {IdentityProvider} idp               object of identity provider
	 * @param  {string}   binding                   protocol binding
	 * @param  {function} customTagReplacement     used when developers have their own login response template
	 */
	public createLoginRequest(
		idp: IdentityProvider,
		protocol = BindingNamespace.Redirect,
		customTagReplacement?: CustomTagReplacement
	): BindingContext | PostBindingContext {
		const idpMeta = idp.getEntityMeta();
		if (this.entityMeta.isAuthnRequestSigned() !== idpMeta.isWantAuthnRequestsSigned()) {
			throw new SamlifyError(SamlifyErrorCode.MetadataConflictRequestSignedFlag);
		}

		if (protocol === BindingNamespace.Redirect) {
			return redirectBinding.loginRequestRedirectURL({ idp, sp: this }, customTagReplacement);
		}

		if (protocol === BindingNamespace.Post) {
			const context = postBinding.base64LoginRequest(
				"/*[local-name(.)='AuthnRequest']",
				{ idp, sp: this },
				customTagReplacement
			);
			return {
				...context,
				relayState: this.entitySettings.relayState,
				entityEndpoint: idpMeta.getSingleSignOnService(protocol),
				type: 'SAMLRequest',
			};
		}
		// Will support artifact in the next release
		throw new SamlifyError(SamlifyErrorCode.UnsupportedBinding);
	}

	/**
	 * @desc   Validation of the parsed the URL parameters
	 * @param  {IdentityProvider} idp      object of identity provider
	 * @param  {BindingNamespace} protocol protocol binding
	 * @param  {request}          req      request
	 */
	public parseLoginResponse(
		idp: IdentityProvider,
		protocol: BindingNamespace,
		request: ESamlHttpRequest
	): Promise<FlowResult<ParsedLoginResponse>> {
		return flow({
			from: idp,
			self: this,
			checkSignature: true, // saml response must have signature
			parserType: ParserType.SAMLResponse,
			type: 'login',
			binding: protocol,
			request: request,
		}) as Promise<FlowResult<ParsedLoginResponse>>;
	}
}
