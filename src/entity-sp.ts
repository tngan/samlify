/**
 * @file entity-sp.ts
 * @author tngan
 * @desc  Declares the actions taken by service provider
 */
import postBinding from './binding-post';
import redirectBinding from './binding-redirect';
import { BindingContext, Entity, ESamlHttpRequest, PostBindingContext } from './entity';
import type { IdentityProvider } from './entity-idp';
import { SamlifyError, SamlifyErrorCode } from './error';
import { flow } from './flow';
import type { CustomTagReplacement } from './libsaml';
import type { ServiceProviderMetadata, ServiceProviderSettings } from './types';
import { BindingNamespace, ParserType } from './urn';

/*
 * @desc interface function
 */
export default function (props: ServiceProviderSettings) {
	return new ServiceProvider(props);
}

/**
* @desc Service provider can be configured using either metadata importing or spSetting
* @param  {object} spSettingimport { FlowResult } from '../types/src/flow.d';

*/
export class ServiceProvider extends Entity {
	entityMeta!: ServiceProviderMetadata;

	/**
	 * @desc  Inherited from Entity
	 * @param {object} spSetting    setting of service provider
	 */
	constructor(spSetting: ServiceProviderSettings) {
		const entitySetting = Object.assign(
			{
				authnRequestsSigned: false,
				wantAssertionsSigned: false,
				wantMessageSigned: false,
			},
			spSetting
		);
		super(entitySetting, 'sp');
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
		if (this.entityMeta.isAuthnRequestSigned() !== idp.entityMeta.isWantAuthnRequestsSigned()) {
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
				relayState: this.entitySetting.relayState,
				entityEndpoint: idp.entityMeta.getSingleSignOnService(protocol),
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
	public parseLoginResponse(idp: IdentityProvider, protocol: BindingNamespace, request: ESamlHttpRequest) {
		return flow({
			from: idp,
			self: this,
			checkSignature: true, // saml response must have signature
			parserType: ParserType.SAMLResponse,
			type: 'login',
			binding: protocol,
			request: request,
		});
	}
}
