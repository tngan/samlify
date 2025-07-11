/**
 * @file entity-sp.ts
 * @author tngan
 * @desc  Declares the actions taken by service provider
 */
import Entity, {} from './entity.js';
import Artifact from './binding-artifact.js'
import * as crypto from "node:crypto";
import type {
  BindingContext,
  PostBindingContext,
  ESamlHttpRequest,
  SimpleSignBindingContext,
} from './entity.js';
import {
  IdentityProviderConstructor as IdentityProvider,
  ServiceProviderMetadata,
  type ServiceProviderSettings,
} from './types.js';
import {namespace} from './urn.js';
import redirectBinding from './binding-redirect.js';
import postBinding from './binding-post.js';
import simpleSignBinding from './binding-simplesign.js';
import artifactSignBinding from './binding-artifact.js';
import {flow, type FlowResult} from './flow.js';

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
  declare entityMeta: ServiceProviderMetadata;

  /**
   * @desc  Inherited from Entity
   * @param {object} spSetting    setting of service provider
   */
  constructor(spSetting: ServiceProviderSettings) {
    const entitySetting = Object.assign({
      authnRequestsSigned: false,
      wantAssertionsSigned: false,
      wantMessageSigned: false,
    }, spSetting);
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
      binding = 'redirect',
      customTagReplacement?: (template: string) => BindingContext,
  ): BindingContext | PostBindingContext | SimpleSignBindingContext {
    const nsBinding = namespace.binding;
    const protocol = nsBinding[binding];
    if (this.entityMeta.isAuthnRequestSigned() !== idp.entityMeta.isWantAuthnRequestsSigned()) {
      throw new Error('ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG');
    }

    let context: any = null;
    switch (protocol) {
      case nsBinding.redirect:
        return redirectBinding.loginRequestRedirectURL({idp, sp: this}, customTagReplacement);
      case nsBinding.post:
        context = postBinding.base64LoginRequest("/*[local-name(.)='AuthnRequest']", {
          idp,
          sp: this
        }, customTagReplacement);
        break;
      case nsBinding.simpleSign:
        // Object context = {id, context, signature, sigAlg}
        context = simpleSignBinding.base64LoginRequest({idp, sp: this}, customTagReplacement);
        break;
      default:
        // Will support artifact in the next release
        throw new Error('ERR_SP_LOGIN_REQUEST_UNDEFINED_BINDING');
    }

    return {
      ...context,
      relayState: this.entitySetting.relayState,
      entityEndpoint: idp.entityMeta.getSingleSignOnService(binding) as string,
      type: 'SAMLRequest',
    };
  }

  public async createLoginSoapRequest(
      idp: IdentityProvider,
      binding = 'artifact',
      config:{
        customTagReplacement?: (template: string) => BindingContext,
        inResponseTo?:string,
        relayState?:string,
      }
  ):Promise<any>{
    const nsBinding = namespace.binding;
    const protocol = nsBinding[binding];
    if (this.entityMeta.isAuthnRequestSigned() !== idp.entityMeta.isWantAuthnRequestsSigned()) {
      throw new Error('ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG');
    }

    let context: any = null;
    context =  await artifactSignBinding.soapLoginRequest("/*[local-name(.)='AuthnRequest']", {
      idp,
      sp: this,
      inResponse:config?.inResponseTo,
      relayState:config?.relayState,
    }, config?.customTagReplacement);

    return context;
  }





  /**
   * @desc   Validation of the parsed the URL parameters
   * @param  {IdentityProvider}   idp             object of identity provider
   * @param  {string}   binding                   protocol binding
   * @param  {request}   req                      request
   */
  public parseLoginResponse(idp, binding, request: ESamlHttpRequest) {
    const self = this;
    return flow({
      from: idp,
      self: self,
      checkSignature: true, // saml response must have signature
      parserType: 'SAMLResponse',
      type: 'login',
      binding: binding,
      request: request
    });
  }


  /**
   * @desc   request SamlResponse by Arc id
   * @param  {IdentityProvider}   idp             object of identity provider
   * @param  {string}   binding                   protocol binding
   * @param  {request}   req                      request
   */
  public parseLoginRequestResolve(idp,xml) {
    const self = this;
    return Artifact.parseLoginRequestResolve({
      idp: idp,
      sp: self,
      xml:xml
    });
  }
  public parseLoginResponseResolve(idp, xml, request: ESamlHttpRequest) {
    const self = this;
    return Artifact.parseLoginResponseResolve({
      idp: idp,
      sp: self,
      xml:xml
    });
  }

}
