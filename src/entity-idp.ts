/**
* @file entity-idp.ts
* @author tngan
* @desc  Declares the actions taken by identity provider
*/
import {
  wording,
} from './urn.js';
const binding = wording.binding



import Entity, { type ESamlHttpRequest } from './entity.js';
import {
  ServiceProviderConstructor as ServiceProvider,
  ServiceProviderMetadata,
  IdentityProviderMetadata,
  type IdentityProviderSettings
} from './types.js';
import libsaml from './libsaml.js';
import { namespace } from './urn.js';
import postBinding from './binding-post.js';
import redirectBinding from './binding-redirect.js';
import simpleSignBinding from './binding-simplesign.js';
import { flow, type FlowResult } from  './flow.js';
import { isString } from './utility.js';
import type  { BindingContext } from './entity.js';

/**
 * Identity provider can be configured using either metadata importing or idpSetting
 */
export default function(props: IdentityProviderSettings) {
  return new IdentityProvider(props);
}

/**
 * Identity provider can be configured using either metadata importing or idpSetting
 */
export class IdentityProvider extends Entity {

  declare entityMeta: IdentityProviderMetadata;

  constructor(idpSetting: IdentityProviderSettings) {
    const defaultIdpEntitySetting = {
      wantAuthnRequestsSigned: false,
      tagPrefix: {
        encryptedAssertion: 'saml',
      },
    };
    const entitySetting = Object.assign(defaultIdpEntitySetting, idpSetting);
    super(entitySetting, 'idp');
  }

  /**
   * @desc  Generates the login response for developers to design their own method
   * @param params
   */
  public async createLoginResponse(params:{
    sp: ServiceProvider;
    requestInfo: Record<string, any>;
    binding?: string;  // 可选参数，带默认值
    user: Record<string, any>;
    customTagReplacement?: (template: string) => BindingContext,
    encryptThenSign?: boolean,
    relayState?: string,
    context: Record<string, any>,
    AttributeStatement:[]
  }) {
const bindType = params?.binding ?? 'post';
    const {  sp,requestInfo ={}, user = {},customTagReplacement,encryptThenSign = false ,relayState='',AttributeStatement= [] } = params
    const protocol = namespace.binding[bindType];
    // can support post, redirect and post simple sign bindings for login response
    let context: any = null;
    switch (protocol) {
      case namespace.binding.post:
        context = await postBinding.base64LoginResponse(requestInfo, {
          idp: this,
          sp,
        }, user, customTagReplacement, encryptThenSign,AttributeStatement);
        break;

      case namespace.binding.simpleSign:
        context = await simpleSignBinding.base64LoginResponse( requestInfo, {
          idp: this, sp,
        }, user, relayState, customTagReplacement,AttributeStatement);
        break;

      case namespace.binding.redirect:
        return redirectBinding.loginResponseRedirectURL(requestInfo, {
          idp: this,
          sp,
        }, user, relayState, customTagReplacement,AttributeStatement);
      default:
        context = await postBinding.base64LoginResponse(requestInfo, {
          idp: this,
          sp,
        }, user, customTagReplacement, encryptThenSign,AttributeStatement);
 /*       throw new Error('ERR_CREATE_RESPONSE_UNDEFINED_BINDING');*/
    }

    return {
      ...context,
      relayState,
      entityEndpoint: (sp.entityMeta as ServiceProviderMetadata).getAssertionConsumerService(bindType ?? 'post') as string,
      type: 'SAMLResponse'
    };
  }

  /**
   * Validation of the parsed URL parameters
   * @param sp ServiceProvider instance
   * @param binding Protocol binding
   * @param req RequesmessageSigningOrderst
   */
  parseLoginRequest(sp: ServiceProvider, binding: string, req: ESamlHttpRequest) {
    const self = this;
    return flow({
      from: sp,
      self: self,
      checkSignature: self.entityMeta.isWantAuthnRequestsSigned(),
      parserType: 'SAMLRequest',
      type: 'login',
      binding: binding,
      request: req
    });
  }
}
