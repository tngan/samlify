/**
* @file entity-idp.ts
* @author tngan
* @desc  Declares the actions taken by identity provider
*/
import {
  wording,
} from './urn.js';
const binding = wording.binding



import Entity, { ESamlHttpRequest } from './entity.js';
import {
  ServiceProviderConstructor as ServiceProvider,
  ServiceProviderMetadata,
  IdentityProviderMetadata,
  IdentityProviderSettings,
  CreateLoginResponseParams
} from './types.js';
import libsaml from './libsaml.js';
import { namespace } from './urn.js';
import postBinding from './binding-post.js';
import redirectBinding from './binding-redirect.js';
import simpleSignBinding from './binding-simplesign.js';
import { flow, FlowResult } from  './flow.js';
import { isString } from './utility.js';
import { BindingContext } from './entity.js';

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
    // build attribute part
    if (idpSetting.loginResponseTemplate) {
      if (isString(idpSetting.loginResponseTemplate.context) && Array.isArray(idpSetting.loginResponseTemplate.attributes)) {
        let attributeStatementTemplate;
        let attributeTemplate;
        if (!idpSetting.loginResponseTemplate.additionalTemplates || !idpSetting.loginResponseTemplate.additionalTemplates!.attributeStatementTemplate) {
          attributeStatementTemplate = libsaml.defaultAttributeStatementTemplate;
        } else {
          attributeStatementTemplate = idpSetting.loginResponseTemplate.additionalTemplates!.attributeStatementTemplate!;
        }
        if (!idpSetting.loginResponseTemplate.additionalTemplates || !idpSetting.loginResponseTemplate.additionalTemplates!.attributeTemplate) {
          attributeTemplate = libsaml.defaultAttributeTemplate;
        } else {
          attributeTemplate = idpSetting.loginResponseTemplate.additionalTemplates!.attributeTemplate!;
        }
        const replacement = {
          AttributeStatement: libsaml.attributeStatementBuilder(idpSetting.loginResponseTemplate.attributes, attributeTemplate, attributeStatementTemplate),
        };
        entitySetting.loginResponseTemplate = {
          ...entitySetting.loginResponseTemplate,
          context: libsaml.replaceTagsByValue(entitySetting.loginResponseTemplate!.context, replacement),
        };
      } else {
        console.warn('Invalid login response template');
      }
    }
    super(entitySetting, 'idp');
  }

  /**
   * @desc  Generates the login response for developers to design their own method
   * @param params
   */
  public async createLoginResponse(params:CreateLoginResponseParams) {
const bindType = params?.binding ?? 'post';
    const {  sp,requestInfo ={}, user = {},customTagReplacement,encryptThenSign = false ,relayState=''} = params
    const protocol = namespace.binding[bindType];
    // can support post, redirect and post simple sign bindings for login response
    let context: any = null;
    switch (protocol) {
      case namespace.binding.post:
        context = await postBinding.base64LoginResponse(requestInfo, {
          idp: this,
          sp,
        }, user, customTagReplacement, encryptThenSign);
        break;

      case namespace.binding.simpleSign:
        context = await simpleSignBinding.base64LoginResponse( requestInfo, {
          idp: this, sp,
        }, user, relayState, customTagReplacement);
        break;

      case namespace.binding.redirect:
        return redirectBinding.loginResponseRedirectURL(requestInfo, {
          idp: this,
          sp,
        }, user, relayState, customTagReplacement);
      default:
        context = await postBinding.base64LoginResponse(requestInfo, {
          idp: this,
          sp,
        }, user, customTagReplacement, encryptThenSign);
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
