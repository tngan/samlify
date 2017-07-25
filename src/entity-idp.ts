/**
* @file entity-idp.ts
* @author tngan
* @desc  Declares the actions taken by identity provider
*/
import Entity, { ESamlHttpRequest } from './entity';

// This unfortunately creates a circular dependency that doesn't exist at run time
import { ServiceProvider, ServiceProviderMetadata, IdentityProviderMetadata } from './types';

import libsaml from './libsaml';
import utility from './utility';
import { wording, namespace, tags } from './urn';
import redirectBinding from './binding-redirect';
import postBinding from './binding-post';
import { isString } from 'lodash';
import * as xml from 'xml';

const bindDict = wording.binding;
const xmlTag = tags.xmlTag;
const metaWord = wording.metadata;

export interface IdentityProviderOptions {
  metadata?: string | Buffer;

  /** signature algorithm */
  requestSignatureAlgotithm?: string;

  /** template of login response */
  loginResponseTemplate?: { [key: string]: any };

  /** template of login response */
  logoutRequestTemplate?: { [key: string]: any };

  /** customized function used for generating request ID */
  generateID?: () => string;

  entityID?: string;
  privateKey?: string | Buffer;
  privateKeyPass?: string;
  signingCert?: string;
  encrpytCert?: string; /** todo */
  nameIDFormat?: string[];
  singleSignOnService?: Array<{ [key: string]: string }>;
  singleLogoutService?: Array<{ [key: string]: string }>;
  isAssertionEncrypted?: boolean;
  encPrivateKey?: string | Buffer;
  encPrivateKeyPass?: string;
  messageSigningOrder?: string;
  wantLogoutRequestSigned?: boolean;
  wantLogoutResponseSigned?: boolean;
  wantAuthnRequestsSigned?: boolean;
  wantLogoutRequestSignedResponseSigned?: boolean;
  tagPrefix?: { [key: string]: string };
}

/**
 * Identity prvider can be configured using either metadata importing or idpSetting
 */
export default function(props: IdentityProviderOptions) {
  return new IdentityProvider(props);
}

/**
 * Identity prvider can be configured using either metadata importing or idpSetting
 */
export class IdentityProvider extends Entity {
  entityMeta: IdentityProviderMetadata;

  constructor(idpSetting: IdentityProviderOptions) {
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
        const replacement = {
          AttributeStatement: libsaml.attributeStatementBuilder(idpSetting.loginResponseTemplate.attributes),
        };
        entitySetting.loginResponseTemplate = {
          ...entitySetting.loginResponseTemplate,
          context: libsaml.replaceTagsByValue(entitySetting.loginResponseTemplate.context, replacement),
        };
      } else {
        console.warn('Invalid login response template');
      }
    }
    super(entitySetting, 'idp');
  }

  /**
  * @desc  Generates the login response for developers to design their own method
  * @param  sp                        object of service provider
  * @param  requestInfo               corresponding request, used to obtain the id
  * @param  binding                   protocol binding
  * @param  user                      current logged user (e.g. req.user)
  * @param  customTagReplacement      used when developers have their own login response template
  * @param  encryptThenSign           whether or not to encrypt then sign first (if signing)
  */
  public async createLoginResponse(
    sp: ServiceProvider,
    requestInfo: { [key: string]: any },
    binding: string,
    user: { [key: string]: any },
    customTagReplacement?: (...args: any[]) => any,
    encryptThenSign?: boolean,
  ) {
    const protocol = namespace.binding[binding] || namespace.binding.redirect;
    if (protocol === namespace.binding.post) {
      const context = await postBinding.base64LoginResponse(requestInfo, {
        idp: this,
        sp,
      }, user, customTagReplacement, encryptThenSign);
      // xmlenc is using async process
      return {
        ...context,
        entityEndpoint: (sp.entityMeta as ServiceProviderMetadata).getAssertionConsumerService(binding),
        type: 'SAMLResponse',
      };
    }

    // Will support artifact in the next release
    throw new Error('this binding is not supported');
  }

  /**
   * Validation of the parsed URL parameters
   * @param sp ServiceProvider instance
   * @param binding Protocol binding
   * @param req Request
   */
  public parseLoginRequest(sp: ServiceProvider, binding: string, req: ESamlHttpRequest) {
    return this.genericParser({
      parserFormat: ['AuthnContextClassRef', 'Issuer', {
        localName: 'Signature',
        extractEntireBody: true,
      }, {
          localName: 'AuthnRequest',
          attributes: ['ID'],
        }, {
          localName: 'NameIDPolicy',
          attributes: ['Format', 'AllowCreate'],
        }],
      from: sp,
      checkSignature: this.entityMeta.isWantAuthnRequestsSigned(),
      parserType: 'SAMLRequest',
      type: 'login',
    }, binding, req);
  }
}
