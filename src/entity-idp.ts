/**
* @file entity-idp.ts
* @author tngan
* @desc  Declares the actions taken by identity provider
*/
import Entity from './entity';
import libsaml from './libsaml';
import utility from './utility';
import { wording, namespace, tags } from './urn';
import redirectBinding from './binding-redirect';
import postBinding from './binding-post';
import { isString } from 'lodash';

const bindDict = wording.binding;
const xmlTag = tags.xmlTag;
const metaWord = wording.metadata;
const xml = require('xml');

/*
 * @desc interface function
 */
export default function (props) {
  return new IdentityProvider(props);
}

export class IdentityProvider extends Entity {
  // local variables
  // idpSetting is an object with properties as follow:
  // -------------------------------------------------
  // {string}       requestSignatureAlgorithm     signature algorithm
  // {string}       loginResponseTemplate         template of login response
  // {string}       logoutRequestTemplate         template of logout request
  // {function}     generateID is the customized function used for generating request ID
  //
  // if no metadata is provided, idpSetting includes
  // {string}       entityID
  // {string}       privateKey
  // {string}       privateKeyPass
  // {string}       signingCert
  // {string}       encryptCert (todo)
  // {[string]}     nameIDFormat
  // {[object]}     singleSignOnService
  // {[object]}     singleLogoutService
  // {boolean}      wantLogoutRequestSigned
  // {boolean}      wantAuthnRequestsSigned
  // {boolean}      wantLogoutResponseSigned
  //
  /**
  * @desc  Identity prvider can be configured using either metadata importing or idpSetting
  * @param  {object} idpSetting
  * @param  {string} meta
  */
  constructor(idpSetting) {
    let entitySetting = Object.assign({ wantAuthnRequestsSigned: false }, idpSetting);
    // build attribute part
    if (idpSetting.loginResponseTemplate) {
      if(isString(idpSetting.loginResponseTemplate.context) && Array.isArray(idpSetting.loginResponseTemplate.attributes)) {
        let replacement = {
          AttributeStatement: libsaml.attributeStatementBuilder(idpSetting.loginResponseTemplate.attributes)
        };
        entitySetting.loginResponseTemplate = libsaml.replaceTagsByValue(entitySetting.loginResponseTemplate.context, replacement);
      } else {
        console.warn('Invalid login response template');
      }
    }
    super(entitySetting, 'idp');
  }
  /**
  * @desc  Generates the login response for developers to design their own method
  * @param  {ServiceProvider}   sp               object of service provider
  * @param  {object}   requestInfo               corresponding request, used to obtain the id
  * @param  {string}   binding                   protocol binding
  * @param  {object}   user                      current logged user (e.g. req.user)
  * @param  {function} customTagReplacement                 used when developers have their own login response template
  */
  public async createLoginResponse(sp, requestInfo, binding, user, customTagReplacement) {
    const protocol = namespace.binding[binding] || namespace.binding.redirect;
    if (protocol == namespace.binding.post) {
      const context = await postBinding.base64LoginResponse(requestInfo, {
        idp: this,
        sp: sp
      }, user, customTagReplacement);
      // xmlenc is using async process
      return {
        ...context,
        entityEndpoint: sp.entityMeta.getAssertionConsumerService(binding),
        type: 'SAMLResponse'
      };

    } else {
      // Will support artifact in the next release
      throw new Error('This binding is not support');
    }
  }
  /**
  * @desc   Validation of the parsed URL parameters
  * @param  {ServiceProvider}   sp               object of service provider
  * @param  {string}   binding                   protocol binding
  * @param  {request}   req                      request
  */
  public parseLoginRequest(sp, binding, req) {
    return this.abstractBindingParser({
      parserFormat: ['AuthnContextClassRef', 'Issuer', {
        localName: 'Signature',
        extractEntireBody: true
      }, {
          localName: 'AuthnRequest',
          attributes: ['ID']
        }, {
          localName: 'NameIDPolicy',
          attributes: ['Format', 'AllowCreate']
        }],
      checkSignature: this.entityMeta.isWantAuthnRequestsSigned(),
      parserType: 'SAMLRequest',
      type: 'login'
    }, binding, req, sp.entityMeta);
  };
}
