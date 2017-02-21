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
import * as _ from 'lodash';

const bindDict = wording.binding;
const xmlTag = tags.xmlTag;
const metaWord = wording.metadata;
//Why not an import?
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
    const entitySetting = _.assign({ wantAuthnRequestsSigned: false }, idpSetting);
    super(entitySetting, 'idp');
  }

  /**
  * @desc  Generates the login response for developers to design their own method
  * @param  {ServiceProvider}   sp               object of service provider
  * @param  {object}   requestInfo               corresponding request, used to obtain the id
  * @param  {string}   binding                   protocol binding
  * @param  {object}   user                      current logged user (e.g. req.user)
  * @param  {function} rcallback                 used when developers have their own login response template
  */
   //It's not actually sending anything, so I renamed to 'create'
   //What does the 'r' in 'rcallback' stand for? Maybe rename to be more clear?
  public async createLoginResponse(sp, requestInfo, binding, user, rcallback) {
    const protocol = namespace.binding[binding] || namespace.binding.redirect;
    if (protocol == namespace.binding.post) {
      const res = await postBinding.base64LoginResponse(requestInfo, libsaml.createXPath('Assertion'), {
        idp: this,
        sp: sp
      }, user, rcallback);

      // xmlenc is using async process
      return {
        actionValue: res,
        entityEndpoint: sp.entityMeta.getAssertionConsumerService(binding),
        actionType: 'SAMLResponse'
      };

    } else {
      // Will support arifact in the next release
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
      actionType: 'login'
    }, binding, req, sp.entityMeta);
  };
}
