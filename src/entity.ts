/**
* @file entity.ts
* @author tngan
* @desc  An abstraction for identity provider and service provider.
*/
import { base64Decode, isNonEmptyArray, inflateString } from './utility';
import { namespace, wording, algorithms } from './urn';
import * as uuid from 'uuid';
import libsaml from './libsaml';
import Metadata from './metadata';
import IdpMetadata from './metadata-idp';
import SpMetadata from './metadata-sp';
import redirectBinding from './binding-redirect';
import postBinding from './binding-post';
import { isString, isUndefined, isArray } from 'lodash';

const dataEncryptionAlgorithm = algorithms.encryption.data;
const keyEncryptionAlgorithm = algorithms.encryption.key;
const bindDict = wording.binding;
const signatureAlgorithms = algorithms.signature;
const nsBinding = namespace.binding;

const defaultEntitySetting = {
  wantLogoutResponseSigned: false,
  wantLogoutRequestSigned: false,
  allowCreate: false,
  isAssertionEncrypted: false,
  requestSignatureAlgorithm: signatureAlgorithms.RSA_SHA1,
  dataEncryptionAlgorithm: dataEncryptionAlgorithm.AES_256,
  keyEncryptionAlgorithm: keyEncryptionAlgorithm.RSA_1_5,
  generateID: (): string => ('_' + uuid.v4()),
  relayState: ''
};

export interface BindingContext {
  context: string;
  id: string;
}

export interface PostRequestInfo extends BindingContext {
  relayState: string;
  type: string;
  entityEndpoint: string;
}

export interface PostResponseInfo extends BindingContext {
  entityEndpoint: string;
  type: string;
}

export default class Entity {

  entitySetting: any;
  entityType: string;
  entityMeta: any;
  /**
  * @desc  Constructor
  * @param {object} entitySetting
  * @param {object} entityMetaClass determine whether the entity is IdentityProvider or ServiceProvider
  * @param {string} entityMeta is the entity metadata, deprecated after 2.0
  */
  constructor(entitySetting, entityType) {
    this.entitySetting = Object.assign({}, defaultEntitySetting, entitySetting);
    const metadata = entitySetting.metadata ? entitySetting.metadata : entitySetting;
    switch (entityType) {
      case 'idp':
        this.entityMeta = IdpMetadata(metadata);
        this.entitySetting.wantAuthnRequestsSigned = this.entityMeta.isWantAuthnRequestsSigned();
        break;
      case 'sp':
        this.entityMeta = SpMetadata(metadata);
        this.entitySetting.authnRequestsSigned = this.entityMeta.isAuthnRequestSigned();
        this.entitySetting.wantAssertionsSigned = this.entityMeta.isWantAssertionsSigned();
        break;
      default:
        throw new Error('undefined entity type');
    }
  }
  /**
  * @desc  getEntityID
  * @return {string} ID of entitiy
  */
  getEntityId(): string {
    return this.entityMeta.getEntityId();
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
  };
  /**
  * @desc  Exports the entity metadata into specified folder
  * @param  {string} exportFile indicates the file name
  */
  exportMetadata(exportFile: string) {
    return this.entityMeta.exportMetadata(exportFile);
  };
  /** * @desc  Verify fields with the one specified in metadata
  * @param  {string/[string]} field is a string or an array of string indicating the field value in SAML message
  * @param  {string} metaField is a string indicating the same field specified in metadata
  * @return {boolean} True/False
  */
  verifyFields(field: string | Array<string>, metaField: string): boolean {
    if (isString(field)) {
      return field === metaField;
    }
    if (isNonEmptyArray(field)) {
      let res = true;
      field.forEach(f => {
        if (f != metaField) {
          res = false;
          return;
        }
      });
      return res;
    }
    return false;
  };
  /**
  * @desc  Verify time stamp
  * @param  {date} notBefore
  * @param  {date} notOnOrAfter
  * @return {boolean}
  */
  verifyTime(notBefore: Date, notOnOrAfter: Date): boolean {
    const now = new Date();
    if (isUndefined(notBefore) && isUndefined(notOnOrAfter)) {
      return true; // throw exception todo
    }
    if (!isUndefined(notBefore) && isUndefined(notOnOrAfter)) {
      return +notBefore <= +now;
    }
    if (isUndefined(notBefore) && !isUndefined(notOnOrAfter)) {
      return now < notOnOrAfter;
    }
    return +notBefore <= +now && now < notOnOrAfter;
  };
  /**
  * @desc  Validate and parse the request/response with different bindings
  * @param  {object} opts is the options for abstraction
  * @param  {string} binding is the protocol bindings (e.g. redirect, post)
  * @param  {request} req is the http request
  * @param  {Metadata} targetEntityMetadata either IDP metadata or SP metadata
  * @return {ParseResult} parseResult
  */
  async abstractBindingParser(opts, binding: string, req, targetEntityMetadata) {
    const here = this;
    const entityMeta: any = this.entityMeta;
    let options = opts || {};
    let parseResult = {};
    let supportBindings = [nsBinding.redirect, nsBinding.post];
    let { parserFormat: fields, parserType, type, from, checkSignature = true, decryptAssertion = false } = options;

    if (type === 'login') {
      if (entityMeta.getAssertionConsumerService) {
        let assertionConsumerService = entityMeta.getAssertionConsumerService(binding);
        if (!assertionConsumerService) {
          supportBindings = [];
        }
      } else if (entityMeta.getSingleSignOnService) {
        let singleSignOnService = entityMeta.getSingleSignOnService(binding);
        if (!singleSignOnService) {
          supportBindings = [];
        }
      }
    } else if (type == 'logout') {
      let singleLogoutServices = entityMeta.getSingleLogoutService(binding);
      if (!singleLogoutServices) {
        supportBindings = [];
      }
    } else {
      throw new Error('Invalid type in abstractBindingParser');
    }

    if (binding === bindDict.redirect && supportBindings.indexOf(nsBinding[binding]) !== -1) {
      let reqQuery: { SigAlg: string, Signature: string } = req.query;
      let samlContent = reqQuery[libsaml.getQueryParamByType(parserType)];

      if (samlContent === undefined) {
        throw new Error('Bad request');
      }
      let xmlString = inflateString(decodeURIComponent(samlContent));
      if (checkSignature) {
        let { SigAlg: sigAlg, Signature: signature } = reqQuery;
        if (signature && sigAlg) {
          if (libsaml.verifyMessageSignature(targetEntityMetadata, <string>req._parsedOriginalUrl.query.split('&Signature=')[0], new Buffer(decodeURIComponent(signature), 'base64'), sigAlg)) {
            parseResult = {
              samlContent: xmlString,
              sigAlg: decodeURIComponent(sigAlg),
              extract: libsaml.extractor(xmlString, fields)
            };
          } else {
            // Fail to verify message signature
            throw new Error('fail to verify message signature in request');
          }
        } else {
          // Missing signature or signature algorithm
          throw new Error('missing signature or signature algorithm');
        }
      } else {
        parseResult = {
          samlContent: xmlString,
          extract: libsaml.extractor(xmlString, fields)
        };
      }
      return parseResult;
    }

    if (binding == bindDict.post && supportBindings.indexOf(nsBinding[binding]) !== -1) {
      // make sure express.bodyParser() has been used
      let encodedRequest = req.body[libsaml.getQueryParamByType(parserType)];
      let decodedRequest = String(base64Decode(encodedRequest));
      let issuer = targetEntityMetadata.getEntityID();
      const res = await libsaml.decryptAssertion(parserType, here, from, decodedRequest);
      let parseResult = {
        samlContent: res,
        extract: libsaml.extractor(res, fields)
      };
      if (checkSignature) {
        // verify the signatures (for both assertion/message)
        // sigantures[0] is message signature
        // sigantures[1] is assertion signature
        [...parseResult.extract.signature].reverse().forEach(s => {
          if (!libsaml.verifySignature(res, parseResult.extract.signature, {
            cert: targetEntityMetadata,
            signatureAlgorithm: here.entitySetting.requestSignatureAlgorithm
          })) {
            throw new Error('incorrect signature');
          }
          // in order to get the raw xml
          // remove assertion signature because the assertion signature is later than the message signature
          res.replace(s, '');
        });
      }
      if (!here.verifyFields(parseResult.extract.issuer, issuer)) {
        throw new Error('incorrect issuer');
      }
      return parseResult;
    }
    // Will support artifact in the next release
    throw new Error('this binding is not support');
  };

  /** @desc   Generates the logout request for developers to design their own method
  * @param  {ServiceProvider} sp     object of service provider
  * @param  {string}   binding       protocol binding
  * @param  {object}   user          current logged user (e.g. req.user)
  * @param  {string} relayState      the URL to which to redirect the user when logout is complete
  * @param  {function} customTagReplacement     used when developers have their own login response template
  */
  createLogoutRequest(targetEntity, binding, user, relayState, customTagReplacement): BindingContext | PostRequestInfo {
    if (binding === wording.binding.redirect) {
      return redirectBinding.logoutRequestRedirectURL(user, {
        init: this,
        target: targetEntity
      }, customTagReplacement, relayState);
    }
    if (binding === wording.binding.post) {
      const entityEndpoint = targetEntity.entityMeta.getSingleLogoutService(binding);
      const context = postBinding.base64LogoutRequest(user, libsaml.createXPath('Issuer'), { init: this, target: targetEntity }, customTagReplacement);
      return {
        ...context,
        relayState,
        entityEndpoint,
        type: 'SAMLRequest'
      };
    }
    // Will support artifact in the next release
    throw new Error('The binding is not support');
  }
  /**
  * @desc  Generates the logout response for developers to design their own method
  * @param  {IdentityProvider} idp               object of identity provider
  * @param  {object} requestInfo                 corresponding request, used to obtain the id
  * @param  {string} relayState                  the URL to which to redirect the user when logout is complete.
  * @param  {string} binding                     protocol binding
  * @param  {function} customTagReplacement                 used when developers have their own login response template
  */
  createLogoutResponse(target, requestInfo, binding, relayState, customTagReplacement): BindingContext {
    binding = namespace.binding[binding] || namespace.binding.redirect;
    if (binding === namespace.binding.redirect) {
      return redirectBinding.logoutResponseRedirectURL(requestInfo, {
        init: this,
        target,
      }, relayState, customTagReplacement);
    }
    if (binding === namespace.binding.post) {
      const context = postBinding.base64LogoutResponse(requestInfo, {
          init: this,
          target,
        }, customTagReplacement)
      return {
        ...context,
        relayState,
        entityEndpoint: target.entityMeta.getSingleLogoutService(binding),
        type: 'SAMLResponse'
      };
    }
    throw new Error('This binding is not support');
  }
  /**
  * @desc   Validation of the parsed the URL parameters
  * @param  {IdentityProvider}   idp             object of identity provider
  * @param  {string}   binding                   protocol binding
  * @param  {request}   req                      request
  * @return {Promise}
  */
  parseLogoutRequest(targetEntity, binding, req) {
    return this.abstractBindingParser({
      parserFormat: ['NameID', 'Issuer', {
        localName: 'Signature',
        extractEntireBody: true
      }, {
          localName: 'LogoutRequest',
          attributes: ['ID', 'Destination']
        }],
      checkSignature: this.entitySetting.wantLogoutRequestSigned,
      parserType: 'LogoutRequest',
      type: 'logout'
    }, binding, req, targetEntity.entityMeta);
  };
  /**
  * @desc   Validation of the parsed the URL parameters
  * @param  {string}   binding                   protocol binding
  * @param  {request}   req                      request
  * @param  {ServiceProvider}   sp               object of service provider
  * @return {Promise}
  */
  parseLogoutResponse(targetEntity, binding, req) {
    return this.abstractBindingParser({
      parserFormat: [{
        localName: 'StatusCode',
        attributes: ['Value']
      }, 'Issuer', {
        localName: 'Signature',
        extractEntireBody: true
      }, {
        localName: 'LogoutResponse',
        attributes: ['ID', 'Destination', 'InResponseTo']
      }],
      checkSignature: this.entitySetting.wantLogoutResponseSigned,
      supportBindings: ['post'],
      parserType: 'LogoutResponse',
      type: 'logout'
    }, binding, req, targetEntity.entityMeta);
  }
}
