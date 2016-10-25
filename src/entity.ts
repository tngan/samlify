/**
* @file entity.ts
* @author tngan
* @desc  An abstraction for identity provider and service provider.
*
* v2.0
* v1.1  SS-1.1
*/

import utility from './utility';
import { namespace, wording, algorithms } from './urn';
import * as uuid from 'node-uuid';
import libsaml from './libsaml';
import { EntityMeta } from './metadata';

const dataEncryptionAlgorithm = algorithms.encryption.data; // SS1.1
const keyEncryptionAlgorithm = algorithms.encryption.key; // SS1.1
const bindDict = wording.binding;
const signatureAlgorithms = algorithms.signature;
const nsBinding = namespace.binding;

var RedirectBinding = require('./RedirectBinding');
var PostBinding = require('./PostBinding');

export class EntitySetting {
  wantLogoutResponseSigned: boolean;
  wantLogoutRequestSigned: boolean;
  allowCreate: boolean;
  isAssertionEncrypted: boolean;
  requestSignatureAlgorithm: string;
  dataEncryptionAlgorithm: string;
  keyEncryptionAlgorithm: string;
  generateID: () => string;

  constructor (obj) {
    this.wantLogoutResponseSigned = !!obj.wantLogoutResponseSigned;
    this.wantLogoutResponseSigned = !!obj.wantLogoutRequestSigned;
    this.allowCreate = !!obj.allowCreate;
    this.isAssertionEncrypted = !!obj.isAssertionEncrypted;
    this.requestSignatureAlgorithm = obj.requestSignatureAlgorithm || signatureAlgorithms.RSA_SHA1;
    this.dataEncryptionAlgorithm = obj.dataEncryptionAlgorithm || dataEncryptionAlgorithm.AES_256;
    this.keyEncryptionAlgorithm = obj.keyEncryptionAlgorithm || keyEncryptionAlgorithm.RSA_1_5;
    this.generateID = obj.generateID || ((): string => uuid.v4());
  }
}

class Entity {

  entitySetting: EntitySetting;
  entityType: string;
  entityMeta: EntityMeta;
  /**
  * @desc  Constructor
  * @param {object} entitySetting
  * @param {object} entityMetaClass determine whether the entity is IdentityProvider or ServiceProvider
  * @param {string} entityMeta is the entity metafile path
  */
  constructor (entitySetting, entityType, entityMeta) {
    this.entitySetting = new EntitySetting(entitySetting);
    if (!['idp', 'sp'].indexOf(entityType)) {
      throw new Error('undefined entity type');
    }
    this.entityMeta = require('./' + entityType)(entityMeta !== undefined ? entityMeta: entitySetting);
  }
  /**
  * @desc  getEntityID
  * @return {string} ID of entitiy
  */
  getEntityId (): string {
    return this.entityMeta.getEntityId();
  }
  /**
  * @desc  Returns the setting of entity
  * @return {object}
  */
  getEntitySetting (): EntitySetting {
    return this.entitySetting;
  }
  /**
  * @desc  Returns the xml string of entity metadata
  * @return {string}
  */
  getMetadata (): string {
    return this.entityMeta.getMetadata();
  };
  /**
  * @desc  Exports the entity metadata into specified folder
  * @param  {string} exportFile indicates the file name
  */
  exportMetadata (exportFile: string) {
    return this.entityMeta.exportMetadata(exportFile);
  };
  /** * @desc  Verify fields with the one specified in metadata
  * @param  {string/[string]} field is a string or an array of string indicating the field value in SAML message
  * @param  {string} metaField is a string indicating the same field specified in metadata
  * @return {boolean} True/False
  */
  verifyFields (field: string | Array<string>, metaField: string): boolean {
    if (typeof field === 'string') {
      return field === metaField;
    }
    if (field && field.length > 0) {
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
  verifyTime (notBefore: Date, notOnOrAfter: Date): boolean {
    const now = new Date();
    if (notBefore === undefined && notOnOrAfter === undefined) {
      return true; // throw exception todo
    }
    if (notBefore !== undefined && notOnOrAfter === undefined) {
      return +new Date(notBefore) <= +now;
    }
    if (notBefore === undefined && notOnOrAfter !== undefined) {
      return now < new Date(notOnOrAfter);
    }
    return +new Date(notBefore) <= +now && now < new Date(notOnOrAfter);
  };
  /**
  * @desc  Validate and parse the request/response with different bindings
  * @param  {object} opts is the options for abstraction
  * @param  {string} binding is the protocol bindings (e.g. redirect, post)
  * @param  {request} req is the http request
  * @param  {Metadata} targetEntityMetadata either IDP metadata or SP metadata
  * @param  {function} parseCallback is the callback function with extracted parameter
  * @return {function} parseCallback
  */
  abstractBindingParser (opts, binding: string, req, targetEntityMetadata, parseCallback) {
    const here = this; //SS-1.1 (refractor later on)
    const entityMeta = this.entityMeta;
    let options = opts || {};
    let parseResult = {};
    let supportBindings = [nsBinding.redirect, nsBinding.post];
    let { parserFormat: fields, parserType, actionType, from, checkSignature = true, decryptAssertion = true } = options;

    if (actionType === 'login') {
      if (entityMeta.getAssertionConsumerService) {
        let assertionConsumerService = entityMeta.getAssertionConsumerService();
        if (assertionConsumerService !== undefined) {
          supportBindings =  entityMeta.getSupportBindings(typeof assertionConsumerService === 'string' ? [assertionConsumerService] : assertionConsumerService);
        }
      } else if (entityMeta.getSingleSignOnService) {
        let singleSignOnService = entityMeta.getSingleSignOnService();
        if (singleSignOnService !== undefined) {
          supportBindings =  entityMeta.getSupportBindings(typeof singleSignOnService === 'string' ? [singleSignOnService] : singleSignOnService);
        }
      }
    } else if (actionType == 'logout') {
      let singleLogoutServices = entityMeta.getSingleLogoutService();
      if (singleLogoutServices !== undefined) {
        supportBindings =  entityMeta.getSupportBindings(typeof singleLogoutServices === 'string' ? [singleLogoutServices] : singleLogoutServices);
      }
    }

    if (binding === bindDict.redirect && supportBindings.indexOf(nsBinding[binding]) !== -1) {
      let reqQuery: { sigAlg: string, signature: string } = req.query;
      let samlContent = reqQuery[parserType];

      if (samlContent === undefined) {
        throw new Error('Bad request');
      }
      let xmlString = utility.inflateString(decodeURIComponent(samlContent));
      if (checkSignature) {
        let { sigAlg, signature } = reqQuery;
        if (signature && sigAlg) {
          // add sigAlg to verify message (SS-1.1)
          if (libsaml.verifyMessageSignature(targetEntityMetadata, <string>req._parsedOriginalUrl.query.split('&Signature=')[0], new Buffer(decodeURIComponent(signature), 'base64'), sigAlg)) {
            parseResult = {
              samlContent: xmlString,
              sigAlg: decodeURIComponent(sigAlg),
              extract: libsaml.extractor(xmlString, fields)
            };
          } else {
            // Fail to verify message signature
            throw new Error('fail to verify message signature');
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
      return parseCallback(parseResult);
    }
    if (binding == bindDict.post && supportBindings.indexOf(nsBinding[binding]) !== -1) {
      // make sure express.bodyParser() has been used
      let encodedRequest = req.body[parserType];
      let decodedRequest = utility.base64Decode(encodedRequest);
      let issuer = targetEntityMetadata.getEntityID();
      //SS-1.1
      libsaml.decryptAssertion(parserType, here, from, decodedRequest, function(res) {
        let parseResult = {
          samlContent: res,
          extract: libsaml.extractor(res, fields)
        };
        if (checkSignature) {
          // verify the signature
          if (!libsaml.verifySignature(res, parseResult.extract.signature, {
            cert:targetEntityMetadata,
            signatureAlgorithm: here.entitySetting.requestSignatureAlgorithm
          })) {
            throw new Error('incorrect signature');
          }
        }
        if (!here.verifyFields(parseResult.extract.issuer, issuer)) {
          throw new Error('incorrect issuer');
        }
        return parseCallback(parseResult);
      });
    }
    // Will support arifact in the next release
    throw new Error('this binding is not support');
  };

  /** @desc   Generates the logout request and callback to developers to design their own method
  * @param  {ServiceProvider} sp     object of service provider
  * @param  {string}   binding       protocol binding
  * @param  {object}   user          current logged user (e.g. req.user)
  * @param  {string} relayState      the URL to which to redirect the user when logout is complete
  * @param  {function} callback      developers do their own request to do with passing information
  * @param  {function} rcallback     used when developers have their own login response template
  */
  sendLogoutRequest (targetEntity, binding, user, relayState, callback, rcallback) {
    binding = namespace.binding[binding] || namespace.binding.redirect;
    if (binding === namespace.binding.redirect) {
      return callback(RedirectBinding.logoutRequestRedirectURL(user, {
        init: this,
        target: targetEntity
      }, rcallback, relayState));
    }
    if (binding === namespace.binding.post) {
      return callback({
        actionValue: PostBinding.base64LogoutRequest(user, libsaml.createXPath('Issuer'), {
          init: this,
          target: targetEntity
        }, rcallback),
        relayState: relayState,
        entityEndpoint: targetEntity.entityMeta.getSingleLogoutService(binding),
        actionType: 'LogoutRequest'
      });
    }
    // Will support arifact in the next release
    throw new Error('The binding is not support');
  }
  /**
  * @desc  Generates the logout response and callback to developers to design their own method
  * @param  {IdentityProvider} idp               object of identity provider
  * @param  {object} requestInfo                 corresponding request, used to obtain the id
  * @param  {string} relayState                  the URL to which to redirect the user when logout is complete.
  * @param  {string} binding                     protocol binding
  * @param  {function} callback                  developers use their own form submit to do with passing information
  * @param  {function} rcallback                 used when developers have their own login response template
  */
  sendLogoutResponse (targetEntity, requestInfo, binding, relayState, callback, rcallback) {
    binding = namespace.binding[binding] || namespace.binding.redirect;
    if (binding === namespace.binding.redirect) {
      return callback(RedirectBinding.logoutResponseRedirectURL(requestInfo, {
        init: this,
        target: targetEntity
      }, relayState, rcallback));
    }
    if (binding === namespace.binding.post) {
      return callback({
        actionValue: PostBinding.base64LogoutResponse(requestInfo, libsaml.createXPath('Issuer'), {
          init: this,
          target: targetEntity
        }, rcallback),
        relayState: relayState,
        entityEndpoint: targetEntity.entityMeta.getSingleLogoutService(binding),
        actionType: 'LogoutResponse'
      });
    }
    throw new Error('This binding is not support');
  }
  /**
  * @desc   Validation and callback parsed the URL parameters
  * @param  {IdentityProvider}   idp             object of identity provider
  * @param  {string}   binding                   protocol binding
  * @param  {request}   req                      request
  * @param  {function} parseCallback             developers use their own validation to do with passing information
  */
  parseLogoutRequest (targetEntity, binding, req, parseCallback) {
    return this.abstractBindingParser({
      parserFormat: ['NameID', 'Issuer', {
        localName: 'Signature',
        extractEntireBody: true
      },{
        localName: 'LogoutRequest',
        attributes: ['ID', 'Destination']
      }],
      checkSignature: this.entitySetting.wantLogoutRequestSigned,
      parserType: 'LogoutRequest',
      actionType: 'logout'
    }, binding, req, targetEntity.entityMeta, parseCallback);
  };
  /**
  * @desc   Validation and callback parsed the URL parameters
  * @param  {string}   binding                   protocol binding
  * @param  {request}   req                      request
  * @param  {ServiceProvider}   sp               object of service provider
  * @param  {function} parseCallback             developers use their own validation to do with passing information
  */
  parseLogoutResponse (targetEntity, binding, req, parseCallback) {
    return this.abstractBindingParser({
      parserFormat: [{
        localName: 'StatusCode',
        attributes: ['Value']
      }, 'Issuer', {
        localName: 'Signature',
        extractEntireBody: true
      },{
        localName: 'LogoutResponse',
        attributes: ['ID', 'Destination', 'InResponseTo']
      }],
      checkSignature: this.entitySetting.wantLogoutResponseSigned,
      supportBindings: ['post'],
      parserType: 'LogoutResponse',
      actionType: 'logout'
    },binding, req, targetEntity.entityMeta, parseCallback);
  }
}

export default function (entitySetting, entityType, entityMeta) {
  return new Entity(entitySetting, entityType, entityMeta);
}
