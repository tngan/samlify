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
import * as uuid from 'uuid';
import libsaml from './libsaml';
import Metadata from './metadata';
import IdpMetadata from './metadata-idp';
import SpMetadata from './metadata-sp';
import redirectBinding from './binding-redirect';
import postBinding from './binding-post';

const dataEncryptionAlgorithm = algorithms.encryption.data; // SS1.1
const keyEncryptionAlgorithm = algorithms.encryption.key; // SS1.1
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
  generateID: (): string => uuid.v4(),
  relayState: ''
};

export default class Entity {

  entitySetting: any;
  entityType: string;
  entityMeta: any;
  /**
  * @desc  Constructor
  * @param {object} entitySetting
  * @param {object} entityMetaClass determine whether the entity is IdentityProvider or ServiceProvider
  * @param {string} entityMeta is the entity metafile path, deprecated after 2.0
  */
  constructor(entitySetting, entityType) {
    this.entitySetting = Object.assign({}, defaultEntitySetting, entitySetting);
    const metadata = entitySetting.metadata ? entitySetting.metadata : entitySetting;
    switch (entityType) {
      case 'idp':
        this.entityMeta = IdpMetadata(metadata);
        break;
      case 'sp':
        this.entityMeta = SpMetadata(metadata);
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
  verifyTime(notBefore: Date, notOnOrAfter: Date): boolean {
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
  * @return {ParseResult} parseResult
  */
  async abstractBindingParser(opts, binding: string, req, targetEntityMetadata) {
    const here = this; //SS-1.1 (refractor later on)
    const entityMeta: any = this.entityMeta;
    let options = opts || {};
    let parseResult = {};
    let supportBindings = [nsBinding.redirect, nsBinding.post];
    let { parserFormat: fields, parserType, actionType, from, checkSignature = true, decryptAssertion = true } = options;

    if (actionType === 'login') {
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
    } else if (actionType == 'logout') {
      let singleLogoutServices = entityMeta.getSingleLogoutService(binding);
      if (!singleLogoutServices) {
        supportBindings = [];
      }
    } else {
      throw new Error('Invalid actionType in abstractBindingParser');
    }

    if (binding === bindDict.redirect && supportBindings.indexOf(nsBinding[binding]) !== -1) {
      let reqQuery: { SigAlg: string, Signature: string } = req.query;
      let samlContent = reqQuery[libsaml.getQueryParamByType(parserType)];

      if (samlContent === undefined) {
        throw new Error('Bad request');
      }
      let xmlString = utility.inflateString(decodeURIComponent(samlContent));
      if (checkSignature) {
        let { SigAlg: sigAlg, Signature: signature } = reqQuery;
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
      return parseResult;
    }

    if (binding == bindDict.post && supportBindings.indexOf(nsBinding[binding]) !== -1) {
      // make sure express.bodyParser() has been used
      let encodedRequest = req.body[libsaml.getQueryParamByType(parserType)];
      let decodedRequest = String(utility.base64Decode(encodedRequest));
      let issuer = targetEntityMetadata.getEntityID();
      //SS-1.1
      const res = await libsaml.decryptAssertion(parserType, here, from, decodedRequest);

      let parseResult = {
        samlContent: res,
        extract: libsaml.extractor(res, fields)
      };
      if (checkSignature) {
        // verify the signature
        if (!libsaml.verifySignature(res, parseResult.extract.signature, {
          cert: targetEntityMetadata,
          signatureAlgorithm: here.entitySetting.requestSignatureAlgorithm
        })) {
          throw new Error('incorrect signature');
        }
      }
      if (!here.verifyFields(parseResult.extract.issuer, issuer)) {
        throw new Error('incorrect issuer');
      }

      return parseResult;

    }
    // Will support arifact in the next release
    throw new Error('this binding is not support');
  };

  /** @desc   Generates the logout request for developers to design their own method
  * @param  {ServiceProvider} sp     object of service provider
  * @param  {string}   binding       protocol binding
  * @param  {object}   user          current logged user (e.g. req.user)
  * @param  {string} relayState      the URL to which to redirect the user when logout is complete
  * @param  {function} rcallback     used when developers have their own login response template
  */
  sendLogoutRequest(targetEntity, binding, user, relayState, rcallback) : any {
    if (binding === wording.binding.redirect) {
      return redirectBinding.logoutRequestRedirectURL(user, {
        init: this,
        target: targetEntity
      }, rcallback, relayState);
    }
    if (binding === wording.binding.post) {
      const entityEndpoint = targetEntity.entityMeta.getSingleLogoutService(binding);
      const	actionValue = postBinding.base64LogoutRequest(user, libsaml.createXPath('Issuer'), { init: this, target: targetEntity }, rcallback);
      return {
        actionValue,
        relayState,
        entityEndpoint,
        actionType: 'SAMLRequest'
      };
    }
    // Will support arifact in the next release
    throw new Error('The binding is not support');
  }
  /**
  * @desc  Generates the logout response for developers to design their own method
  * @param  {IdentityProvider} idp               object of identity provider
  * @param  {object} requestInfo                 corresponding request, used to obtain the id
  * @param  {string} relayState                  the URL to which to redirect the user when logout is complete.
  * @param  {string} binding                     protocol binding
  * @param  {function} rcallback                 used when developers have their own login response template
  */
  sendLogoutResponse(targetEntity, requestInfo, binding, relayState, rcallback) : any {
    binding = namespace.binding[binding] || namespace.binding.redirect;
    if (binding === namespace.binding.redirect) {
      return redirectBinding.logoutResponseRedirectURL(requestInfo, {
        init: this,
        target: targetEntity
      }, relayState, rcallback);
    }
    if (binding === namespace.binding.post) {
      return {
        actionValue: postBinding.base64LogoutResponse(requestInfo, libsaml.createXPath('Issuer'), {
          init: this,
          target: targetEntity
        }, rcallback),
        relayState: relayState,
        entityEndpoint: targetEntity.entityMeta.getSingleLogoutService(binding),
        actionType: 'SAMLResponse'
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
      actionType: 'logout'
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
      actionType: 'logout'
    }, binding, req, targetEntity.entityMeta);
  }
}
