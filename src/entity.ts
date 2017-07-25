/**
* @file entity.ts
* @author tngan
* @desc  An abstraction for identity provider and service provider.
*/
import { base64Decode, isNonEmptyArray, inflateString } from './utility';
import { namespace, wording, algorithms, messageConfigurations } from './urn';
import * as uuid from 'uuid';
import libsaml from './libsaml';
import Metadata from './metadata';
import IdpMetadata, { IdpMetadata as IdpMetadataConstructor } from './metadata-idp';
import SpMetadata, { SpMetadata as SpMetadataConstructor } from './metadata-sp';
import redirectBinding from './binding-redirect';
import postBinding from './binding-post';
import { isString, isUndefined, isArray, get } from 'lodash';
import * as url from 'url';
import { MetadataIdpConstructor, MetadataSpConstructor, EntitySetting } from './types';

const dataEncryptionAlgorithm = algorithms.encryption.data;
const keyEncryptionAlgorithm = algorithms.encryption.key;
const bindDict = wording.binding;
const signatureAlgorithms = algorithms.signature;
const messageSigningOrders = messageConfigurations.signingOrder;
const nsBinding = namespace.binding;

const defaultEntitySetting = {
  wantLogoutResponseSigned: false,
  messageSigningOrder: messageSigningOrders.SIGN_THEN_ENCRYPT,
  wantLogoutRequestSigned: false,
  allowCreate: false,
  isAssertionEncrypted: false,
  requestSignatureAlgorithm: signatureAlgorithms.RSA_SHA256,
  dataEncryptionAlgorithm: dataEncryptionAlgorithm.AES_256,
  keyEncryptionAlgorithm: keyEncryptionAlgorithm.RSA_1_5,
  generateID: (): string => ('_' + uuid.v4()),
  relayState: '',
};

export interface ESamlHttpRequest {
  query?: any;
  body?: any;
  octetString?: string;
}

export interface BindingContext {
  context: string;
  id: string;
}

export interface PostBindingContext extends BindingContext {
  relayState?: string;
  entityEndpoint: string;
  type: string;
}

export interface ParseResult {
  samlContent: string;
  extract: any;
  sigAlg?: string;
}

export type EntityConstructor = (MetadataIdpConstructor | MetadataSpConstructor)
  & { metadata?: string | Buffer };

export default class Entity {
  entitySetting: EntitySetting;
  entityType: string;
  entityMeta: IdpMetadataConstructor | SpMetadataConstructor;

  /**
  * @param entitySetting
  * @param entityMeta is the entity metadata, deprecated after 2.0
  */
  constructor(entitySetting: EntityConstructor, entityType: 'idp' | 'sp') {
    this.entitySetting = Object.assign({}, defaultEntitySetting, entitySetting);
    const metadata = entitySetting.metadata || entitySetting;
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
  }

  /**
  * @desc  Exports the entity metadata into specified folder
  * @param  {string} exportFile indicates the file name
  */
  exportMetadata(exportFile: string) {
    return this.entityMeta.exportMetadata(exportFile);
  }

  /** * @desc  Verify fields with the one specified in metadata
  * @param  {string/[string]} field is a string or an array of string indicating the field value in SAML message
  * @param  {string} metaField is a string indicating the same field specified in metadata
  * @return {boolean} True/False
  */
  verifyFields(field: string | string[], metaField: string): boolean {
    if (isString(field)) {
      return field === metaField;
    }
    if (isNonEmptyArray(field)) {
      let res = true;
      field.forEach(f => {
        if (f !== metaField) {
          res = false;
          return;
        }
      });
      return res;
    }
    return false;
  }

  /**
  * @desc  Verify time stamp
  * @param  {date} notBefore
  * @param  {date} notOnOrAfter
  * @return {boolean}
  */
  verifyTime(notBefore?: Date, notOnOrAfter?: Date): boolean {
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
  }

  /**
  * @desc  Validate and parse the request/response with different bindings
  * @param  {object} opts is the options for abstraction
  * @param  {string} binding is the protocol bindings (e.g. redirect, post)
  * @param  {request} req is the http request
  * @param  {Metadata} targetEntityMetadata either IDP metadata or SP metadata
  * @return {ParseResult} parseResult
  */
  async genericParser(opts, binding: string, req) {
    const { query, body, octetString } = req;
    const here = this;
    const entityMeta: any = this.entityMeta;
    const options = opts || {};
    let parseResult: ParseResult;
    let supportBindings = [nsBinding.redirect, nsBinding.post];
    const { parserFormat: fields, parserType, type, from, checkSignature = true, decryptAssertion = false } = options;
    const targetEntityMetadata = opts.from.entityMeta;

    if (type === 'login') {
      if (entityMeta.getAssertionConsumerService) {
        const assertionConsumerService = entityMeta.getAssertionConsumerService(binding);
        if (!assertionConsumerService) {
          supportBindings = [];
        }
      } else if (entityMeta.getSingleSignOnService) {
        const singleSignOnService = entityMeta.getSingleSignOnService(binding);
        if (!singleSignOnService) {
          supportBindings = [];
        }
      }
    } else if (type === 'logout') {
      const singleLogoutServices = entityMeta.getSingleLogoutService(binding);
      if (!singleLogoutServices) {
        supportBindings = [];
      }
    } else {
      throw new Error('Invalid type in genericParser');
    }

    if (binding === bindDict.redirect && supportBindings.indexOf(nsBinding[binding]) !== -1) {
      const reqQuery: any = query;
      const samlContent = reqQuery[libsaml.getQueryParamByType(parserType)];

      if (samlContent === undefined) {
        throw new Error('bad request');
      }
      const xmlString = inflateString(decodeURIComponent(samlContent));
      if (checkSignature) {
        const { SigAlg: sigAlg, Signature: signature } = reqQuery;
        if (signature && sigAlg) {
          if (libsaml.verifyMessageSignature(targetEntityMetadata, octetString, new Buffer(decodeURIComponent(signature), 'base64'), sigAlg)) {
            parseResult = {
              samlContent: xmlString,
              sigAlg: decodeURIComponent(sigAlg),
              extract: libsaml.extractor(xmlString, fields),
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
          extract: libsaml.extractor(xmlString, fields),
        };
      }
      return parseResult;
    }

    if (binding === bindDict.post && supportBindings.indexOf(nsBinding[binding]) !== -1) {
      // make sure express.bodyParser() has been used
      const encodedRequest = body[libsaml.getQueryParamByType(parserType)];
      let res = String(base64Decode(encodedRequest));
      const issuer = targetEntityMetadata.getEntityID();
      //verify signature before decryption if IDP encrypted then signed the message
      if (checkSignature && from.entitySetting.messageSigningOrder === messageSigningOrders.ENCRYPT_THEN_SIGN) {

        // verify the signatures (for both assertion/message)
        if (!libsaml.verifySignature(res, {
          cert: opts.from.entityMeta,
          signatureAlgorithm: opts.from.entitySetting.requestSignatureAlgorithm,
        })) {
          throw new Error('incorrect signature');
        }
      }
      if (parserType === 'SAMLResponse' && from.entitySetting.isAssertionEncrypted) {
        res = await libsaml.decryptAssertion(here, res);
      }
      parseResult = {
        samlContent: res,
        extract: libsaml.extractor(res, fields),
      };
      if (checkSignature && from.entitySetting.messageSigningOrder === messageSigningOrders.SIGN_THEN_ENCRYPT) {
        // verify the signatures (for both assertion/message)
        if (!libsaml.verifySignature(res, {
          cert: opts.from.entityMeta,
          signatureAlgorithm: opts.from.entitySetting.requestSignatureAlgorithm,
        })) {
          throw new Error('incorrect signature');
        }
      }
      if (!here.verifyFields(parseResult.extract.issuer, issuer)) {
        throw new Error('incorrect issuer');
      }
      return parseResult;
    }
    // Will support artifact in the next release
    throw new Error('this binding is not supported');
  }

  /** @desc   Generates the logout request for developers to design their own method
  * @param  {ServiceProvider} sp     object of service provider
  * @param  {string}   binding       protocol binding
  * @param  {object}   user          current logged user (e.g. user)
  * @param  {string} relayState      the URL to which to redirect the user when logout is complete
  * @param  {function} customTagReplacement     used when developers have their own login response template
  */
  createLogoutRequest(targetEntity, binding, user, relayState = '', customTagReplacement?): BindingContext | PostBindingContext {
    if (binding === wording.binding.redirect) {
      return redirectBinding.logoutRequestRedirectURL(user, {
        init: this,
        target: targetEntity,
      }, relayState, customTagReplacement);
    }
    if (binding === wording.binding.post) {
      const entityEndpoint = targetEntity.entityMeta.getSingleLogoutService(binding);
      const context = postBinding.base64LogoutRequest(user, libsaml.createXPath('Issuer'), { init: this, target: targetEntity }, customTagReplacement);
      return {
        ...context,
        relayState,
        entityEndpoint,
        type: 'SAMLRequest',
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
  createLogoutResponse(target, requestInfo, binding, relayState = '', customTagReplacement?): BindingContext | PostBindingContext {
    const protocol = namespace.binding[binding];
    if (protocol === namespace.binding.redirect) {
      return redirectBinding.logoutResponseRedirectURL(requestInfo, {
        init: this,
        target,
      }, relayState, customTagReplacement);
    }
    if (protocol === namespace.binding.post) {
      const context = postBinding.base64LogoutResponse(requestInfo, {
        init: this,
        target,
      }, customTagReplacement);
      return {
        ...context,
        relayState,
        entityEndpoint: target.entityMeta.getSingleLogoutService(binding),
        type: 'SAMLResponse',
      };
    }
    throw new Error('this binding is not supported');
  }

  /**
  * @desc   Validation of the parsed the URL parameters
  * @param  {IdentityProvider}   idp             object of identity provider
  * @param  {string}   binding                   protocol binding
  * @param  {request}   req                      request
  * @return {Promise}
  */
  parseLogoutRequest(from, binding, req: ESamlHttpRequest) {
    const checkSignature = this.entitySetting.wantLogoutRequestSigned;
    const parserType = 'LogoutRequest';
    const type = 'logout';
    return this.genericParser({
      from,
      type,
      parserType,
      checkSignature,
      parserFormat: [
        'NameID',
        'Issuer',
        { localName: 'Signature', extractEntireBody: true },
        { localName: 'LogoutRequest', attributes: ['ID', 'Destination'] },
      ],
    }, binding, req);
  }

  /**
  * @desc   Validation of the parsed the URL parameters
  * @param  {object} config                      config for the parser
  * @param  {string}   binding                   protocol binding
  * @param  {request}   req                      request
  * @return {Promise}
  */
  parseLogoutResponse(from, binding, req: ESamlHttpRequest) {
    const checkSignature = this.entitySetting.wantLogoutResponseSigned;
    const supportBindings = ['post'];
    const parserType = 'LogoutResponse';
    const type = 'logout';
    return this.genericParser({
      from,
      type,
      parserType,
      checkSignature,
      supportBindings,
      parserFormat: [
        { localName: 'StatusCode', attributes: ['Value'] },
        'Issuer',
        { localName: 'Signature', extractEntireBody: true },
        { localName: 'LogoutResponse', attributes: ['ID', 'Destination', 'InResponseTo'] },
      ],
    }, binding, req);
  }
}
