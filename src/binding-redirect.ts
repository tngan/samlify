/**
* @file binding-redirect.ts
* @author tngan
* @desc Binding-level API, declare the functions using Redirect binding
*/
import utility, { get } from './utility';
import libsaml from './libsaml';
import { BindingContext } from './entity';
import { IdentityProvider as Idp } from './entity-idp';
import { ServiceProvider as Sp } from './entity-sp';
import * as url from 'url';
import { wording, namespace } from './urn';

const binding = wording.binding;
const urlParams = wording.urlParams;

export interface BuildRedirectConfig {
  baseUrl: string;
  type: string;
  isSigned: boolean;
  context: string;
  entitySetting: any;
  relayState?: string;
}

/**
* @private
* @desc Helper of generating URL param/value pair
* @param  {string} param     key
* @param  {string} value     value of key
* @param  {boolean} first    determine whether the param is the starting one in order to add query header '?'
* @return {string}
*/
function pvPair(param: string, value: string, first?: boolean): string {
  return (first === true ? '?' : '&') + param + '=' + value;
}
/**
* @private
* @desc Refractored part of URL generation for login/logout request
* @param  {string} type
* @param  {boolean} isSigned
* @param  {string} rawSamlRequest
* @param  {object} entitySetting
* @return {string}
*/
function buildRedirectURL(opts: BuildRedirectConfig) {
  const {
    baseUrl,
    type,
    isSigned,
    context,
    entitySetting,
  } = opts;
  let { relayState = '' } = opts;
  const noParams = (url.parse(baseUrl).query || []).length === 0;
  const queryParam = libsaml.getQueryParamByType(type);
  // In general, this xmlstring is required to do deflate -> base64 -> urlencode
  const samlRequest = encodeURIComponent(utility.base64Encode(utility.deflateString(context)));
  if (relayState !== '') {
    relayState = pvPair(urlParams.relayState, encodeURIComponent(relayState));
  }
  if (isSigned) {
    const sigAlg = pvPair(urlParams.sigAlg, encodeURIComponent(entitySetting.requestSignatureAlgorithm));
    const octetString = samlRequest + relayState + sigAlg;
    return baseUrl + pvPair(queryParam, octetString, noParams) + pvPair(urlParams.signature, encodeURIComponent(libsaml.constructMessageSignature(queryParam + '=' + octetString, entitySetting.privateKey, entitySetting.privateKeyPass, undefined, entitySetting.requestSignatureAlgorithm)));
  }
  return baseUrl + pvPair(queryParam, samlRequest + relayState, noParams);
}
/**
* @desc Redirect URL for login request
* @param  {object} entity                       object includes both idp and sp
* @param  {function} customTagReplacement      used when developers have their own login response template
* @return {string} redirect URL
*/
function loginRequestRedirectURL(entity: { idp: Idp, sp: Sp }, customTagReplacement?: (template: string) => BindingContext): BindingContext {

  const metadata: any = { idp: entity.idp.entityMeta, sp: entity.sp.entityMeta };
  const spSetting: any = entity.sp.entitySetting;
  let id: string = '';

  if (metadata && metadata.idp && metadata.sp) {
    const base = metadata.idp.getSingleSignOnService(binding.redirect);
    let rawSamlRequest: string;
    if (spSetting.loginRequestTemplate && customTagReplacement) {
      const info = customTagReplacement(spSetting.loginRequestTemplate);
      id = get(info, 'id', null);
      rawSamlRequest = get(info, 'context', null);
    } else {
      const nameIDFormat = spSetting.nameIDFormat;
      const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;
      id = spSetting.generateID();
      rawSamlRequest = libsaml.replaceTagsByValue(libsaml.defaultLoginRequestTemplate.context, {
        ID: id,
        Destination: base,
        Issuer: metadata.sp.getEntityID(),
        IssueInstant: new Date().toISOString(),
        NameIDFormat: selectedNameIDFormat,
        AssertionConsumerServiceURL: metadata.sp.getAssertionConsumerService(binding.post),
        EntityID: metadata.sp.getEntityID(),
        AllowCreate: spSetting.allowCreate,
      } as any);
    }
    return {
      id,
      context: buildRedirectURL({
        context: rawSamlRequest,
        type: urlParams.samlRequest,
        isSigned: metadata.sp.isAuthnRequestSigned(),
        entitySetting: spSetting,
        baseUrl: base,
        relayState: spSetting.relayState,
      }),
    };
  }
  throw new Error('ERR_GENERATE_REDIRECT_LOGIN_REQUEST_MISSING_METADATA');
}
/**
* @desc Redirect URL for logout request
* @param  {object} user                        current logged user (e.g. req.user)
* @param  {object} entity                      object includes both idp and sp
* @param  {function} customTagReplacement     used when developers have their own login response template
* @return {string} redirect URL
*/
function logoutRequestRedirectURL(user, entity, relayState?: string, customTagReplacement?: (template: string, tags: object) => BindingContext): BindingContext {
  const metadata = { init: entity.init.entityMeta, target: entity.target.entityMeta };
  const initSetting = entity.init.entitySetting;
  let id: string = initSetting.generateID();
  const nameIDFormat = initSetting.nameIDFormat;
  const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;
  
  if (metadata && metadata.init && metadata.target) {
    const base = metadata.target.getSingleLogoutService(binding.redirect);
    let rawSamlRequest: string = '';
    const requiredTags = {
      ID: id,
      Destination: base,
      EntityID: metadata.init.getEntityID(),
      Issuer: metadata.init.getEntityID(),
      IssueInstant: new Date().toISOString(),
      NameIDFormat: selectedNameIDFormat,
      NameID: user.logoutNameID,
      SessionIndex: user.sessionIndex,
    };
    if (initSetting.logoutRequestTemplate && customTagReplacement) {
      const info = customTagReplacement(initSetting.logoutRequestTemplate, requiredTags);
      id = get(info, 'id', null);
      rawSamlRequest = get(info, 'context', null);
    } else {
      rawSamlRequest = libsaml.replaceTagsByValue(libsaml.defaultLogoutRequestTemplate.context, requiredTags as any);
    }
    return {
      id,
      context: buildRedirectURL({
        context: rawSamlRequest,
        relayState,
        type: urlParams.logoutRequest,
        isSigned: entity.target.entitySetting.wantLogoutRequestSigned,
        entitySetting: initSetting,
        baseUrl: base,
      }),
    };
  }
  throw new Error('ERR_GENERATE_REDIRECT_LOGOUT_REQUEST_MISSING_METADATA');
}
/**
* @desc Redirect URL for logout response
* @param  {object} requescorresponding request, used to obtain the id
* @param  {object} entity                      object includes both idp and sp
* @param  {function} customTagReplacement     used when developers have their own login response template
*/
function logoutResponseRedirectURL(requestInfo: any, entity: any, relayState?: string, customTagReplacement?: (template: string) => BindingContext): BindingContext {
  const metadata = {
    init: entity.init.entityMeta,
    target: entity.target.entityMeta,
  };
  const initSetting = entity.init.entitySetting;
  let id: string = initSetting.generateID();
  if (metadata && metadata.init && metadata.target) {
    const base = metadata.target.getSingleLogoutService(binding.redirect);
    let rawSamlResponse: string;
    if (initSetting.logoutResponseTemplate && customTagReplacement) {
      const template = customTagReplacement(initSetting.logoutResponseTemplate);
      id = get(template, 'id', null);
      rawSamlResponse = get(template, 'context', null);
    } else {
      const tvalue: any = {
        ID: id,
        Destination: base,
        Issuer: metadata.init.getEntityID(),
        EntityID: metadata.init.getEntityID(),
        IssueInstant: new Date().toISOString(),
        StatusCode: namespace.statusCode.success,
      };
      if (requestInfo && requestInfo.extract && requestInfo.extract.logoutRequest) {
        tvalue.InResponseTo = requestInfo.extract.logoutRequest.id;
      }
      rawSamlResponse = libsaml.replaceTagsByValue(libsaml.defaultLogoutResponseTemplate.context, tvalue);
    }
    return {
      id,
      context: buildRedirectURL({
        baseUrl: base,
        type: urlParams.logoutResponse,
        isSigned: entity.target.entitySetting.wantLogoutResponseSigned,
        context: rawSamlResponse,
        entitySetting: initSetting,
        relayState,
      }),
    };
  }
  throw new Error('ERR_GENERATE_REDIRECT_LOGOUT_RESPONSE_MISSING_METADATA');
}

const redirectBinding = {
  loginRequestRedirectURL,
  logoutRequestRedirectURL,
  logoutResponseRedirectURL,
};

export default redirectBinding;
