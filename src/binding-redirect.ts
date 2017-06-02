/**
* @file binding-redirect.ts
* @author tngan
* @desc Binding-level API, declare the functions using Redirect binding
*/
import utility from './utility';
import libsaml from './libsaml';
import Entity, { BindingContext } from './entity';
import { IdentityProvider as Idp } from './entity-idp';
import { ServiceProvider as Sp } from './entity-sp';

import { wording, namespace } from './urn';
import { get } from 'lodash';

const binding = wording.binding;
const urlParams = wording.urlParams;

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
function buildRedirectURL(type: string, isSigned: boolean, rawSamlRequest: string, entitySetting: any, relayState: string = ''): string {
  const queryParam = libsaml.getQueryParamByType(type);
  // In general, this xmlstring is required to do deflate -> base64 -> urlencode
  let samlRequest = encodeURIComponent(utility.base64Encode(utility.deflateString(rawSamlRequest)));
  if (relayState !== '') {
    relayState = pvPair(urlParams.relayState, encodeURIComponent(relayState));
  }
  if (isSigned) {
    let sigAlg = pvPair(urlParams.sigAlg, encodeURIComponent(entitySetting.requestSignatureAlgorithm));
    let octetString = samlRequest + sigAlg + relayState;
    return pvPair(queryParam, octetString, true) + pvPair(urlParams.signature, encodeURIComponent(libsaml.constructMessageSignature(type + '=' + octetString, entitySetting.privateKey, entitySetting.privateKeyPass, null, entitySetting.requestSignatureAlgorithm)));
  }
  return pvPair(queryParam, samlRequest + relayState, true);
}
/**
* @desc Redirect URL for login request
* @param  {object} entity                       object includes both idp and sp
* @param  {function} customTagReplacement      used when developers have their own login response template
* @return {string} redirect URL
*/
function loginRequestRedirectURL(entity: { idp: Idp, sp: Sp }, customTagReplacement?: (template: string) => BindingContext): BindingContext {

  let metadata: any = { idp: entity.idp.entityMeta, sp: entity.sp.entityMeta };
  let spSetting: any = entity.sp.entitySetting;
  let id: string = '';
  let context: string = '';

  if (metadata && metadata.idp && metadata.sp) {
    let base = metadata.idp.getSingleSignOnService(binding.redirect);
    let rawSamlRequest: string;
    if (spSetting.loginRequestTemplate) {
      const info = customTagReplacement(spSetting.logoutRequestTemplate);
      id = get<string>(info, 'id');
      rawSamlRequest = get<string>(info, 'context');
    } else {
      id = spSetting.generateID();
      rawSamlRequest = libsaml.replaceTagsByValue(libsaml.defaultLoginRequestTemplate.context, <any>{
        ID: id,
        Destination: base,
        Issuer: metadata.sp.getEntityID(),
        IssueInstant: new Date().toISOString(),
        NameIDFormat: namespace.format[spSetting.loginNameIDFormat] || namespace.format.emailAddress,
        AssertionConsumerServiceURL: metadata.sp.getAssertionConsumerService(binding.redirect),
        EntityID: metadata.sp.getEntityID(),
        AllowCreate: spSetting.allowCreate
      });
    }
    return {
      id,
      context: base + buildRedirectURL(urlParams.samlRequest, metadata.sp.isAuthnRequestSigned(), rawSamlRequest, spSetting),
    }
  }
  throw new Error('Missing declaration of metadata');
}
/**
* @desc Redirect URL for logout request
* @param  {object} user                        current logged user (e.g. req.user)
* @param  {object} entity                      object includes both idp and sp
* @param  {function} customTagReplacement     used when developers have their own login response template
* @return {string} redirect URL
*/
function logoutRequestRedirectURL(user, entity, relayState?: string, customTagReplacement?: (template: string) => BindingContext): BindingContext {
  let metadata = { init: entity.init.entityMeta, target: entity.target.entityMeta };
  let initSetting = entity.init.entitySetting;
  let id: string = '';
  let context: string = '';
  if (metadata && metadata.init && metadata.target) {
    let base = metadata.target.getSingleLogoutService(binding.redirect);
    let rawSamlRequest: string = '';
    if (initSetting.logoutRequestTemplate) {
      const info = customTagReplacement(initSetting.logoutRequestTemplate);
      id = get<string>(info, 'id');
      rawSamlRequest = get<string>(info, 'context');
    } else {
      id = initSetting.generateID();
      rawSamlRequest = libsaml.replaceTagsByValue(libsaml.defaultLogoutRequestTemplate.context, <any>{
        ID: id,
        Destination: base,
        EntityID: metadata.init.getEntityID(),
        Issuer: metadata.init.getEntityID(),
        IssueInstant: new Date().toISOString(),
        NameIDFormat: namespace.format[initSetting.logoutNameIDFormat] || namespace.format.emailAddress,
        NameID: user.logoutNameID,
        SessionIndex: user.sessionIndex
      });
    }
    return {
      id,
      context: base + buildRedirectURL(urlParams.logoutRequest, entity.target.entitySetting.wantLogoutRequestSigned, rawSamlRequest, initSetting, relayState),
    }
  }
  throw new Error('Missing declaration of metadata');
}
/**
* @desc Redirect URL for logout response
* @param  {object} requescorresponding request, used to obtain the id
* @param  {object} entity                      object includes both idp and sp
* @param  {function} customTagReplacement     used when developers have their own login response template
*/
function logoutResponseRedirectURL(requestInfo: any, entity: any, relayState?: string, customTagReplacement?: (template: string) => BindingContext): BindingContext {
  let id: string = '';
  let context: string = '';
  let metadata = {
    init: entity.init.entityMeta,
    target: entity.target.entityMeta
  };
  let initSetting = entity.init.entitySetting;
  if (metadata && metadata.init && metadata.target) {
    let base = metadata.target.getSingleLogoutService(binding.redirect);
    let rawSamlResponse;

    if (initSetting.logoutResponseTemplate) {
      const template = customTagReplacement(initSetting.logoutResponseTemplate);
      id = get<string>(template, 'id');
      rawSamlResponse = get<string>(template, 'context');
    } else {
      id = initSetting.generateID();
      let tvalue: any = {
        ID: id,
        Destination: base,
        Issuer: metadata.init.getEntityID(),
        EntityID: metadata.init.getEntityID(),
        IssueInstant: new Date().toISOString(),
        StatusCode: namespace.statusCode.success
      };
      if (requestInfo && requestInfo.extract && requestInfo.extract.logoutrequest) {
        tvalue.InResponseTo = requestInfo.extract.logoutrequest.id;
      }
      rawSamlResponse = libsaml.replaceTagsByValue(libsaml.defaultLogoutResponseTemplate.context, tvalue);
    }
    return {
      id,
      context: base + buildRedirectURL(urlParams.logoutResponse, entity.target.entitySetting.wantLogoutResponseSigned, rawSamlResponse, initSetting, relayState)
    }
  }
  throw new Error('Missing declaration of metadata');
}

const redirectBinding = {
  loginRequestRedirectURL,
  logoutRequestRedirectURL,
  logoutResponseRedirectURL
};

export default redirectBinding;
