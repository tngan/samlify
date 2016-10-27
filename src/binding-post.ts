/**
* @file binding-post.ts
* @author tngan
* @desc Binding-level API, declare the functions using POST binding
*/

import { wording, tags, namespace } from './urn';
import * as uuid from 'node-uuid';
import libsaml from './libsaml';
import utility from './utility';

const xmlTag = tags.xmlTag;
const binding = wording.binding;

/**
* @desc Generate a base64 encoded login request
* @param  {string} referenceTagXPath           reference uri
* @param  {object} entity                      object includes both idp and sp
* @param  {function} rcallback     used when developers have their own login response template
*/
function base64LoginRequest(referenceTagXPath: string, entity: any, rcallback: (template: string) => string) {
  let metadata = { idp: entity.idp.entityMeta, sp: entity.sp.entityMeta };
  let spSetting = entity.sp.entitySetting;

  if (metadata && metadata.idp && metadata.sp) {
    let base = metadata.idp.getSingleSignOnService(binding.post);
    let rawSamlRequest;
    if (metadata.sp.isAuthnRequestSigned() !== metadata.idp.isWantAuthnRequestsSigned()) {
      throw new Error('Conflict of metadata - sp isAuthnRequestSigned is not equal to idp isWantAuthnRequestsSigned');
    }
    if (spSetting.loginRequestTemplate) {
      rawSamlRequest = rcallback(spSetting.loginRequestTemplate);
    } else {
      rawSamlRequest = libsaml.replaceTagsByValue(libsaml.defaultLoginRequestTemplate, <any>{
        ID: spSetting.generateID ? spSetting.generateID() : uuid.v4(),
        Destination: base,
        Issuer: metadata.sp.getEntityID(),
        IssueInstant: new Date().toISOString(),
        AssertionConsumerServiceURL: metadata.sp.getAssertionConsumerService(binding.post),
        EntityID: metadata.sp.getEntityID(),
        AllowCreate: spSetting.allowCreate,
        NameIDFormat: namespace.format[spSetting.logoutNameIDFormat] || namespace.format.emailAddress,
      });
    }
    if (metadata.idp.isWantAuthnRequestsSigned()) {
      return libsaml.constructSAMLSignature(rawSamlRequest, referenceTagXPath, metadata.sp.getX509Certificate('signing'), spSetting.privateKeyFile, spSetting.privateKeyFilePass, spSetting.requestSignatureAlgorithm); // SS1.1 add signature algorithm
      // No need to embeded XML signature
    }
    // No need to embeded XML signature
    return utility.base64Encode(rawSamlRequest);
  }
  throw new Error('Missing declaration of metadata');
}
/**
* @desc Generate a base64 encoded login response
* @param  {object} requestInfo                 corresponding request, used to obtain the id
* @param  {string} referenceTagXPath           reference uri
* @param  {object} entity                      object includes both idp and sp
* @param  {object} user                        current logged user (e.g. req.user)
* @param  {function} rcallback     used when developers have their own login response template
*/
function base64LoginResponse(requestInfo: any, referenceTagXPath: string, entity: any, user: any, rcallback: (template: string) => string, rtnCallback: (xmlStr: any) => void) {
  let metadata = {
    idp: entity.idp.entityMeta,
    sp: entity.sp.entityMeta
  };
  let idpSetting = entity.idp.entitySetting;
  let resXml = undefined;
  if (metadata && metadata.idp && metadata.sp) {
    let base = metadata.sp.getAssertionConsumerService(binding.post);
    let template;
    let _user = user || {};
    let rawSamlResponse;
    if (idpSetting.loginResponseTemplate) {
      rawSamlResponse = rcallback(idpSetting.loginResponseTemplate);
    } else {
      let nowTime = new Date();
      let spEntityID = metadata.sp.getEntityID();
      let fiveMinutesLaterTime = new Date(nowTime.getTime());
      fiveMinutesLaterTime.setMinutes(fiveMinutesLaterTime.getMinutes() + 5);
      let fiveMinutesLater = new Date(fiveMinutesLaterTime).toISOString();
      let now = nowTime.toISOString();
      let tvalue: any = {
        ID: idpSetting.generateID ? idpSetting.generateID() : uuid.v4(),
        AssertionID: idpSetting.generateID ? idpSetting.generateID() : uuid.v4(),
        Destination: base,
        Audience: spEntityID,
        SubjectRecipient: spEntityID,
        NameIDFormat: namespace.format[idpSetting.logoutNameIDFormat] || namespace.format.emailAddress,
        NameID: _user.email || '',
        Issuer: metadata.idp.getEntityID(),
        IssueInstant: now,
        ConditionsNotBefore: now,
        ConditionsNotOnOrAfter: fiveMinutesLater,
        SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater,
        AssertionConsumerServiceURL: metadata.sp.getAssertionConsumerService(binding.post),
        EntityID: spEntityID,
        StatusCode: namespace.statusCode.success,
        // future features
        AuthnStatement: '',
        AttributeStatement: ''
      };
      if (requestInfo !== null) {
        tvalue.InResponseTo = requestInfo.extract.authnrequest.id;
      }
      rawSamlResponse = libsaml.replaceTagsByValue(libsaml.defaultLoginResponseTemplate, tvalue);
    }
    resXml = metadata.sp.isWantAssertionsSigned() ? libsaml.constructSAMLSignature(rawSamlResponse, referenceTagXPath, metadata.idp.getX509Certificate('signing'), idpSetting.privateKeyFile, idpSetting.privateKeyFilePass, idpSetting.requestSignatureAlgorithm, false) : rawSamlResponse; // SS1.1 add signature algorithm
    // SS-1.1
    idpSetting.isAssertionEncrypted ? libsaml.encryptAssertion(entity.idp, entity.sp, resXml, rtnCallback) : rtnCallback(resXml);
  } else {
    throw new Error('Missing declaration of metadata');
  }
}
/**
* @desc Generate a base64 encoded logout request
* @param  {object} user                         current logged user (e.g. req.user)
* @param  {string} referenceTagXPath            reference uri
* @param  {object} entity                       object includes both idp and sp
* @param  {function} rcallback      used when developers have their own login response template
* @return {string} base64 encoded request
*/
function base64LogoutRequest(user, referenceTagXPath, entity, rcallback?: (template: string) => string): string {
  let metadata = {
    init: entity.init.entityMeta,
    target: entity.target.entityMeta
  };
  let initSetting = entity.init.entitySetting;
  if (metadata && metadata.init && metadata.target) {
    let rawSamlRequest;
    if (initSetting.loginRequestTemplate) {
      rawSamlRequest = rcallback(initSetting.loginRequestTemplate);
    } else {
      let tvalue: any = {
        ID: initSetting.generateID ? initSetting.generateID() : uuid.v4(),
        Destination: metadata.target.getSingleLogoutService(binding.redirect),
        Issuer: metadata.init.getEntityID(),
        IssueInstant: new Date().toISOString(),
        EntityID: metadata.init.getEntityID(),
        NameIDFormat: namespace.format[initSetting.logoutNameIDFormat] || namespace.format.transient,
        NameID: user.logoutNameID
      };
      let rawSamlRequest = libsaml.replaceTagsByValue(libsaml.defaultLogoutRequestTemplate, tvalue);
    }
    if (entity.target.entitySetting.wantLogoutRequestSigned) {
      // Need to embeded XML signature
      return libsaml.constructSAMLSignature(rawSamlRequest, referenceTagXPath, metadata.init.getX509Certificate('signing'), initSetting.privateKeyFile, initSetting.privateKeyFilePass, initSetting.requestSignatureAlgorithm); // SS1.1 add signature algorithm
    } else {
      // No need to embeded XML signature
      return utility.base64Encode(rawSamlRequest);
    }
  } else {
    throw new Error('Missing declaration of metadata');
  }
}
/**
* @desc Generate a base64 encoded logout response
* @param  {object} requestInfo                 corresponding request, used to obtain the id
* @param  {string} referenceTagXPath           reference uri
* @param  {object} entity                      object includes both idp and sp
* @param  {function} rcallback     used when developers have their own login response template
*/
function base64LogoutResponse(requestInfo: any, referenceTagXPath: string, entity: any, rcallback: (template: string) => string) {
  let metadata = {
    init: entity.init.entityMeta,
    target: entity.target.entityMeta
  };
  let initSetting = entity.init.entitySetting;
  if (metadata && metadata.init && metadata.target) {
    let rawSamlResponse;
    if (initSetting.logoutResponseTemplate) {
      rawSamlResponse = rcallback(initSetting.logoutResponseTemplate);
    } else {
      let tvalue: any = {
        ID: initSetting.generateID ? initSetting.generateID() : uuid.v4(),
        Destination:  metadata.target.getAssertionConsumerService(binding.post),
        EntityID: metadata.init.getEntityID(),
        Issuer: metadata.init.getEntityID(),
        IssueInstant: new Date().toISOString(),
        StatusCode: namespace.statusCode.success
      };
      if (requestInfo && requestInfo.extract && requestInfo.extract.logoutrequest) {
        tvalue.InResponseTo = requestInfo.extract.logoutrequest.id;
      }
      rawSamlResponse = libsaml.replaceTagsByValue(libsaml.defaultLogoutResponseTemplate, tvalue);
      if (entity.target.entitySetting.wantLogoutResponseSigned) {
        // Need to embeded XML signature
        return libsaml.constructSAMLSignature(rawSamlResponse, referenceTagXPath, metadata.init.getX509Certificate('signing'), initSetting.privateKeyFile, initSetting.privateKeyFilePass, initSetting.requestSignatureAlgorithm); // SS1.1 add signature algorithm
      }
      // No need to embeded XML signature
      return utility.base64Encode(rawSamlResponse);
    }
  }
  throw new Error('Missing declaration of metadata');
}

const postBinding = {
  base64LoginRequest,
  base64LoginResponse,
  base64LogoutRequest,
  base64LogoutResponse
};

export default postBinding;
