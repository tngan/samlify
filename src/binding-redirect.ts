/**
* @file binding-redirect.ts
* @author tngan
* @desc Binding-level API, declare the functions using Redirect binding
*/
import utility, { get } from './utility.js';
import libsaml from './libsaml.js';
import { BindingContext } from './entity.js';
import { IdentityProvider as Idp } from './entity-idp.js';
import { ServiceProvider as Sp } from './entity-sp.js';
import * as url from 'url';
import url2  from 'node:url'
import { wording, namespace } from './urn.js';

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
  console.log('这里是没问题的')
  console.log(baseUrl);
  const myURL = new URL('/saml/idp/authnRequest?SAMLRequest=nJJBb5tAEIX%2FCto7sLtmg1kFJDdWVUtpa8VuD71EGzxxVoJZujOkzb%2BvwK7qXnzIFea9%2Bd7buSXXd4NdjfyCD%2FBzBOLkd98h2elHLcaINjjyZNH1QJZbu1t9vrc6k9YRQWQfUFxIhuuaIQYObehEslnX4jV07WMhC7kwapnqpXNpUZUqfQIHadkCVCU8l0YbkXyHSD5gLXQmRbIhGmGDxA65Flpqk0qTqsVeFVbdWFNki2X1QyRrIPboeFa%2BMA9k81xVOlM3y8xkurRGSplP4Lk%2FDLm76EEkq78B7wLS2EPcQXz1LXx7uP%2FnRv6IHrMpCuDRI2Rt6E%2BOREEk23PiDx4PHo%2FX63k6DZH9tN9v0%2B3X3V408xPZOXFMPobYO75uMn3xh%2FR5HrWA7PlNNNd5tZKqXKiqKGf0x5EgTvy3%2BcX25nwtX1wPm%2FU2dL59ewcRR4fkAaeGuy78uovgGGrBcQSRN6eV%2F99k8ycAAP%2F%2F&RelayState=https%3A%2F%2Fconsole.volcengine.com&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=C%2BldoMXH96RTzqul5Kg1c7SAJ4mCrR3%2Bw4V%2BvO42Yqf0Nm6lSqZxQyc3jCzqJqBSzXyHaR3VM6W8YQ0Vo%2BoaT9JAgJPb%2FTpbFORAwK2pC9ZqVHdk0hgjDtbej9G%2FfAyP44tnw3tlq4SX6286%2Fek6hZOSzBnelPj9B8acRNSSPzpVzmSTD3h8oXfYE7xNWSENLcXDGkb8sHJtJuWccvV2zrelyWXFyVvmmJJj9dqiC2RSDQZvxFw0JQWGm9l8aaY4wqN%2BsfylLpO3J2DW4UkXWo2f7jbpA39Pq6j4Gl2I9a2SMWkyLhX9rB970R4WAvib%2FmaHBvJgUgYWY%2FtEBIUyeQ%3D%3D\n');
  console.log(myURL.searchParams);

  const noParams = (url.parse(baseUrl).query || []).length === 0;
  console.log(noParams);
  console.log('这里是有问题的')
  const queryParam = libsaml.getQueryParamByType(type);
  // In general, this xmlstring is required to do deflate -> base64 -> urlencode
  const samlRequest = encodeURIComponent(utility.base64Encode(utility.deflateString(context)));
  if (relayState !== '') {
    relayState = pvPair(urlParams.relayState, encodeURIComponent(relayState));
  }
  if (isSigned) {
    const sigAlg = pvPair(urlParams.sigAlg, encodeURIComponent(entitySetting.requestSignatureAlgorithm));
    const octetString = samlRequest + relayState + sigAlg;
    return baseUrl
      + pvPair(queryParam, octetString, noParams)
      + pvPair(urlParams.signature, encodeURIComponent(
        libsaml.constructMessageSignature(
          queryParam + '=' + octetString,
          entitySetting.privateKey,
          entitySetting.privateKeyPass,
          undefined,
          entitySetting.requestSignatureAlgorithm
        ).toString()
      )
      );
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
* @desc Redirect URL for login response
* @param  {object} requestInfo             corresponding request, used to obtain the id
* @param  {object} entity                      object includes both idp and sp
* @param  {object} user                         current logged user (e.g. req.user)
* @param  {String} relayState                the relaystate sent by sp corresponding request
* @param  {function} customTagReplacement     used when developers have their own login response template
*/
function loginResponseRedirectURL(requestInfo: any, entity: any, user: any = {}, relayState?: string, customTagReplacement?: (template: string) => BindingContext): BindingContext {
  const idpSetting = entity.idp.entitySetting;
  const spSetting = entity.sp.entitySetting;
  const metadata = {
    idp: entity.idp.entityMeta,
    sp: entity.sp.entityMeta,
  };

  let id: string = idpSetting.generateID();
  if (metadata && metadata.idp && metadata.sp) {
    const base = metadata.sp.getAssertionConsumerService(binding.redirect);
    let rawSamlResponse: string;
    //
    const nameIDFormat = idpSetting.nameIDFormat;
    const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;
    const nowTime = new Date();
    // Five minutes later : nowtime  + 5 * 60 * 1000 (in milliseconds)
    const fiveMinutesLaterTime = new Date(nowTime.getTime() + 300_000);
    const tvalue: any = {
      ID: id,
      AssertionID: idpSetting.generateID(),
      Destination: base,
      SubjectRecipient: base,
      Issuer: metadata.idp.getEntityID(),
      Audience: metadata.sp.getEntityID(),
      EntityID: metadata.sp.getEntityID(),
      IssueInstant: nowTime.toISOString(),
      AssertionConsumerServiceURL: base,
      StatusCode: namespace.statusCode.success,
      // can be customized
      ConditionsNotBefore: nowTime.toISOString(),
      ConditionsNotOnOrAfter: fiveMinutesLaterTime.toISOString(),
      SubjectConfirmationDataNotOnOrAfter: fiveMinutesLaterTime.toISOString(),
      NameIDFormat: selectedNameIDFormat,
      NameID: user.email || '',
      InResponseTo: get(requestInfo, 'extract.request.id', ''),
      AuthnStatement: '',
      AttributeStatement: '',
    };

    if (idpSetting.loginResponseTemplate && customTagReplacement) {
      const template = customTagReplacement(idpSetting.loginResponseTemplate.context);
      id = get(template, 'id', null);
      rawSamlResponse = get(template, 'context', null);
    } else {

      if (requestInfo !== null) {
        tvalue.InResponseTo = requestInfo.extract.request.id;
      }
      rawSamlResponse = libsaml.replaceTagsByValue(libsaml.defaultLoginResponseTemplate.context, tvalue);
    }

    const { privateKey, privateKeyPass, requestSignatureAlgorithm: signatureAlgorithm } = idpSetting;
    const config = {
      privateKey,
      privateKeyPass,
      signatureAlgorithm,
      signingCert: metadata.idp.getX509Certificate('signing'),
      isBase64Output: false,
    };
    // step: sign assertion ? -> encrypted ? -> sign message ?
    if (metadata.sp.isWantAssertionsSigned()) {
      rawSamlResponse = libsaml.constructSAMLSignature({
        ...config,
        rawSamlMessage: rawSamlResponse,
        transformationAlgorithms: spSetting.transformationAlgorithms,
        referenceTagXPath: "/*[local-name(.)='Response']/*[local-name(.)='Assertion']",
        signatureConfig: {
          prefix: 'ds',
          location: { reference: "/*[local-name(.)='Response']/*[local-name(.)='Assertion']/*[local-name(.)='Issuer']", action: 'after' },
        },
      });
    }

    // Like in post binding, SAML response is always signed
    return {
      id,
      context: buildRedirectURL({
        baseUrl: base,
        type: urlParams.samlResponse,
        isSigned: true,
        context: rawSamlResponse,
        entitySetting: idpSetting,
        relayState,
      }),
    };
  }
  throw new Error('ERR_GENERATE_REDIRECT_LOGIN_RESPONSE_MISSING_METADATA');
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
      if (requestInfo && requestInfo.extract && requestInfo.extract.request) {
        tvalue.InResponseTo = requestInfo.extract.request.id;
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
  loginResponseRedirectURL,
  logoutRequestRedirectURL,
  logoutResponseRedirectURL,
};

export default redirectBinding;
