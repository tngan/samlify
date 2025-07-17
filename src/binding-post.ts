/**
 * @file binding-post.ts
 * @author tngan
 * @desc Binding-level API, declare the functions using POST binding
 */

import {wording, namespace, StatusCode} from './urn.js';
import type {BindingContext} from './entity.js';
import libsaml from './libsaml.js';
import utility, {get} from './utility.js';
import {
  IdentityProviderConstructor as IdentityProvider,
  ServiceProviderConstructor as ServiceProvider
} from "./types.js";
import {extract, ExtractorFields} from "./extractor.js";


const binding = wording.binding;

/**
 * @desc Generate a base64 encoded login request
 * @param  {string} referenceTagXPath           reference uri
 * @param  {object} entity                      object includes both idp and sp
 * @param  {function} customTagReplacement     used when developers have their own login response template
 */
function base64LoginRequest(referenceTagXPath: string, entity: any, customTagReplacement?: (template: string) => BindingContext): BindingContext {
  const metadata = {idp: entity.idp.entityMeta, sp: entity.sp.entityMeta};
  const spSetting = entity.sp.entitySetting;
  let id: string = '';

  if (metadata && metadata.idp && metadata.sp) {
    const base = metadata.idp.getSingleSignOnService(binding.post);
    let rawSamlRequest: string;
    if (spSetting.loginRequestTemplate && customTagReplacement) {
      const info = customTagReplacement(spSetting.loginRequestTemplate.context);
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
        AssertionConsumerServiceURL: metadata.sp.getAssertionConsumerService(binding.post),
        EntityID: metadata.sp.getEntityID(),
        AllowCreate: spSetting.allowCreate,
        NameIDFormat: selectedNameIDFormat
      } as any);
    }

    if (metadata.idp.isWantAuthnRequestsSigned()) {
      const {
        privateKey,
        privateKeyPass,
        requestSignatureAlgorithm: signatureAlgorithm,
        transformationAlgorithms
      } = spSetting;
      return {
        id,
        context: libsaml.constructSAMLSignature({
          referenceTagXPath,
          privateKey,
          privateKeyPass,
          signatureAlgorithm,
          transformationAlgorithms,
          rawSamlMessage: rawSamlRequest,
          signingCert: metadata.sp.getX509Certificate('signing'),
          signatureConfig: spSetting.signatureConfig || {
            prefix: 'ds',
            location: {reference: "/*[local-name(.)='AuthnRequest']/*[local-name(.)='Issuer']", action: 'after'},
          }
        }),
      };
    }
    // No need to embeded XML signature

    return {
      id,
      context: utility.base64Encode(rawSamlRequest),
    };
  }
  throw new Error('ERR_GENERATE_POST_LOGIN_REQUEST_MISSING_METADATA');
}



/**
 * @desc Generate a base64 encoded login response
 * @param  {object} requestInfo                 corresponding request, used to obtain the id
 * @param  {object} entity                      object includes both idp and sp
 * @param  {object} user                        current logged user (e.g. req.user)
 * @param  {function} customTagReplacement     used when developers have their own login response template
 * @param  {boolean}  encryptThenSign           whether or not to encrypt then sign first (if signing). Defaults to sign-then-encrypt
 * @param AttributeStatement
 */
async function base64LoginResponse(requestInfo: any = {}, entity: any, user: any = {}, customTagReplacement?: (template: string) => BindingContext, encryptThenSign: boolean = false, AttributeStatement = []): Promise<BindingContext> {
  const idpSetting = entity.idp.entitySetting;
  const spSetting = entity.sp.entitySetting;
  const id = idpSetting.generateID();
  const metadata = {
    idp: entity.idp.entityMeta,
    sp: entity.sp.entityMeta,
  };
  const nameIDFormat = idpSetting.nameIDFormat;
  const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;


  if (metadata && metadata.idp && metadata.sp) {
    const base = metadata.sp.getAssertionConsumerService(binding.post);
    let rawSamlResponse;
    const nowTime = new Date();
    const spEntityID = metadata.sp.getEntityID();
    const oneMinutesLaterTime = new Date(nowTime.getTime());
    oneMinutesLaterTime.setMinutes(oneMinutesLaterTime.getMinutes() + 5);
    const OneMinutesLater = oneMinutesLaterTime.toISOString();
    const now = nowTime.toISOString();
    const acl = metadata.sp.getAssertionConsumerService(binding.post);
    const sessionIndex = 'session' + idpSetting.generateID(); // 这个是当前系统的会话索引，用于单点注销
    const tenHoursLaterTime = new Date(nowTime.getTime());
    tenHoursLaterTime.setHours(tenHoursLaterTime.getHours() + 10);
    const tenHoursLater = tenHoursLaterTime.toISOString();
    const tvalue: any = {
      ID: id,
      AssertionID: idpSetting.generateID(),
      Destination: base,
      Audience: spEntityID,
      EntityID: spEntityID,
      SubjectRecipient: acl,
      Issuer: metadata.idp.getEntityID(),
      IssueInstant: now,
      AssertionConsumerServiceURL: acl,
      StatusCode: StatusCode.Success,
      // can be customized
      ConditionsNotBefore: now,
      ConditionsNotOnOrAfter: OneMinutesLater,
      SubjectConfirmationDataNotOnOrAfter: OneMinutesLater,
      NameIDFormat: selectedNameIDFormat,
      NameID: user?.NameID || '',
      InResponseTo: get(requestInfo, 'extract.request.id', ''),
      AuthnStatement: `<saml:AuthnStatement AuthnInstant="${now}" SessionNotOnOrAfter="${tenHoursLater}" SessionIndex="${sessionIndex}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`,
      AttributeStatement: libsaml.attributeStatementBuilder(AttributeStatement),
    };
    if (idpSetting.loginResponseTemplate && customTagReplacement) {
      const template = customTagReplacement(idpSetting.loginResponseTemplate.context)
      rawSamlResponse = get(template, 'context', null);
    } else {
      if (requestInfo !== null) {
        tvalue.InResponseTo = requestInfo?.extract?.request?.id ?? '';
      }
      rawSamlResponse = libsaml.replaceTagsByValue(libsaml.defaultLoginResponseTemplate.context, tvalue);

    }
    const {privateKey, privateKeyPass, requestSignatureAlgorithm: signatureAlgorithm} = idpSetting;
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
          location: {
            reference: "/*[local-name(.)='Response']/*[local-name(.)='Assertion']/*[local-name(.)='Issuer']",
            action: 'after'
          },
        },
      });
    }

    // console.debug('after assertion signed', rawSamlResponse);

    // SAML response must be signed sign message first, then encrypt
    if (!encryptThenSign && (spSetting.wantMessageSigned || !metadata.sp.isWantAssertionsSigned())) {
      // console.debug('sign then encrypt and sign entire message');
      rawSamlResponse = libsaml.constructSAMLSignature({
        ...config,
        rawSamlMessage: rawSamlResponse,
        isMessageSigned: true,
        transformationAlgorithms: spSetting.transformationAlgorithms,
        signatureConfig: spSetting.signatureConfig || {
          prefix: 'ds',
          location: {reference: "/*[local-name(.)='Response']/*[local-name(.)='Issuer']", action: 'after'},
        },
      });
    }

/*    if (spSetting.wantMessageSigned) {
      // console.debug('sign then encrypt and sign entire message');
      rawSamlResponse = libsaml.constructSAMLSignature({
        ...config,
        rawSamlMessage: rawSamlResponse,
        isMessageSigned: true,
        transformationAlgorithms: spSetting.transformationAlgorithms,
        signatureConfig: spSetting.signatureConfig || {
          prefix: 'ds',
          location: {reference: "/!*[local-name(.)='Response']/!*[local-name(.)='Issuer']", action: 'after'},
        },
      });
    }*/

    if (idpSetting.isAssertionEncrypted) {
      // console.debug('idp is configured to do encryption');
      const context = await libsaml.encryptAssertion(entity.idp, entity.sp, rawSamlResponse);
      if (encryptThenSign) {
        //need to decode it
        rawSamlResponse = utility.base64Decode(context) as string;
      } else {
        return Promise.resolve({id, context});
      }
    }

    //sign after encrypting
/*    if (encryptThenSign && (spSetting.wantMessageSigned || !metadata.sp.isWantAssertionsSigned())) {
      rawSamlResponse = libsaml.constructSAMLSignature({
        ...config,
        rawSamlMessage: rawSamlResponse,
        isMessageSigned: true,
        transformationAlgorithms: spSetting.transformationAlgorithms,
        signatureConfig: spSetting.signatureConfig || {
          prefix: 'ds',
          location: {reference: "/!*[local-name(.)='Response']/!*[local-name(.)='Issuer']", action: 'after'},
        },
      });
    }*/
    return Promise.resolve({
      id,
      context: utility.base64Encode(rawSamlResponse),
    });

  }


  throw new Error('ERR_GENERATE_POST_LOGIN_RESPONSE_MISSING_METADATA');
}

/**
 * @desc Generate a base64 encoded logout request
 * @param  {object} user                         current logged user (e.g. req.user)
 * @param  {string} referenceTagXPath            reference uri
 * @param  {object} entity                       object includes both idp and sp
 * @param  {function} customTagReplacement      used when developers have their own login response template
 * @return {string} base64 encoded request
 */
function base64LogoutRequest(user: Record<string, unknown>, referenceTagXPath: string, entity, customTagReplacement?: (template: string) => BindingContext): BindingContext {
  const metadata = {init: entity.init.entityMeta, target: entity.target.entityMeta};
  const initSetting = entity.init.entitySetting;
  const nameIDFormat = initSetting.nameIDFormat;
  const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;
  let id: string = '';
  if (metadata && metadata.init && metadata.target) {
    let rawSamlRequest: string;
    if (initSetting.logoutRequestTemplate && customTagReplacement) {
      const template = customTagReplacement(initSetting.logoutRequestTemplate.context);
      id = get(template, 'id', null);
      rawSamlRequest = get(template, 'context', null);
    } else {
      id = initSetting.generateID();
      const tvalue: any = {
        ID: id,
        Destination: metadata.target.getSingleLogoutService(binding.post),
        Issuer: metadata.init.getEntityID(),
        IssueInstant: new Date().toISOString(),
        EntityID: metadata.init.getEntityID(),
        NameIDFormat: selectedNameIDFormat,
        NameID: user.NameID || '',
      };
      rawSamlRequest = libsaml.replaceTagsByValue(libsaml.defaultLogoutRequestTemplate.context, tvalue);
    }
    if (entity.target.entitySetting.wantLogoutRequestSigned) {
      // Need to embeded XML signature
      const {
        privateKey,
        privateKeyPass,
        requestSignatureAlgorithm: signatureAlgorithm,
        transformationAlgorithms
      } = initSetting;
      return {
        id,
        context: libsaml.constructSAMLSignature({
          referenceTagXPath,
          privateKey,
          privateKeyPass,
          signatureAlgorithm,
          transformationAlgorithms,
          rawSamlMessage: rawSamlRequest,
          signingCert: metadata.init.getX509Certificate('signing'),
          signatureConfig: initSetting.signatureConfig || {
            prefix: 'ds',
            location: {reference: "/*[local-name(.)='LogoutRequest']/*[local-name(.)='Issuer']", action: 'after'},
          }
        }),
      };
    }
    return {
      id,
      context: utility.base64Encode(rawSamlRequest),
    };
  }
  throw new Error('ERR_GENERATE_POST_LOGOUT_REQUEST_MISSING_METADATA');
}

/**
 * @desc Generate a base64 encoded logout response
 * @param  {object} requestInfo                 corresponding request, used to obtain the id
 * @param  {string} referenceTagXPath           reference uri
 * @param  {object} entity                      object includes both idp and sp
 * @param  {function} customTagReplacement     used when developers have their own login response template
 */
function base64LogoutResponse(requestInfo: any, entity: any, customTagReplacement: (template: string) => BindingContext): BindingContext {
  const metadata = {
    init: entity.init.entityMeta,
    target: entity.target.entityMeta,
  };
  let id: string = '';
  const initSetting = entity.init.entitySetting;
  if (metadata && metadata.init && metadata.target) {
    let rawSamlResponse;
    if (initSetting.logoutResponseTemplate) {
      const template = customTagReplacement(initSetting.logoutResponseTemplate.context);
      id = template.id;
      rawSamlResponse = template.context;
    } else {
      id = initSetting.generateID();
      const tvalue: any = {
        ID: id,
        Destination: metadata.target.getSingleLogoutService(binding.post),
        EntityID: metadata.init.getEntityID(),
        Issuer: metadata.init.getEntityID(),
        IssueInstant: new Date().toISOString(),
        StatusCode: StatusCode.Success,
        InResponseTo: get(requestInfo, 'extract.request.id', '')
      };
      rawSamlResponse = libsaml.replaceTagsByValue(libsaml.defaultLogoutResponseTemplate.context, tvalue);
    }
    if (entity.target.entitySetting.wantLogoutResponseSigned) {
      const {
        privateKey,
        privateKeyPass,
        requestSignatureAlgorithm: signatureAlgorithm,
        transformationAlgorithms
      } = initSetting;
      return {
        id,
        context: libsaml.constructSAMLSignature({
          isMessageSigned: true,
          transformationAlgorithms: transformationAlgorithms,
          privateKey,
          privateKeyPass,
          signatureAlgorithm,
          rawSamlMessage: rawSamlResponse,
          signingCert: metadata.init.getX509Certificate('signing'),
          signatureConfig: {
            prefix: 'ds',
            location: {
              reference: "/*[local-name(.)='LogoutResponse']/*[local-name(.)='Issuer']",
              action: 'after'
            }
          }
        }),
      };
    }
    return {
      id,
      context: utility.base64Encode(rawSamlResponse),
    };
  }
  throw new Error('ERR_GENERATE_POST_LOGOUT_RESPONSE_MISSING_METADATA');
}

const postBinding = {
  base64LoginRequest,
  base64LoginResponse,
  base64LogoutRequest,
  base64LogoutResponse,
};

export default postBinding;
