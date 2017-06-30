/**
* @file binding-post.ts
* @author tngan
* @desc Binding-level API, declare the functions using POST binding
*/

import { wording, tags, namespace } from './urn';
import { BindingContext } from './entity';
import libsaml from './libsaml';
import utility from './utility';
import { get } from 'lodash';

const xmlTag = tags.xmlTag;
const binding = wording.binding;

/**
* @desc Generate a base64 encoded login request
* @param  {string} referenceTagXPath           reference uri
* @param  {object} entity                      object includes both idp and sp
* @param  {function} customTagReplacement     used when developers have their own login response template
*/
function base64LoginRequest(referenceTagXPath: string, entity: any, customTagReplacement: (template: string) => BindingContext): BindingContext {
  const metadata = { idp: entity.idp.entityMeta, sp: entity.sp.entityMeta };
  const spSetting = entity.sp.entitySetting;
  let id: string = '';

  if (metadata && metadata.idp && metadata.sp) {
    const base = metadata.idp.getSingleSignOnService(binding.post);
    let rawSamlRequest;
    if (spSetting.loginRequestTemplate) {
      const info = customTagReplacement(spSetting.loginRequestTemplate.context);
      id = get<string>(info, 'id');
      rawSamlRequest = get<string>(info, 'context');
    } else {
      id = spSetting.generateID();
      rawSamlRequest = libsaml.replaceTagsByValue(libsaml.defaultLoginRequestTemplate.context, {
        ID: id,
        Destination: base,
        Issuer: metadata.sp.getEntityID(),
        IssueInstant: new Date().toISOString(),
        AssertionConsumerServiceURL: metadata.sp.getAssertionConsumerService(binding.post),
        EntityID: metadata.sp.getEntityID(),
        AllowCreate: spSetting.allowCreate,
        NameIDFormat: namespace.format[spSetting.logoutNameIDFormat] || namespace.format.emailAddress,
      } as any);
    }
    if (metadata.idp.isWantAuthnRequestsSigned()) {
      const { privateKey, privateKeyPass, requestSignatureAlgorithm: signatureAlgorithm } = spSetting;
      return {
        id,
        context: libsaml.constructSAMLSignature({
          referenceTagXPath,
          privateKey,
          privateKeyPass,
          signatureAlgorithm,
          rawSamlMessage: rawSamlRequest,
          signingCert: metadata.sp.getX509Certificate('signing'),
        }),
      };
    }
    // No need to embeded XML signature
    return {
      id,
      context: utility.base64Encode(rawSamlRequest),
    };
  }
  throw new Error('missing declaration of metadata');
}
/**
* @desc Generate a base64 encoded login response
* @param  {object} requestInfo                 corresponding request, used to obtain the id
* @param  {object} entity                      object includes both idp and sp
* @param  {object} user                        current logged user (e.g. req.user)
* @param  {function} customTagReplacement     used when developers have their own login response template
* @param  {boolean}  encryptThenSign           whether or not to encrypt then sign first (if signing). Defaults to sign-then-encrypt
*/
async function base64LoginResponse(requestInfo: any, entity: any, user: any = {}, customTagReplacement: (template: string) => BindingContext, encryptThenSign: boolean = false): Promise<BindingContext> {
  const idpSetting = entity.idp.entitySetting;
  const spSetting = entity.sp.entitySetting;
  let id = idpSetting.generateID();
  const metadata = {
    idp: entity.idp.entityMeta,
    sp: entity.sp.entityMeta,
  };
  if (metadata && metadata.idp && metadata.sp) {
    const base = metadata.sp.getAssertionConsumerService(binding.post);
    let rawSamlResponse;
    const nowTime = new Date();
    const spEntityID = metadata.sp.getEntityID();
    const fiveMinutesLaterTime = new Date(nowTime.getTime());
    fiveMinutesLaterTime.setMinutes(fiveMinutesLaterTime.getMinutes() + 5);
    const fiveMinutesLater = fiveMinutesLaterTime.toISOString();
    const now = nowTime.toISOString();
    const acl = metadata.sp.getAssertionConsumerService(binding.post);
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
      StatusCode: namespace.statusCode.success,
      // can be customized
      ConditionsNotBefore: now,
      ConditionsNotOnOrAfter: fiveMinutesLater,
      SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater,
      NameIDFormat: namespace.format[idpSetting.logoutNameIDFormat] || namespace.format.emailAddress,
      NameID: user.email || '',
      AuthnStatement: '',
      AttributeStatement: '',
    };
    if (idpSetting.loginResponseTemplate) {
      const template = customTagReplacement(idpSetting.loginResponseTemplate.context);
      id = get<string>(template, 'id');
      rawSamlResponse = get<string>(template, 'context');
    } else {
      if (requestInfo !== null) {
        tvalue.InResponseTo = requestInfo.extract.authnrequest.id;
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

    // SAML response must be signed sign message first, then encrypt
    if (!encryptThenSign && (spSetting.wantMessageSigned || !metadata.sp.isWantAssertionsSigned())) {
      rawSamlResponse = libsaml.constructSAMLSignature({
        ...config,
        rawSamlMessage: rawSamlResponse,
        isMessageSigned: true,
        signatureConfig: spSetting.signatureConfig || {
          prefix: 'ds',
          location: { reference: '/samlp:Response/saml:Issuer', action: 'after' },
        },
      });
    }

    // step: sign assertion ? -> encrypted ? -> sign message ?
    if (metadata.sp.isWantAssertionsSigned()) {
      rawSamlResponse = libsaml.constructSAMLSignature({
        ...config,
        rawSamlMessage: rawSamlResponse,
        referenceTagXPath: '/samlp:Response/saml:Assertion', // libsaml.createXPath('Assertion'),
        signatureConfig: {
          prefix: 'ds',
          location: { reference: '/samlp:Response/saml:Assertion/saml:Issuer', action: 'after' },
        },
      });
    }

    if (idpSetting.isAssertionEncrypted) {
      const context = await libsaml.encryptAssertion(entity.idp, entity.sp, rawSamlResponse);
      if (encryptThenSign) {
        //need to decode it
        rawSamlResponse = utility.base64Decode(context);
      } else {
        return Promise.resolve({ id, context });
      }
    }

    //sign after encrypting
    if (encryptThenSign && (spSetting.wantMessageSigned || !metadata.sp.isWantAssertionsSigned())) {
      rawSamlResponse = libsaml.constructSAMLSignature({
        ...config,
        rawSamlMessage: rawSamlResponse,
        isMessageSigned: true,
        signatureConfig: spSetting.signatureConfig || {
          prefix: 'ds',
          location: { reference: '/samlp:Response/saml:Issuer', action: 'after' },
        },
      });
    }

    return Promise.resolve({
      id,
      context: utility.base64Encode(rawSamlResponse),
    });

  }
  throw new Error('Missing declaration of metadata');
}
/**
* @desc Generate a base64 encoded logout request
* @param  {object} user                         current logged user (e.g. req.user)
* @param  {string} referenceTagXPath            reference uri
* @param  {object} entity                       object includes both idp and sp
* @param  {function} customTagReplacement      used when developers have their own login response template
* @return {string} base64 encoded request
*/
function base64LogoutRequest(user, referenceTagXPath, entity, customTagReplacement?: (template: string) => BindingContext): BindingContext {
  const metadata = { init: entity.init.entityMeta, target: entity.target.entityMeta };
  const initSetting = entity.init.entitySetting;
  let id: string = '';
  if (metadata && metadata.init && metadata.target) {
    let rawSamlRequest;
    if (initSetting.loginRequestTemplate) {
      const template = customTagReplacement(initSetting.loginRequestTemplate.context);
      id = get<string>(template, 'id');
      rawSamlRequest = get<string>(template, 'context');
    } else {
      id = initSetting.generateID();
      const tvalue: any = {
        ID: id,
        Destination: metadata.target.getSingleLogoutService(binding.redirect),
        Issuer: metadata.init.getEntityID(),
        IssueInstant: new Date().toISOString(),
        EntityID: metadata.init.getEntityID(),
        NameIDFormat: namespace.format[initSetting.logoutNameIDFormat] || namespace.format.transient,
        NameID: user.logoutNameID,
      };
      rawSamlRequest = libsaml.replaceTagsByValue(libsaml.defaultLogoutRequestTemplate.context, tvalue);
    }
    if (entity.target.entitySetting.wantLogoutRequestSigned) {
      // Need to embeded XML signature
      const { privateKey, privateKeyPass, requestSignatureAlgorithm: signatureAlgorithm } = initSetting;
      return {
        id,
        context: libsaml.constructSAMLSignature({
          referenceTagXPath,
          privateKey,
          privateKeyPass,
          signatureAlgorithm,
          rawSamlMessage: rawSamlRequest,
          signingCert: metadata.init.getX509Certificate('signing'),
        }),
      };
    }
    return {
      id,
      context: utility.base64Encode(rawSamlRequest),
    };
  }
  throw new Error('Missing declaration of metadata');
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
        StatusCode: namespace.statusCode.success,
      };
      if (requestInfo && requestInfo.extract && requestInfo.extract.logoutrequest) {
        tvalue.InResponseTo = requestInfo.extract.logoutrequest.id;
      }
      rawSamlResponse = libsaml.replaceTagsByValue(libsaml.defaultLogoutResponseTemplate.context, tvalue);
    }
    if (entity.target.entitySetting.wantLogoutResponseSigned) {
      const { privateKey, privateKeyPass, requestSignatureAlgorithm: signatureAlgorithm } = initSetting;
      return {
        id,
        context: libsaml.constructSAMLSignature({
          referenceTagXPath: libsaml.createXPath('Issuer'),
          privateKey,
          privateKeyPass,
          signatureAlgorithm,
          rawSamlMessage: rawSamlResponse,
          signingCert: metadata.init.getX509Certificate('signing'),
        }),
      };
    }
    return {
      id,
      context: utility.base64Encode(rawSamlResponse),
    };
  }
  throw new Error('Missing declaration of metadata');
}

const postBinding = {
  base64LoginRequest,
  base64LoginResponse,
  base64LogoutRequest,
  base64LogoutResponse,
};

export default postBinding;
