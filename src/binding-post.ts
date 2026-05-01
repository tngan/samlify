/**
 * @file binding-post.ts
 * @author tngan
 * @desc Binding-level API for SAML HTTP-POST. Builds base64 login/logout
 * request and response payloads that callers embed in an auto-submitting
 * HTML form.
 */

import { wording, StatusCode } from './urn';
import type {
  BindingContext,
  RequestInfo,
  SAMLUser,
  TagReplacementMap,
} from './types';
import type { IdentityProvider as Idp } from './entity-idp';
import type { ServiceProvider as Sp } from './entity-sp';
import type Entity from './entity';
import libsaml from './libsaml';
import utility, { get } from './utility';

const binding = wording.binding;

/** Shape passed to builder functions that need both IdP and SP handles. */
interface PostIdpSpPair {
  idp: Idp;
  sp: Sp;
}

/** Shape passed to builder functions for logout (initiator + target). */
interface PostInitTargetPair {
  init: Entity;
  target: Entity;
}

/**
 * Generate a base64-encoded AuthnRequest for the HTTP-POST binding.
 *
 * @param referenceTagXPath XPath used when signing the request
 * @param entity `{ idp, sp }` handles
 * @param customTagReplacement optional custom template transformer
 * @param forceAuthn per-request `ForceAuthn` flag (saml-core §3.4.1)
 * @returns id / base64-XML pair
 */
function base64LoginRequest(
  referenceTagXPath: string,
  entity: PostIdpSpPair,
  customTagReplacement?: (template: string) => BindingContext,
  forceAuthn?: boolean,
): BindingContext {
  const metadata = { idp: entity.idp.entityMeta, sp: entity.sp.entityMeta };
  const spSetting = entity.sp.entitySetting;
  let id = '';

  /* v8 ignore start */
  if (!metadata.idp || !metadata.sp) {
    throw new Error('ERR_GENERATE_POST_LOGIN_REQUEST_MISSING_METADATA');
  }
  /* v8 ignore stop */

  const base = metadata.idp.getSingleSignOnService(binding.post);
  let rawSamlRequest: string;
  if (spSetting.loginRequestTemplate && customTagReplacement) {
    const info = customTagReplacement(spSetting.loginRequestTemplate.context!);
    id = get<string>(info as unknown as Record<string, unknown>, 'id') as string;
    rawSamlRequest = get<string>(info as unknown as Record<string, unknown>, 'context') as string;
  } else {
    const nameIDFormat = spSetting.nameIDFormat;
    const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;
    id = spSetting.generateID!();
    const tags: TagReplacementMap = {
      ID: id,
      Destination: base as string,
      Issuer: metadata.sp.getEntityID(),
      IssueInstant: new Date().toISOString(),
      AssertionConsumerServiceURL: metadata.sp.getAssertionConsumerService(binding.post) as string,
      EntityID: metadata.sp.getEntityID(),
      AllowCreate: spSetting.allowCreate,
      NameIDFormat: selectedNameIDFormat,
      // saml-core §3.4.1 — `replaceTagsByValue` drops the attribute when
      // `forceAuthn` is undefined, matching `use="optional"`.
      ForceAuthn: forceAuthn,
    };
    rawSamlRequest = libsaml.replaceTagsByValue(libsaml.defaultLoginRequestTemplate.context, tags);
  }
  if (metadata.idp.isWantAuthnRequestsSigned()) {
    const { privateKey, privateKeyPass, requestSignatureAlgorithm: signatureAlgorithm, transformationAlgorithms } = spSetting;
    return {
      id,
      context: libsaml.constructSAMLSignature({
        referenceTagXPath,
        privateKey: privateKey as string,
        privateKeyPass,
        signatureAlgorithm: signatureAlgorithm!,
        transformationAlgorithms,
        rawSamlMessage: rawSamlRequest,
        signingCert: metadata.sp.getX509Certificate('signing') as string,
        signatureConfig: spSetting.signatureConfig || {
          prefix: 'ds',
          location: { reference: "/*[local-name(.)='AuthnRequest']/*[local-name(.)='Issuer']", action: 'after' },
        },
      }),
    };
  }
  return {
    id,
    context: utility.base64Encode(rawSamlRequest),
  };
}

/**
 * Generate a base64-encoded login response for the HTTP-POST binding.
 * Supports the sign-then-encrypt and encrypt-then-sign pipelines based on
 * `encryptThenSign`.
 *
 * @param requestInfo parsed login request used to link `InResponseTo`
 * @param entity `{ idp, sp }` handles
 * @param user authenticated user
 * @param customTagReplacement optional custom template transformer
 * @param encryptThenSign when true, encrypt the assertion first then sign
 * @returns id / base64-XML pair
 */
async function base64LoginResponse(
  requestInfo: RequestInfo | { extract?: { request?: { id?: string } } } = {} as RequestInfo,
  entity: PostIdpSpPair,
  user: SAMLUser = {},
  customTagReplacement?: (template: string) => BindingContext,
  encryptThenSign = false,
): Promise<BindingContext> {
  const idpSetting = entity.idp.entitySetting;
  const spSetting = entity.sp.entitySetting;
  const id = idpSetting.generateID!();
  const metadata = {
    idp: entity.idp.entityMeta,
    sp: entity.sp.entityMeta,
  };
  const nameIDFormat = idpSetting.nameIDFormat;
  const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;

  /* v8 ignore start */
  if (!metadata.idp || !metadata.sp) {
    throw new Error('ERR_GENERATE_POST_LOGIN_RESPONSE_MISSING_METADATA');
  }
  /* v8 ignore stop */

  const base = metadata.sp.getAssertionConsumerService(binding.post);
  let rawSamlResponse: string;
  const nowTime = new Date();
  const spEntityID = metadata.sp.getEntityID();
  const fiveMinutesLaterTime = new Date(nowTime.getTime());
  fiveMinutesLaterTime.setMinutes(fiveMinutesLaterTime.getMinutes() + 5);
  const fiveMinutesLater = fiveMinutesLaterTime.toISOString();
  const now = nowTime.toISOString();
  const acl = metadata.sp.getAssertionConsumerService(binding.post);
  const tvalue: TagReplacementMap = {
    ID: id,
    AssertionID: idpSetting.generateID!(),
    Destination: base as string,
    Audience: spEntityID,
    EntityID: spEntityID,
    SubjectRecipient: acl as string,
    Issuer: metadata.idp.getEntityID(),
    IssueInstant: now,
    AssertionConsumerServiceURL: acl as string,
    StatusCode: StatusCode.Success,
    ConditionsNotBefore: now,
    ConditionsNotOnOrAfter: fiveMinutesLater,
    SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater,
    NameIDFormat: selectedNameIDFormat,
    NameID: user.email || '',
    InResponseTo: get<string>(requestInfo as Record<string, unknown>, 'extract.request.id', '') as string,
    AuthnStatement: '',
    AttributeStatement: '',
  };
  if (idpSetting.loginResponseTemplate && customTagReplacement) {
    const template = customTagReplacement(idpSetting.loginResponseTemplate.context!);
    rawSamlResponse = get<string>(template as unknown as Record<string, unknown>, 'context') as string;
  } else {
    if (requestInfo !== null && (requestInfo as RequestInfo).extract?.request) {
      tvalue.InResponseTo = (requestInfo as RequestInfo).extract.request!.id as string;
    }
    rawSamlResponse = libsaml.replaceTagsByValue(libsaml.defaultLoginResponseTemplate.context, tvalue);
  }
  const { privateKey, privateKeyPass, requestSignatureAlgorithm: signatureAlgorithm } = idpSetting;
  const config = {
    privateKey: privateKey as string,
    privateKeyPass,
    signatureAlgorithm: signatureAlgorithm!,
    signingCert: metadata.idp.getX509Certificate('signing') as string,
    isBase64Output: false,
  };
  // Order: sign assertion (if SP wants) → encrypt (if IdP wants) → sign message (if needed).
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

  if (!encryptThenSign && (spSetting.wantMessageSigned || !metadata.sp.isWantAssertionsSigned())) {
    rawSamlResponse = libsaml.constructSAMLSignature({
      ...config,
      rawSamlMessage: rawSamlResponse,
      isMessageSigned: true,
      transformationAlgorithms: spSetting.transformationAlgorithms,
      signatureConfig: spSetting.signatureConfig || {
        prefix: 'ds',
        location: { reference: "/*[local-name(.)='Response']/*[local-name(.)='Issuer']", action: 'after' },
      },
    });
  }

  if (idpSetting.isAssertionEncrypted) {
    const context = await libsaml.encryptAssertion(entity.idp, entity.sp, rawSamlResponse);
    if (encryptThenSign) {
      rawSamlResponse = utility.base64Decode(context) as string;
    } else {
      return Promise.resolve({ id, context });
    }
  }

  if (encryptThenSign && (spSetting.wantMessageSigned || !metadata.sp.isWantAssertionsSigned())) {
    rawSamlResponse = libsaml.constructSAMLSignature({
      ...config,
      rawSamlMessage: rawSamlResponse,
      isMessageSigned: true,
      transformationAlgorithms: spSetting.transformationAlgorithms,
      signatureConfig: spSetting.signatureConfig || {
        prefix: 'ds',
        location: { reference: "/*[local-name(.)='Response']/*[local-name(.)='Issuer']", action: 'after' },
      },
    });
  }

  return Promise.resolve({
    id,
    context: utility.base64Encode(rawSamlResponse),
  });
}

/**
 * Generate a base64-encoded LogoutRequest for the HTTP-POST binding.
 *
 * @param user currently authenticated user
 * @param referenceTagXPath XPath used when signing the request
 * @param entity `{ init, target }` handles
 * @param customTagReplacement optional custom template transformer
 * @returns id / base64-XML pair
 */
function base64LogoutRequest(
  user: SAMLUser,
  referenceTagXPath: string,
  entity: PostInitTargetPair,
  customTagReplacement?: (template: string) => BindingContext,
): BindingContext {
  const metadata = { init: entity.init.entityMeta, target: entity.target.entityMeta };
  const initSetting = entity.init.entitySetting;
  const nameIDFormat = initSetting.nameIDFormat;
  const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;
  let id = '';

  /* v8 ignore start */
  if (!metadata.init || !metadata.target) {
    throw new Error('ERR_GENERATE_POST_LOGOUT_REQUEST_MISSING_METADATA');
  }
  /* v8 ignore stop */

  let rawSamlRequest: string;
  if (initSetting.logoutRequestTemplate && customTagReplacement) {
    const template = customTagReplacement(initSetting.logoutRequestTemplate.context!);
    id = get<string>(template as unknown as Record<string, unknown>, 'id') as string;
    rawSamlRequest = get<string>(template as unknown as Record<string, unknown>, 'context') as string;
  } else {
    id = initSetting.generateID!();
    const tvalue: TagReplacementMap = {
      ID: id,
      Destination: metadata.target.getSingleLogoutService(binding.post) as string,
      Issuer: metadata.init.getEntityID(),
      IssueInstant: new Date().toISOString(),
      EntityID: metadata.init.getEntityID(),
      NameIDFormat: selectedNameIDFormat,
      NameID: user.logoutNameID,
      // saml-core §3.7.1 — SessionIndex is optional; replaceTagsByValue
      // drops the element when undefined (closes #470).
      SessionIndex: user.sessionIndex,
    };
    rawSamlRequest = libsaml.replaceTagsByValue(libsaml.defaultLogoutRequestTemplate.context, tvalue);
  }
  if (entity.target.entitySetting.wantLogoutRequestSigned) {
    const { privateKey, privateKeyPass, requestSignatureAlgorithm: signatureAlgorithm, transformationAlgorithms } = initSetting;
    return {
      id,
      context: libsaml.constructSAMLSignature({
        referenceTagXPath,
        privateKey: privateKey as string,
        privateKeyPass,
        signatureAlgorithm: signatureAlgorithm!,
        transformationAlgorithms,
        rawSamlMessage: rawSamlRequest,
        signingCert: metadata.init.getX509Certificate('signing') as string,
        signatureConfig: initSetting.signatureConfig || {
          prefix: 'ds',
          location: { reference: "/*[local-name(.)='LogoutRequest']/*[local-name(.)='Issuer']", action: 'after' },
        },
      }),
    };
  }
  return {
    id,
    context: utility.base64Encode(rawSamlRequest),
  };
}

/**
 * Generate a base64-encoded LogoutResponse for the HTTP-POST binding.
 *
 * @param requestInfo parsed request used to link `InResponseTo`
 * @param entity `{ init, target }` handles
 * @param customTagReplacement optional custom template transformer
 * @returns id / base64-XML pair
 */
function base64LogoutResponse(
  requestInfo: RequestInfo,
  entity: PostInitTargetPair,
  customTagReplacement?: (template: string) => BindingContext,
): BindingContext {
  const metadata = {
    init: entity.init.entityMeta,
    target: entity.target.entityMeta,
  };
  let id = '';
  const initSetting = entity.init.entitySetting;

  /* v8 ignore start */
  if (!metadata.init || !metadata.target) {
    throw new Error('ERR_GENERATE_POST_LOGOUT_RESPONSE_MISSING_METADATA');
  }
  /* v8 ignore stop */

  let rawSamlResponse: string;
  if (initSetting.logoutResponseTemplate && customTagReplacement) {
    const template = customTagReplacement(initSetting.logoutResponseTemplate.context!);
    id = template.id;
    rawSamlResponse = template.context;
  } else {
    id = initSetting.generateID!();
    const tvalue: TagReplacementMap = {
      ID: id,
      Destination: metadata.target.getSingleLogoutService(binding.post) as string,
      EntityID: metadata.init.getEntityID(),
      Issuer: metadata.init.getEntityID(),
      IssueInstant: new Date().toISOString(),
      StatusCode: StatusCode.Success,
      InResponseTo: get<string>(requestInfo as Record<string, unknown>, 'extract.request.id') as string,
    };
    rawSamlResponse = libsaml.replaceTagsByValue(libsaml.defaultLogoutResponseTemplate.context, tvalue);
  }
  if (entity.target.entitySetting.wantLogoutResponseSigned) {
    const { privateKey, privateKeyPass, requestSignatureAlgorithm: signatureAlgorithm, transformationAlgorithms } = initSetting;
    return {
      id,
      context: libsaml.constructSAMLSignature({
        isMessageSigned: true,
        transformationAlgorithms,
        privateKey: privateKey as string,
        privateKeyPass,
        signatureAlgorithm: signatureAlgorithm!,
        rawSamlMessage: rawSamlResponse,
        signingCert: metadata.init.getX509Certificate('signing') as string,
        signatureConfig: {
          prefix: 'ds',
          location: {
            reference: "/*[local-name(.)='LogoutResponse']/*[local-name(.)='Issuer']",
            action: 'after',
          },
        },
      }),
    };
  }
  return {
    id,
    context: utility.base64Encode(rawSamlResponse),
  };
}

const postBinding = {
  base64LoginRequest,
  base64LoginResponse,
  base64LogoutRequest,
  base64LogoutResponse,
};

export default postBinding;
