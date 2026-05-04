/**
 * @file binding-simplesign.ts
 * @author Orange
 * @desc Binding-level API for SAML HTTP-POST-SimpleSign. Produces base64
 * payloads alongside a detached signature over the canonical octet string.
 */

import { wording, StatusCode } from './urn';
import type {
  BindingContext,
  SimpleSignComputedContext,
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
const urlParams = wording.urlParams;

/** Options consumed by {@link buildSimpleSignature}. */
export interface BuildSimpleSignConfig {
  type: string;
  context: string;
  entitySetting: {
    requestSignatureAlgorithm?: string;
    privateKey?: string | Buffer;
    privateKeyPass?: string;
  };
  relayState?: string;
}

/** Return value for login-response building with simple signatures. */
export interface BindingSimpleSignContext {
  id: string;
  context: string;
  signature: string | Buffer;
  sigAlg: string;
}

/** `{ idp, sp }` handle used by simple-sign builders. */
interface SimpleSignIdpSpPair {
  idp: Idp;
  sp: Sp;
}

/** `{ init, target }` handle used by simple-sign logout builders. */
interface SimpleSignInitTargetPair {
  init: Entity;
  target: Entity;
}

/**
 * Build a `key=value` URL fragment prefixed with the correct separator.
 */
function pvPair(param: string, value: string, first?: boolean): string {
  return (first === true ? '?' : '&') + param + '=' + value;
}

/**
 * Compute a detached RSA signature over a SimpleSign canonical octet string.
 *
 * @param opts signing inputs
 * @returns base64-encoded signature
 */
function buildSimpleSignature(opts: BuildSimpleSignConfig): string {
  const { type, context, entitySetting } = opts;
  let { relayState = '' } = opts;
  const queryParam = libsaml.getQueryParamByType(type);

  if (relayState !== '') {
    relayState = pvPair(urlParams.relayState, relayState);
  }

  const sigAlg = pvPair(urlParams.sigAlg, entitySetting.requestSignatureAlgorithm!);
  const octetString = context + relayState + sigAlg;
  return libsaml.constructMessageSignature(
    queryParam + '=' + octetString,
    entitySetting.privateKey as string,
    entitySetting.privateKeyPass,
    undefined,
    entitySetting.requestSignatureAlgorithm,
  ).toString();
}

/**
 * Generate a base64-encoded AuthnRequest together with a detached simple
 * signature when the IdP advertises `WantAuthnRequestsSigned`.
 *
 * @param entity `{ idp, sp }` handles
 * @param customTagReplacement optional custom template transformer
 * @param relayState per-request RelayState; falls back to `entitySetting.relayState`
 * @param forceAuthn per-request `ForceAuthn` flag (saml-core §3.4.1)
 */
function base64LoginRequest(
  entity: SimpleSignIdpSpPair,
  customTagReplacement?: (template: string) => BindingContext,
  relayState?: string,
  forceAuthn?: boolean,
): SimpleSignComputedContext {
  const metadata = { idp: entity.idp.entityMeta, sp: entity.sp.entityMeta };
  const spSetting = entity.sp.entitySetting;
  let id = '';

  /* v8 ignore start */
  if (!metadata.idp || !metadata.sp) {
    throw new Error('ERR_GENERATE_POST_SIMPLESIGN_LOGIN_REQUEST_MISSING_METADATA');
  }
  /* v8 ignore stop */

  const base = metadata.idp.getSingleSignOnService(binding.simpleSign);
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
      AssertionConsumerServiceURL: metadata.sp.getAssertionConsumerService(binding.simpleSign) as string,
      EntityID: metadata.sp.getEntityID(),
      AllowCreate: spSetting.allowCreate,
      NameIDFormat: selectedNameIDFormat,
      // saml-core §3.4.1 — `replaceTagsByValue` drops the attribute when
      // `forceAuthn` is undefined, matching `use="optional"`.
      ForceAuthn: forceAuthn,
    };
    rawSamlRequest = libsaml.replaceTagsByValue(libsaml.defaultLoginRequestTemplate.context, tags);
  }

  let simpleSignatureContext: { signature: string; sigAlg: string } | null = null;
  if (metadata.idp.isWantAuthnRequestsSigned()) {
    const simpleSignature = buildSimpleSignature({
      type: urlParams.samlRequest,
      context: rawSamlRequest,
      entitySetting: spSetting,
      relayState: relayState ?? spSetting.relayState,
    });
    simpleSignatureContext = {
      signature: simpleSignature,
      sigAlg: spSetting.requestSignatureAlgorithm!,
    };
  }
  return {
    id,
    context: utility.base64Encode(rawSamlRequest),
    ...(simpleSignatureContext ?? {}),
  };
}

/**
 * Generate a base64-encoded login response together with a detached simple
 * signature. Login responses are always signed under this binding.
 *
 * @param requestInfo parsed request used to link `InResponseTo`
 * @param entity `{ idp, sp }` handles
 * @param user authenticated user
 * @param relayState caller-supplied redirect URL
 * @param customTagReplacement optional custom template transformer
 */
async function base64LoginResponse(
  requestInfo: RequestInfo | { extract?: { request?: { id?: string } } } = {} as RequestInfo,
  entity: SimpleSignIdpSpPair,
  user: SAMLUser = {},
  relayState?: string,
  customTagReplacement?: (template: string) => BindingContext,
): Promise<BindingSimpleSignContext> {
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
    throw new Error('ERR_GENERATE_POST_SIMPLESIGN_LOGIN_RESPONSE_MISSING_METADATA');
  }
  /* v8 ignore stop */

  const base = metadata.sp.getAssertionConsumerService(binding.simpleSign);
  let rawSamlResponse: string;
  const nowTime = new Date();
  const fiveMinutesLaterTime = new Date(nowTime.getTime() + 300_000);
  const tvalue: TagReplacementMap = {
    ID: id,
    AssertionID: idpSetting.generateID!(),
    Destination: base as string,
    Audience: metadata.sp.getEntityID(),
    EntityID: metadata.sp.getEntityID(),
    SubjectRecipient: base as string,
    Issuer: metadata.idp.getEntityID(),
    IssueInstant: nowTime.toISOString(),
    AssertionConsumerServiceURL: base as string,
    StatusCode: StatusCode.Success,
    ConditionsNotBefore: nowTime.toISOString(),
    ConditionsNotOnOrAfter: fiveMinutesLaterTime.toISOString(),
    SubjectConfirmationDataNotOnOrAfter: fiveMinutesLaterTime.toISOString(),
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
    // saml-core §1.4: prefer the IdP-rewritten default when tagPrefix is
    // overridden (closes #388); otherwise fall back to the library default.
    const baseTemplate = idpSetting.tagPrefixedDefaults?.loginResponseTemplate?.context
      ?? libsaml.defaultLoginResponseTemplate.context;
    rawSamlResponse = libsaml.replaceTagsByValue(baseTemplate, tvalue);
  }
  const { privateKey, privateKeyPass, requestSignatureAlgorithm: signatureAlgorithm } = idpSetting;
  const config = {
    privateKey: privateKey as string,
    privateKeyPass,
    signatureAlgorithm: signatureAlgorithm!,
    signingCert: metadata.idp.getX509Certificate('signing') as string,
    isBase64Output: false,
  };
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

  // Login response is always signed in the simple-sign binding.
  const simpleSignature = buildSimpleSignature({
    type: urlParams.samlResponse,
    context: rawSamlResponse,
    entitySetting: idpSetting,
    relayState,
  });

  return Promise.resolve({
    id,
    context: utility.base64Encode(rawSamlResponse),
    signature: simpleSignature,
    sigAlg: idpSetting.requestSignatureAlgorithm!,
  });
}

/**
 * Generate a base64-encoded LogoutRequest together with a detached simple
 * signature when the receiving entity requires signed logout requests.
 *
 * @param user currently authenticated user
 * @param entity `{ init, target }` handles
 * @param relayState caller-supplied redirect URL
 * @param customTagReplacement optional custom template transformer
 */
function base64LogoutRequest(
  user: SAMLUser,
  entity: SimpleSignInitTargetPair,
  relayState?: string,
  customTagReplacement?: (template: string) => BindingContext,
): SimpleSignComputedContext {
  const metadata = { init: entity.init.entityMeta, target: entity.target.entityMeta };
  const initSetting = entity.init.entitySetting;
  const nameIDFormat = initSetting.nameIDFormat;
  const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;
  let id = '';

  /* v8 ignore start */
  if (!metadata.init || !metadata.target) {
    throw new Error('ERR_GENERATE_POST_SIMPLESIGN_LOGOUT_REQUEST_MISSING_METADATA');
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
      Destination: metadata.target.getSingleLogoutService(binding.simpleSign) as string,
      Issuer: metadata.init.getEntityID(),
      IssueInstant: new Date().toISOString(),
      EntityID: metadata.init.getEntityID(),
      NameIDFormat: selectedNameIDFormat,
      NameID: user.logoutNameID,
      // saml-core §3.7.1 — SessionIndex is optional; replaceTagsByValue
      // drops the element when undefined (closes #470).
      SessionIndex: user.sessionIndex,
    };
    const baseTemplate = initSetting.tagPrefixedDefaults?.logoutRequestTemplate?.context
      ?? libsaml.defaultLogoutRequestTemplate.context;
    rawSamlRequest = libsaml.replaceTagsByValue(baseTemplate, tvalue);
  }

  let simpleSignatureContext: { signature: string; sigAlg: string } | null = null;
  if (entity.target.entitySetting.wantLogoutRequestSigned) {
    const simpleSignature = buildSimpleSignature({
      type: urlParams.logoutRequest,
      context: rawSamlRequest,
      entitySetting: initSetting,
      relayState,
    });
    simpleSignatureContext = {
      signature: simpleSignature,
      sigAlg: initSetting.requestSignatureAlgorithm!,
    };
  }
  return {
    id,
    context: utility.base64Encode(rawSamlRequest),
    ...(simpleSignatureContext ?? {}),
  };
}

/**
 * Generate a base64-encoded LogoutResponse together with a detached simple
 * signature when the receiving entity requires signed logout responses.
 *
 * @param requestInfo parsed request used to link `InResponseTo`
 * @param entity `{ init, target }` handles
 * @param relayState caller-supplied redirect URL
 * @param customTagReplacement optional custom template transformer
 */
function base64LogoutResponse(
  requestInfo: RequestInfo,
  entity: SimpleSignInitTargetPair,
  relayState?: string,
  customTagReplacement?: (template: string) => BindingContext,
): SimpleSignComputedContext {
  const metadata = { init: entity.init.entityMeta, target: entity.target.entityMeta };
  const initSetting = entity.init.entitySetting;
  let id = '';

  /* v8 ignore start */
  if (!metadata.init || !metadata.target) {
    throw new Error('ERR_GENERATE_POST_SIMPLESIGN_LOGOUT_RESPONSE_MISSING_METADATA');
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
      Destination: metadata.target.getSingleLogoutService(binding.simpleSign) as string,
      EntityID: metadata.init.getEntityID(),
      Issuer: metadata.init.getEntityID(),
      IssueInstant: new Date().toISOString(),
      StatusCode: StatusCode.Success,
      InResponseTo: get<string>(requestInfo as Record<string, unknown>, 'extract.request.id') as string,
    };
    const baseTemplate = initSetting.tagPrefixedDefaults?.logoutResponseTemplate?.context
      ?? libsaml.defaultLogoutResponseTemplate.context;
    rawSamlResponse = libsaml.replaceTagsByValue(baseTemplate, tvalue);
  }

  let simpleSignatureContext: { signature: string; sigAlg: string } | null = null;
  if (entity.target.entitySetting.wantLogoutResponseSigned) {
    const simpleSignature = buildSimpleSignature({
      type: urlParams.logoutResponse,
      context: rawSamlResponse,
      entitySetting: initSetting,
      relayState,
    });
    simpleSignatureContext = {
      signature: simpleSignature,
      sigAlg: initSetting.requestSignatureAlgorithm!,
    };
  }
  return {
    id,
    context: utility.base64Encode(rawSamlResponse),
    ...(simpleSignatureContext ?? {}),
  };
}

const simpleSignBinding = {
  base64LoginRequest,
  base64LoginResponse,
  base64LogoutRequest,
  base64LogoutResponse,
};

export default simpleSignBinding;
