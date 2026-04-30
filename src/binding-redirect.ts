/**
 * @file binding-redirect.ts
 * @author tngan
 * @desc Binding-level API for SAML HTTP-Redirect. Builds signed/unsigned
 * redirect URLs for login/logout requests and responses.
 */
import utility, { get } from './utility';
import libsaml from './libsaml';
import type {
  BindingContext,
  RequestInfo,
  SAMLUser,
  TagReplacementMap,
} from './types';
import type { IdentityProvider as Idp } from './entity-idp';
import type { ServiceProvider as Sp } from './entity-sp';
import type Entity from './entity';
import * as url from 'url';
import { wording, namespace } from './urn';

const binding = wording.binding;
const urlParams = wording.urlParams;

/** Options consumed by {@link buildRedirectURL}. */
export interface BuildRedirectConfig {
  baseUrl: string;
  type: string;
  isSigned: boolean;
  context: string;
  entitySetting: {
    requestSignatureAlgorithm?: string;
    privateKey?: string | Buffer;
    privateKeyPass?: string;
  };
  relayState?: string;
}

/** Initiator/target entity pair used for logout redirects. */
interface RedirectInitTargetPair {
  init: Entity;
  target: Entity;
}

/**
 * Build a `key=value` URL fragment prefixed with the correct separator.
 *
 * @param param key name
 * @param value key value
 * @param first when true, use `?` instead of `&`
 */
function pvPair(param: string, value: string, first?: boolean): string {
  return (first === true ? '?' : '&') + param + '=' + value;
}

/**
 * Compose the final redirect URL, deflate/base64/urlencode the SAML message,
 * optionally append the detached signature.
 *
 * @param opts redirect configuration
 * @returns absolute redirect URL
 */
function buildRedirectURL(opts: BuildRedirectConfig): string {
  const { baseUrl, type, isSigned, context, entitySetting } = opts;
  let { relayState = '' } = opts;
  const noParams = (url.parse(baseUrl).query || []).length === 0;
  const queryParam = libsaml.getQueryParamByType(type);
  // SAML redirect binding: deflate → base64 → URL-encode.
  const samlRequest = encodeURIComponent(utility.base64Encode(utility.deflateString(context)));
  if (relayState !== '') {
    relayState = pvPair(urlParams.relayState, encodeURIComponent(relayState));
  }
  if (isSigned) {
    const sigAlg = pvPair(urlParams.sigAlg, encodeURIComponent(entitySetting.requestSignatureAlgorithm!));
    const octetString = samlRequest + relayState + sigAlg;
    return baseUrl
      + pvPair(queryParam, octetString, noParams)
      + pvPair(urlParams.signature, encodeURIComponent(
        libsaml.constructMessageSignature(
          queryParam + '=' + octetString,
          entitySetting.privateKey as string,
          entitySetting.privateKeyPass,
          undefined,
          entitySetting.requestSignatureAlgorithm,
        ).toString(),
      ));
  }
  return baseUrl + pvPair(queryParam, samlRequest + relayState, noParams);
}

/**
 * Build a redirect URL carrying a SAML AuthnRequest.
 *
 * @param entity `{ idp, sp }` handles
 * @param customTagReplacement optional custom template transformer
 * @param relayState per-request RelayState; falls back to `entitySetting.relayState`
 * @returns id + redirect URL wrapped in a {@link BindingContext}
 */
function loginRequestRedirectURL(
  entity: { idp: Idp; sp: Sp },
  customTagReplacement?: (template: string) => BindingContext,
  relayState?: string,
): BindingContext {
  const metadata = { idp: entity.idp.entityMeta, sp: entity.sp.entityMeta };
  const spSetting = entity.sp.entitySetting;
  let id = '';

  /* v8 ignore start */
  if (!metadata.idp || !metadata.sp) {
    throw new Error('ERR_GENERATE_REDIRECT_LOGIN_REQUEST_MISSING_METADATA');
  }
  /* v8 ignore stop */

  const base = metadata.idp.getSingleSignOnService(binding.redirect);
  let rawSamlRequest: string;
  if (spSetting.loginRequestTemplate && customTagReplacement) {
    const info = customTagReplacement(spSetting.loginRequestTemplate as unknown as string);
    id = get<string>(info as unknown as Record<string, unknown>, 'id') as string;
    rawSamlRequest = get<string>(info as unknown as Record<string, unknown>, 'context') as string;
    // Support callback returning { context: string } or { context: { context: string } }.
    if (typeof rawSamlRequest === 'object' && rawSamlRequest !== null && 'context' in (rawSamlRequest as object)) {
      rawSamlRequest = (rawSamlRequest as { context: string }).context;
    }
  } else {
    const nameIDFormat = spSetting.nameIDFormat;
    const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;
    id = spSetting.generateID!();
    const tags: TagReplacementMap = {
      ID: id,
      Destination: base as string,
      Issuer: metadata.sp.getEntityID(),
      IssueInstant: new Date().toISOString(),
      NameIDFormat: selectedNameIDFormat,
      AssertionConsumerServiceURL: metadata.sp.getAssertionConsumerService(binding.post) as string,
      EntityID: metadata.sp.getEntityID(),
      AllowCreate: spSetting.allowCreate,
    };
    rawSamlRequest = libsaml.replaceTagsByValue(libsaml.defaultLoginRequestTemplate.context, tags);
  }
  return {
    id,
    context: buildRedirectURL({
      context: rawSamlRequest,
      type: urlParams.samlRequest,
      isSigned: metadata.sp.isAuthnRequestSigned(),
      entitySetting: spSetting,
      baseUrl: base as string,
      relayState: relayState ?? spSetting.relayState,
    }),
  };
}

/**
 * Build a redirect URL carrying a SAML login Response.
 *
 * @param requestInfo parsed request used to link `InResponseTo`
 * @param entity `{ idp, sp }` handles
 * @param user authenticated user
 * @param relayState caller-supplied redirect URL
 * @param customTagReplacement optional custom template transformer
 * @returns id + redirect URL wrapped in a {@link BindingContext}
 */
function loginResponseRedirectURL(
  requestInfo: RequestInfo,
  entity: { idp: Idp; sp: Sp },
  user: SAMLUser = {},
  relayState?: string,
  customTagReplacement?: (template: string) => BindingContext,
): BindingContext {
  const idpSetting = entity.idp.entitySetting;
  const spSetting = entity.sp.entitySetting;
  const metadata = {
    idp: entity.idp.entityMeta,
    sp: entity.sp.entityMeta,
  };

  let id: string = idpSetting.generateID!();

  /* v8 ignore start */
  if (!metadata.idp || !metadata.sp) {
    throw new Error('ERR_GENERATE_REDIRECT_LOGIN_RESPONSE_MISSING_METADATA');
  }
  /* v8 ignore stop */

  const base = metadata.sp.getAssertionConsumerService(binding.redirect);
  let rawSamlResponse: string;
  const nameIDFormat = idpSetting.nameIDFormat;
  const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;
  const nowTime = new Date();
  const fiveMinutesLaterTime = new Date(nowTime.getTime() + 300_000);
  const tvalue: TagReplacementMap = {
    ID: id,
    AssertionID: idpSetting.generateID!(),
    Destination: base as string,
    SubjectRecipient: base as string,
    Issuer: metadata.idp.getEntityID(),
    Audience: metadata.sp.getEntityID(),
    EntityID: metadata.sp.getEntityID(),
    IssueInstant: nowTime.toISOString(),
    AssertionConsumerServiceURL: base as string,
    StatusCode: namespace.statusCode.success,
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
    id = get<string>(template as unknown as Record<string, unknown>, 'id') as string;
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

  // SAML response over redirect binding is always signed (see SAML core 3.4.4).
  return {
    id,
    context: buildRedirectURL({
      baseUrl: base as string,
      type: urlParams.samlResponse,
      isSigned: true,
      context: rawSamlResponse,
      entitySetting: idpSetting,
      relayState,
    }),
  };
}

/**
 * Build a redirect URL carrying a SAML LogoutRequest.
 *
 * @param user currently authenticated user
 * @param entity `{ init, target }` handles
 * @param relayState caller-supplied redirect URL
 * @param customTagReplacement optional custom template transformer
 * @returns id + redirect URL wrapped in a {@link BindingContext}
 */
function logoutRequestRedirectURL(
  user: SAMLUser,
  entity: RedirectInitTargetPair,
  relayState?: string,
  customTagReplacement?: (template: string, tags: object) => BindingContext,
): BindingContext {
  const metadata = { init: entity.init.entityMeta, target: entity.target.entityMeta };
  const initSetting = entity.init.entitySetting;
  let id: string = initSetting.generateID!();
  const nameIDFormat = initSetting.nameIDFormat;
  const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;

  /* v8 ignore start */
  if (!metadata.init || !metadata.target) {
    throw new Error('ERR_GENERATE_REDIRECT_LOGOUT_REQUEST_MISSING_METADATA');
  }
  /* v8 ignore stop */

  const base = metadata.target.getSingleLogoutService(binding.redirect);
  let rawSamlRequest = '';
  const requiredTags = {
    ID: id,
    Destination: base as string,
    EntityID: metadata.init.getEntityID(),
    Issuer: metadata.init.getEntityID(),
    IssueInstant: new Date().toISOString(),
    NameIDFormat: selectedNameIDFormat,
    NameID: user.logoutNameID,
    SessionIndex: user.sessionIndex,
  };
  if (initSetting.logoutRequestTemplate && customTagReplacement) {
    const info = customTagReplacement(initSetting.logoutRequestTemplate as unknown as string, requiredTags);
    id = get<string>(info as unknown as Record<string, unknown>, 'id') as string;
    rawSamlRequest = get<string>(info as unknown as Record<string, unknown>, 'context') as string;
  } else {
    rawSamlRequest = libsaml.replaceTagsByValue(libsaml.defaultLogoutRequestTemplate.context, requiredTags as TagReplacementMap);
  }
  return {
    id,
    context: buildRedirectURL({
      context: rawSamlRequest,
      relayState,
      type: urlParams.logoutRequest,
      isSigned: entity.target.entitySetting.wantLogoutRequestSigned!,
      entitySetting: initSetting,
      baseUrl: base as string,
    }),
  };
}

/**
 * Build a redirect URL carrying a SAML LogoutResponse.
 *
 * @param requestInfo parsed request used to link `InResponseTo`
 * @param entity `{ init, target }` handles
 * @param relayState caller-supplied redirect URL
 * @param customTagReplacement optional custom template transformer
 * @returns id + redirect URL wrapped in a {@link BindingContext}
 */
function logoutResponseRedirectURL(
  requestInfo: RequestInfo,
  entity: RedirectInitTargetPair,
  relayState?: string,
  customTagReplacement?: (template: string) => BindingContext,
): BindingContext {
  const metadata = {
    init: entity.init.entityMeta,
    target: entity.target.entityMeta,
  };
  const initSetting = entity.init.entitySetting;
  let id: string = initSetting.generateID!();

  /* v8 ignore start */
  if (!metadata.init || !metadata.target) {
    throw new Error('ERR_GENERATE_REDIRECT_LOGOUT_RESPONSE_MISSING_METADATA');
  }
  /* v8 ignore stop */

  const base = metadata.target.getSingleLogoutService(binding.redirect);
  let rawSamlResponse: string;
  if (initSetting.logoutResponseTemplate && customTagReplacement) {
    const template = customTagReplacement(initSetting.logoutResponseTemplate as unknown as string);
    id = get<string>(template as unknown as Record<string, unknown>, 'id') as string;
    rawSamlResponse = get<string>(template as unknown as Record<string, unknown>, 'context') as string;
  } else {
    const tvalue: TagReplacementMap = {
      ID: id,
      Destination: base as string,
      Issuer: metadata.init.getEntityID(),
      EntityID: metadata.init.getEntityID(),
      IssueInstant: new Date().toISOString(),
      StatusCode: namespace.statusCode.success,
    };
    if (requestInfo && (requestInfo as RequestInfo).extract && (requestInfo as RequestInfo).extract.request) {
      tvalue.InResponseTo = (requestInfo as RequestInfo).extract.request!.id as string;
    }
    rawSamlResponse = libsaml.replaceTagsByValue(libsaml.defaultLogoutResponseTemplate.context, tvalue);
  }
  return {
    id,
    context: buildRedirectURL({
      baseUrl: base as string,
      type: urlParams.logoutResponse,
      isSigned: entity.target.entitySetting.wantLogoutResponseSigned!,
      context: rawSamlResponse,
      entitySetting: initSetting,
      relayState,
    }),
  };
}

const redirectBinding = {
  loginRequestRedirectURL,
  loginResponseRedirectURL,
  logoutRequestRedirectURL,
  logoutResponseRedirectURL,
};

export default redirectBinding;
