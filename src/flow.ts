/**
 * @file flow.ts
 * @author tngan
 * @desc Inbound SAML message pipeline. Dispatches between POST, Redirect,
 * and POST-SimpleSign flows, handling decoding, schema validation, status
 * checks, signature verification, and time-window validation.
 */
import { inflateString, base64Decode, uniq, notEmpty } from './utility';
import { verifyTime } from './validator';
import { parseXml } from './xml';
import { select } from 'xpath';
import libsaml, { assertAllowedSignatureAlgorithm } from './libsaml';
import {
  extract,
  loginRequestFields,
  loginResponseFields,
  logoutRequestFields,
  logoutResponseFields,
  ExtractorFields,
  logoutResponseStatusFields,
  loginResponseStatusFields,
} from './extractor';
import type { ESamlHttpRequest, ExtractorResult } from './types';
import type Entity from './entity';

import {
  BindingNamespace,
  ParserType,
  wording,
  namespace,
  StatusCode,
} from './urn';

const bindDict = wording.binding;
const urlParams = wording.urlParams;

/** Result emitted by the flow dispatcher for successful inbound messages. */
export interface FlowResult {
  samlContent: string;
  extract: ExtractorResult;
  sigAlg?: string | null;
  /**
   * `RelayState` covered by the verified detached signature (Redirect and
   * SimpleSign bindings). Use it instead of the request parameter.
   */
  relayState?: string;
}

/** Options consumed by {@link flow} and its internal dispatch helpers. */
export interface FlowOptions {
  request: ESamlHttpRequest;
  parserType: ParserType | string;
  self: Entity;
  from: Entity;
  checkSignature?: boolean;
  type: 'login' | 'logout';
  binding: string;
  supportBindings?: string[];
  /** Request ID(s) a login response must answer; see `ParseLoginResponseOptions`. */
  inResponseTo?: string | string[] | null;
}

/**
 * Map a parser type onto the default extractor fields that populate
 * {@link FlowResult.extract}. Login-response extraction is parameterised by
 * the verified assertion fragment to defend against wrapping attacks.
 *
 * @param parserType SAML message type
 * @param assertion verified assertion XML (required for SAMLResponse)
 */
function getDefaultExtractorFields(
  parserType: ParserType | string,
  assertion?: string | null,
): ExtractorFields {
  switch (parserType) {
    case ParserType.SAMLRequest:
      return loginRequestFields;
    case ParserType.SAMLResponse:
      if (!assertion) {
        throw new Error('ERR_EMPTY_ASSERTION');
      }
      return loginResponseFields(assertion);
    case ParserType.LogoutRequest:
      return logoutRequestFields;
    case ParserType.LogoutResponse:
      return logoutResponseFields;
    default:
      throw new Error('ERR_UNDEFINED_PARSERTYPE');
  }
}

/**
 * Check that the verified assertion is addressed to this SP. Every
 * `<AudienceRestriction>` must list the SP entityID in one of its
 * `<Audience>` elements (saml-core §2.5.1.4), and at least one restriction
 * must be present (saml-profiles §4.1.4.2). Disabled only when the SP sets
 * `wantAudienceCheck: false`.
 *
 * @param self receiving entity (the SP)
 * @param extracted login-response extractor result
 */
function isIntendedAudience(self: Entity, extracted: ExtractorResult): boolean {
  if (self.entitySetting.wantAudienceCheck === false) {
    return true;
  }
  const restriction = extracted.audienceRestriction as string | string[] | null | undefined;
  const restrictions = ([] as string[]).concat(restriction ?? []);
  const entityID = self.entityMeta.getEntityID();
  return restrictions.length > 0 && restrictions.every(xml => {
    const { audience } = extract(xml, [{ key: 'audience', localPath: ['AudienceRestriction', 'Audience'], attributes: [] }]);
    return ([] as unknown[]).concat(audience ?? []).includes(entityID);
  });
}

/**
 * Check that the response targets one of this SP's AssertionConsumerService
 * endpoints: `Response@Destination` (saml-bindings §3.4.5.2, §3.5.5.2) and the
 * bearer `SubjectConfirmationData@Recipient` (saml-profiles §4.1.4.3) must
 * each match an ACS location when present. Shares the `wantAudienceCheck`
 * opt-out.
 *
 * @param self receiving entity (the SP)
 * @param extracted login-response extractor result
 */
function isIntendedRecipient(self: Entity, extracted: ExtractorResult): boolean {
  if (self.entitySetting.wantAudienceCheck === false) {
    return true;
  }
  const locations = acsLocations(self);
  const destination = (extracted.response as Record<string, string> | undefined)?.destination;
  return !destination || locations.includes(destination);
}

/** ACS locations of this SP. */
function acsLocations(self: Entity): (string | undefined)[] {
  const acs = (self.entityMeta as unknown as { meta: { assertionConsumerService?: unknown } }).meta.assertionConsumerService;
  return ([] as { location?: string }[])
    .concat((acs ?? []) as { location?: string }[])
    .map(service => service.location);
}

const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';

/**
 * `<SubjectConfirmationData>` of each bearer `<SubjectConfirmation>` in the
 * verified assertion; `null` for a bearer confirmation without one.
 */
function bearerConfirmationData(extracted: ExtractorResult): (Element | null)[] {
  return ([] as string[])
    .concat((extracted.subjectConfirmations ?? []) as string[])
    .map(xml => parseXml(xml).documentElement)
    .filter(confirmation => confirmation.getAttribute('Method') === BEARER)
    .map(confirmation => (select("./*[local-name(.)='SubjectConfirmationData']", confirmation) as Element[])[0] ?? null);
}

/**
 * Check the bearer subject confirmation of the verified assertion
 * (saml-profiles §4.1.4.2, §4.1.4.3). At least one bearer
 * `<SubjectConfirmation>` must be present, and each one must carry a
 * `<SubjectConfirmationData>` that is valid now:
 *
 * - `NotOnOrAfter` has not passed and `NotBefore`, if present, has been
 *   reached (with the SP's clock drift). Without its own `NotOnOrAfter`, the
 *   `Conditions` must declare one, so the assertion cannot be used forever.
 * - Unless `wantAudienceCheck` is `false`, `Recipient`, when present, is one
 *   of the SP's AssertionConsumerService locations. A missing `Recipient`
 *   (required by the profile) is logged.
 *
 * @param self receiving entity (the SP)
 * @param extracted login-response extractor result
 * @returns error code, or `null` when the subject is confirmed
 */
function checkBearerConfirmation(self: Entity, extracted: ExtractorResult): string | null {
  const bearer = bearerConfirmationData(extracted);
  if (bearer.length === 0 || bearer.includes(null)) {
    return 'ERR_SUBJECT_UNCONFIRMED';
  }
  const conditionsExpiry = (extracted.conditions as Record<string, string> | undefined)?.notOnOrAfter;
  const checkRecipient = self.entitySetting.wantAudienceCheck !== false;
  const locations = acsLocations(self);

  for (const data of bearer as Element[]) {
    const notBefore = data.getAttribute('NotBefore') || undefined;
    const notOnOrAfter = data.getAttribute('NotOnOrAfter') || undefined;
    if (!notOnOrAfter && !conditionsExpiry) {
      return 'ERR_SUBJECT_UNCONFIRMED';
    }
    if ((notBefore || notOnOrAfter) && !verifyTime(notBefore, notOnOrAfter, self.entitySetting.clockDrifts)) {
      return 'ERR_SUBJECT_UNCONFIRMED';
    }
    const recipient = data.getAttribute('Recipient');
    if (checkRecipient && recipient && !locations.includes(recipient)) {
      return 'ERR_RECIPIENT_MISMATCH';
    }
    if (checkRecipient && !recipient) {
      console.warn(
        `[samlify] bearer SubjectConfirmationData without Recipient from ${String(extracted.issuer)}; `
        + 'saml-profiles §4.1.4.2 requires it, only the Audience binds this assertion to the SP.',
      );
    }
  }
  return null;
}

/**
 * Every `SessionNotOnOrAfter` of the assertion's AuthnStatements must not
 * have passed.
 */
function isSessionValid(self: Entity, extracted: ExtractorResult): boolean {
  return ([] as Record<string, string>[])
    .concat((extracted.sessionIndex ?? []) as Record<string, string>[])
    .every(statement => !statement?.sessionNotOnOrAfter
      || verifyTime(undefined, statement.sessionNotOnOrAfter, self.entitySetting.clockDrifts));
}

/**
 * Check which request a login response answers.
 *
 * The answered request is read from the signed bearer
 * `SubjectConfirmationData@InResponseTo` (saml-profiles §4.1.4.2). The outer
 * `Response@InResponseTo` is only trusted when the whole message is covered
 * by the verified signature (redirect / SimpleSign bindings); on the POST
 * binding it may sit outside the signed assertion.
 *
 * - Always: the signed values and the outer value must agree, and an outer
 *   value that is not covered by the signature needs a signed counterpart.
 * - When `expected` is given: the answered request must be one of them.
 * - When `expected` is `null` (no request pending): a response that answers
 *   a request is rejected.
 * - When the SP sets `allowUnsolicitedResponse: false`: a response that does
 *   not answer a request is rejected.
 *
 * @param self receiving entity (the SP)
 * @param extracted login-response extractor result
 * @param messageSigned whether the outer `Response` is covered by the signature
 * @param expected request ID(s) the caller issued
 * @returns error code, or `null` when the response passes
 */
function checkInResponseTo(
  self: Entity,
  extracted: ExtractorResult,
  messageSigned: boolean,
  expected?: string | string[] | null,
): string | null {
  const outer = (extracted.response as Record<string, string> | undefined)?.inResponseTo;
  const confirmations = ([] as Record<string, string>[])
    .concat((extracted.subjectConfirmation ?? []) as unknown as Record<string, string>[]);
  const signed = uniq(confirmations.map(confirmation => confirmation.inResponseTo).filter(notEmpty));

  if (signed.length > 1 || (outer && signed.length === 1 && signed[0] !== outer)) {
    return 'ERR_INRESPONSETO_MISMATCH';
  }
  // An answered request is always named in the signed confirmation
  // (saml-profiles §4.1.4.2); an unsigned outer value alone is not trusted.
  if (outer && signed.length === 0 && !messageSigned) {
    return 'ERR_INRESPONSETO_MISMATCH';
  }

  const answered = signed[0] ?? (messageSigned ? outer : undefined);

  if (expected === null) {
    // No request is pending: a response answering one was not meant for this session.
    if (answered) {
      return 'ERR_INRESPONSETO_MISMATCH';
    }
  } else if (expected !== undefined) {
    if (!answered) {
      return 'ERR_MISSING_INRESPONSETO';
    }
    if (!([] as string[]).concat(expected).includes(answered)) {
      return 'ERR_INRESPONSETO_MISMATCH';
    }
  }

  if (self.entitySetting.allowUnsolicitedResponse === false && !answered) {
    return 'ERR_UNSOLICITED_RESPONSE';
  }

  return null;
}

/** Retention for a replay-checked LogoutRequest without `NotOnOrAfter`. */
const LOGOUT_REQUEST_LIFETIME_MS = 24 * 60 * 60 * 1000;

/** SingleLogoutService locations of this entity. */
function sloLocations(self: Entity): (string | undefined)[] {
  const slo = (self.entityMeta as unknown as { meta: { singleLogoutService?: unknown } }).meta.singleLogoutService;
  return ([] as { location?: string }[])
    .concat((slo ?? []) as { location?: string }[])
    .map(service => service.location);
}

/**
 * Checks for an inbound `LogoutRequest` / `LogoutResponse` (saml-core §3.7,
 * saml-profiles §4.4.4, saml-bindings §3.4.5.2 / §3.5.5.2):
 *
 * - `Destination`, when present, is one of this entity's SingleLogoutService
 *   locations (`ERR_RECIPIENT_MISMATCH`). Shares the `wantAudienceCheck`
 *   opt-out.
 * - A `LogoutRequest` whose `NotOnOrAfter` has passed is rejected
 *   (`ERR_EXPIRED_REQUEST`).
 * - With a `replayCache`, a `LogoutRequest` is accepted once
 *   (`ERR_REPLAYED_REQUEST`). It is remembered until its `NotOnOrAfter`, or
 *   24 hours after its `IssueInstant`; an older request is rejected.
 *
 * Accepting a message whose signature was not required is logged:
 * saml-profiles §4.4.4 requires front-channel logout messages to be
 * authenticated, and signed logout becomes the default in v3.
 *
 * @param self receiving entity
 * @param parserType `LogoutRequest` or `LogoutResponse`
 * @param extracted extractor result
 * @param signatureChecked whether the message signature was verified
 * @returns error code, or `null` when the message passes
 */
async function checkLogoutMessage(
  self: Entity,
  parserType: string,
  extracted: ExtractorResult,
  signatureChecked: boolean,
): Promise<string | null> {
  const error = await logoutMessageError(self, parserType, extracted);
  if (!error && !signatureChecked) {
    console.warn(
      `[samlify] accepted an unsigned ${parserType} from ${String(extracted.issuer)}; `
      + `set want${parserType}Signed: true to require a signature (the default in v3).`,
    );
  }
  return error;
}

async function logoutMessageError(self: Entity, parserType: string, extracted: ExtractorResult): Promise<string | null> {
  const message = (parserType === 'LogoutRequest' ? extracted.request : extracted.response) as Record<string, string> | undefined;
  const drift = self.entitySetting.clockDrifts;
  if (self.entitySetting.wantAudienceCheck !== false && message?.destination && !sloLocations(self).includes(message.destination)) {
    return 'ERR_RECIPIENT_MISMATCH';
  }
  if (parserType !== 'LogoutRequest') {
    return null;
  }
  if (message?.notOnOrAfter && !verifyTime(undefined, message.notOnOrAfter, drift)) {
    return 'ERR_EXPIRED_REQUEST';
  }
  const replayCache = self.entitySetting.replayCache;
  if (!replayCache) {
    return null;
  }
  const expiry = message?.notOnOrAfter
    ? new Date(message.notOnOrAfter).getTime()
    : new Date(message?.issueInstant ?? '').getTime() + LOGOUT_REQUEST_LIFETIME_MS;
  const allowed = expiry + Math.max(drift?.[1] ?? 0, 0);
  if (!message?.id || Number.isNaN(expiry) || allowed <= Date.now()) {
    return 'ERR_EXPIRED_REQUEST';
  }
  const key = JSON.stringify(['logoutRequest', extracted.issuer, message.id]);
  return (await replayCache.saveIfAbsent(key, new Date(allowed))) ? null : 'ERR_REPLAYED_REQUEST';
}

/**
 * Reject a bearer assertion this SP already accepted (saml-profiles
 * §4.1.4.5). Only active when the SP supplies a `replayCache`. The assertion
 * is remembered until the earliest `NotOnOrAfter` of its `Conditions` and
 * bearer `SubjectConfirmationData`, plus the allowed clock drift, after
 * which the validity checks reject it anyway.
 *
 * Run after every other check, so a response that fails validation does not
 * use up its assertion.
 *
 * @param self receiving entity (the SP)
 * @param extracted login-response extractor result
 * @returns error code, or `null` when the assertion was not seen before
 */
async function checkReplay(self: Entity, extracted: ExtractorResult): Promise<string | null> {
  const replayCache = self.entitySetting.replayCache;
  if (!replayCache) {
    return null;
  }
  const assertionID = extracted.assertionID;
  if (typeof assertionID !== 'string' || assertionID === '') {
    return 'ERR_UNDEFINED_ASSERTION_ID';
  }
  // The same bounds checkBearerConfirmation and the Conditions check enforce.
  const expiries = [
    (extracted.conditions as Record<string, string> | undefined)?.notOnOrAfter,
    ...bearerConfirmationData(extracted).map(data => data?.getAttribute('NotOnOrAfter')),
  ]
    .filter(notEmpty)
    .map(value => new Date(value).getTime())
    .filter(time => !Number.isNaN(time));
  /* v8 ignore next 3 */
  if (expiries.length === 0) {
    return 'ERR_SUBJECT_UNCONFIRMED';
  }
  const drift = self.entitySetting.clockDrifts?.[1] ?? 0;
  const expiresAt = new Date(Math.min(...expiries) + Math.max(drift, 0));
  const key = JSON.stringify(['assertion', extracted.issuer, assertionID]);
  return (await replayCache.saveIfAbsent(key, expiresAt)) ? null : 'ERR_REPLAYED_ASSERTION';
}

/** Root element each parser expects (saml-schema-protocol). */
const MESSAGE_ROOTS: Record<string, string> = {
  SAMLRequest: 'AuthnRequest',
  SAMLResponse: 'Response',
  LogoutRequest: 'LogoutRequest',
  LogoutResponse: 'LogoutResponse',
};

/**
 * Throw unless the message is the SAML protocol element the parser expects,
 * so one signed message type cannot be submitted as another.
 */
function assertMessageType(xml: string, parserType: string): void {
  const root = parseXml(xml).documentElement;
  if (root.namespaceURI !== namespace.names.protocol || root.localName !== MESSAGE_ROOTS[parserType]) {
    throw new Error('ERR_UNEXPECTED_MESSAGE_TYPE');
  }
}

/** Decode a query value; a value the caller already decoded is returned as is. */
function decodeQueryValue(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/**
 * Check that the Redirect-binding octet string that was signed carries the
 * message, `SigAlg` and `RelayState` this flow parses (saml-bindings
 * §3.4.4.1). Otherwise a signature over one message could vouch for another
 * one supplied in the query.
 *
 * @returns the signed `RelayState`, form-decoded, if the octet string has one
 */
function assertRedirectOctetString(
  octetString: string | undefined,
  direction: string,
  content: string,
  sigAlg: string,
  relayState: string | undefined,
): string | undefined {
  if (typeof octetString !== 'string') {
    throw new Error('ERR_MISSING_OCTET_STRING');
  }
  const signed = new Map<string, string>();
  for (const pair of octetString.split('&')) {
    const separator = pair.indexOf('=');
    const key = separator === -1 ? pair : pair.slice(0, separator);
    if (![direction, urlParams.relayState, urlParams.sigAlg].includes(key) || signed.has(key)) {
      throw new Error('ERR_OCTET_STRING_MISMATCH');
    }
    signed.set(key, separator === -1 ? '' : pair.slice(separator + 1));
  }
  const signedMessage = signed.get(direction);
  const signedSigAlg = signed.get(urlParams.sigAlg);
  const signedRelayState = signed.get(urlParams.relayState);
  // A query parser may decode `+` as a space (form encoding) or keep it.
  const relayStateForms = signedRelayState === undefined ? [] : [
    decodeQueryValue(signedRelayState.replace(/\+/g, ' ')),
    decodeQueryValue(signedRelayState),
    signedRelayState,
  ];
  if (
    signedMessage === undefined
    || decodeQueryValue(signedMessage) !== decodeQueryValue(content)
    || signedSigAlg === undefined
    || decodeQueryValue(signedSigAlg) !== decodeQueryValue(sigAlg)
    || (relayState !== undefined && !relayStateForms.includes(relayState))
  ) {
    throw new Error('ERR_OCTET_STRING_MISMATCH');
  }
  return relayStateForms[0];
}

/**
 * Check that the SimpleSign octet string that was signed is built from the
 * message, `SigAlg` and `RelayState` this flow parses (saml-bindings
 * §3.5.4.1): `<direction>=<xml>[&RelayState=<value>]&SigAlg=<value>`.
 *
 * @returns the signed `RelayState`, if the octet string has one
 */
function assertSimpleSignOctetString(
  octetString: string | undefined,
  direction: string,
  xmlString: string,
  sigAlg: string,
  relayState: string | undefined,
): string | undefined {
  if (typeof octetString !== 'string') {
    throw new Error('ERR_MISSING_OCTET_STRING');
  }
  const prefix = `${direction}=${xmlString}`;
  const suffix = `&${urlParams.sigAlg}=${sigAlg}`;
  if (!octetString.startsWith(prefix) || !octetString.endsWith(suffix) || octetString.length < prefix.length + suffix.length) {
    throw new Error('ERR_OCTET_STRING_MISMATCH');
  }
  const middle = octetString.slice(prefix.length, octetString.length - suffix.length);
  const relayStatePrefix = `&${urlParams.relayState}=`;
  const signedRelayState = middle === '' ? undefined : middle.startsWith(relayStatePrefix) ? middle.slice(relayStatePrefix.length) : null;
  if (signedRelayState === null || (relayState !== undefined && relayState !== '' && signedRelayState !== relayState)) {
    throw new Error('ERR_OCTET_STRING_MISMATCH');
  }
  return signedRelayState;
}

/**
 * Redirect-binding flow: reads the base64/deflate SAML message from query
 * params and, when required, verifies the detached signature over the
 * canonical octet string.
 */
async function redirectFlow(options: FlowOptions): Promise<FlowResult> {
  const { request, parserType, self, checkSignature = true, from } = options;
  const { query, octetString } = request;
  const { SigAlg: sigAlg, Signature: signature } = query as Record<string, string | undefined>;

  const targetEntityMetadata = from.entityMeta;

  const direction = libsaml.getQueryParamByType(parserType as string);
  const content = (query as Record<string, string | undefined>)[direction];

  if (content === undefined) {
    return Promise.reject(new Error('ERR_REDIRECT_FLOW_BAD_ARGS'));
  }

  const xmlString = inflateString(decodeURIComponent(content));

  try {
    await libsaml.isValidXml(xmlString);
  } catch {
    return Promise.reject(new Error('ERR_INVALID_XML'));
  }

  assertMessageType(xmlString, parserType as string);
  await checkStatus(xmlString, parserType as string);

  let assertion = '';

  if (parserType === urlParams.samlResponse) {
    const verifiedDoc = extract(xmlString, [{
      key: 'assertion',
      localPath: ['~Response', 'Assertion'],
      attributes: [],
      context: true,
    }]);
    if (verifiedDoc && verifiedDoc.assertion) {
      assertion = verifiedDoc.assertion as string;
    }
  }

  const extractorFields = getDefaultExtractorFields(parserType, assertion.length > 0 ? assertion : null);

  const parseResult: FlowResult = {
    samlContent: xmlString,
    sigAlg: null,
    extract: extract(xmlString, extractorFields),
  };

  if (checkSignature) {
    if (!signature || !sigAlg) {
      return Promise.reject(new Error('ERR_MISSING_SIG_ALG'));
    }

    const base64Signature = Buffer.from(decodeURIComponent(signature), 'base64');
    const decodeSigAlg = decodeURIComponent(sigAlg);

    const signedRelayState = assertRedirectOctetString(
      octetString,
      direction,
      content,
      sigAlg,
      (query as Record<string, string | undefined>)[urlParams.relayState],
    );

    const { allowedSignatureAlgorithms } = self.entitySetting;
    if (allowedSignatureAlgorithms) {
      assertAllowedSignatureAlgorithm(decodeSigAlg, allowedSignatureAlgorithms);
    }

    const verified = libsaml.verifyMessageSignature(
      targetEntityMetadata,
      octetString as string,
      base64Signature,
      sigAlg,
    );

    if (!verified) {
      return Promise.reject(new Error('ERR_FAILED_MESSAGE_SIGNATURE_VERIFICATION'));
    }

    parseResult.sigAlg = decodeSigAlg;
    if (signedRelayState !== undefined) {
      parseResult.relayState = signedRelayState;
    }
  }

  const issuer = targetEntityMetadata.getEntityID();
  const extractedProperties = parseResult.extract;

  if (
    (parserType === 'LogoutRequest' || parserType === 'LogoutResponse' || parserType === 'SAMLResponse')
    && extractedProperties
    && extractedProperties.issuer !== issuer
  ) {
    return Promise.reject(new Error('ERR_UNMATCH_ISSUER'));
  }

  if (parserType === 'LogoutRequest' || parserType === 'LogoutResponse') {
    const logoutError = await checkLogoutMessage(self, parserType, extractedProperties, checkSignature);
    if (logoutError) {
      return Promise.reject(new Error(logoutError));
    }
  }

  if (parserType === 'SAMLResponse' && !isIntendedAudience(self, extractedProperties)) {
    return Promise.reject(new Error('ERR_AUDIENCE_MISMATCH'));
  }

  if (parserType === 'SAMLResponse' && !isIntendedRecipient(self, extractedProperties)) {
    return Promise.reject(new Error('ERR_RECIPIENT_MISMATCH'));
  }

  if (parserType === 'SAMLResponse') {
    const confirmationError = checkBearerConfirmation(self, extractedProperties);
    if (confirmationError) {
      return Promise.reject(new Error(confirmationError));
    }
  }

  if (parserType === 'SAMLResponse') {
    const inResponseToError = checkInResponseTo(self, extractedProperties, checkSignature, options.inResponseTo);
    if (inResponseToError) {
      return Promise.reject(new Error(inResponseToError));
    }
  }

  if (parserType === 'SAMLResponse' && !isSessionValid(self, extractedProperties)) {
    return Promise.reject(new Error('ERR_EXPIRED_SESSION'));
  }

  // Assertion validity window. SAML core 2.4.1.2.
  if (
    parserType === 'SAMLResponse'
    && extractedProperties.conditions
    && !verifyTime(
      (extractedProperties.conditions as Record<string, string>).notBefore,
      (extractedProperties.conditions as Record<string, string>).notOnOrAfter,
      self.entitySetting.clockDrifts,
    )
  ) {
    return Promise.reject(new Error('ERR_SUBJECT_UNCONFIRMED'));
  }

  if (parserType === 'SAMLResponse') {
    const replayError = await checkReplay(self, extractedProperties);
    if (replayError) {
      return Promise.reject(new Error(replayError));
    }
  }

  return Promise.resolve(parseResult);
}

/**
 * POST-binding flow: reads the base64 SAML message from the request body
 * and verifies the embedded XML signature. Supports both encrypted-then-
 * signed and signed-then-encrypted assertion pipelines.
 */
async function postFlow(options: FlowOptions): Promise<FlowResult> {
  const {
    request,
    from,
    self,
    parserType,
    checkSignature = true,
  } = options;

  const { body } = request;

  const direction = libsaml.getQueryParamByType(parserType as string);
  const encodedRequest = (body as Record<string, string | undefined>)[direction] as string;

  let samlContent = String(base64Decode(encodedRequest));

  const verificationOptions = {
    metadata: from.entityMeta,
    allowedSignatureAlgorithms: self.entitySetting.allowedSignatureAlgorithms,
    // An SP with `wantMessageSigned` requires the <Response> itself to be signed.
    requireMessageSignature: parserType === urlParams.samlResponse && self.entitySetting.wantMessageSigned === true,
  };

  // Only a login response carries an (encrypted) assertion.
  const decryptRequired = from.entitySetting.isAssertionEncrypted && parserType === urlParams.samlResponse;

  let extractorFields: ExtractorFields = [];

  await libsaml.isValidXml(samlContent);

  if (parserType !== urlParams.samlResponse) {
    extractorFields = getDefaultExtractorFields(parserType, null);
  }

  assertMessageType(samlContent, parserType as string);
  await checkStatus(samlContent, parserType as string);

  if (checkSignature) {
    const [verified, verifiedAssertionNode] = libsaml.verifySignature(samlContent, verificationOptions);

    // Encrypted-then-signed response: verifiedAssertionNode is actually the Response.
    if (decryptRequired && verified && parserType === 'SAMLResponse' && verifiedAssertionNode) {
      const result = await libsaml.decryptAssertion(self, verifiedAssertionNode);
      samlContent = result[0];
      extractorFields = getDefaultExtractorFields(parserType, result[1]);
    } else if (decryptRequired && !verified) {
      // Encrypted assertion, signature is on the assertion itself.
      const result = await libsaml.decryptAssertion(self, samlContent);
      samlContent = result[0];
      const [decryptedDocVerified, verifiedDecryptedAssertion] = libsaml.verifySignature(samlContent, verificationOptions);
      if (decryptedDocVerified) {
        extractorFields = getDefaultExtractorFields(parserType, verifiedDecryptedAssertion);
      } else {
        return Promise.reject(new Error('FAILED_TO_VERIFY_SIGNATURE'));
      }
    } else if (verified) {
      extractorFields = getDefaultExtractorFields(parserType, verifiedAssertionNode);
    } else {
      return Promise.reject(new Error('FAILED_TO_VERIFY_SIGNATURE'));
    }
  }

  const parseResult: FlowResult = {
    samlContent,
    extract: extract(samlContent, extractorFields),
  };

  // verifySignature checks a root-level signature first and fails on any
  // invalid one, so once it passed, such a signature covers the whole message.
  const messageSigned = checkSignature
    && (select("/*/*[local-name(.)='Signature']", parseXml(samlContent)) as Node[]).length > 0;

  const targetEntityMetadata = from.entityMeta;
  const issuer = targetEntityMetadata.getEntityID();
  const extractedProperties = parseResult.extract;

  if (
    (parserType === 'LogoutRequest' || parserType === 'LogoutResponse' || parserType === 'SAMLResponse')
    && extractedProperties
    && extractedProperties.issuer !== issuer
  ) {
    return Promise.reject(new Error('ERR_UNMATCH_ISSUER'));
  }

  if (parserType === 'LogoutRequest' || parserType === 'LogoutResponse') {
    const logoutError = await checkLogoutMessage(self, parserType, extractedProperties, checkSignature);
    if (logoutError) {
      return Promise.reject(new Error(logoutError));
    }
  }

  if (parserType === 'SAMLResponse' && !isIntendedAudience(self, extractedProperties)) {
    return Promise.reject(new Error('ERR_AUDIENCE_MISMATCH'));
  }

  if (parserType === 'SAMLResponse' && !isIntendedRecipient(self, extractedProperties)) {
    return Promise.reject(new Error('ERR_RECIPIENT_MISMATCH'));
  }

  if (parserType === 'SAMLResponse') {
    const confirmationError = checkBearerConfirmation(self, extractedProperties);
    if (confirmationError) {
      return Promise.reject(new Error(confirmationError));
    }
  }

  if (parserType === 'SAMLResponse') {
    const inResponseToError = checkInResponseTo(self, extractedProperties, messageSigned, options.inResponseTo);
    if (inResponseToError) {
      return Promise.reject(new Error(inResponseToError));
    }
  }

  if (parserType === 'SAMLResponse' && !isSessionValid(self, extractedProperties)) {
    return Promise.reject(new Error('ERR_EXPIRED_SESSION'));
  }

  if (
    parserType === 'SAMLResponse'
    && extractedProperties.conditions
    && !verifyTime(
      (extractedProperties.conditions as Record<string, string>).notBefore,
      (extractedProperties.conditions as Record<string, string>).notOnOrAfter,
      self.entitySetting.clockDrifts,
    )
  ) {
    return Promise.reject(new Error('ERR_SUBJECT_UNCONFIRMED'));
  }

  if (parserType === 'SAMLResponse') {
    const replayError = await checkReplay(self, extractedProperties);
    if (replayError) {
      return Promise.reject(new Error(replayError));
    }
  }

  return Promise.resolve(parseResult);
}

/**
 * POST-SimpleSign flow: reads the base64 SAML message from the request body
 * together with a detached signature over the SimpleSign octet string.
 */
async function postSimpleSignFlow(options: FlowOptions): Promise<FlowResult> {
  const { request, parserType, self, checkSignature = true, from } = options;

  const { body, octetString } = request;

  const targetEntityMetadata = from.entityMeta;

  const direction = libsaml.getQueryParamByType(parserType as string);
  const encodedRequest: string = (body as Record<string, string>)[direction];
  const sigAlg: string = (body as Record<string, string>)['SigAlg'];
  const signature: string = (body as Record<string, string>)['Signature'];

  if (encodedRequest === undefined) {
    return Promise.reject(new Error('ERR_SIMPLESIGN_FLOW_BAD_ARGS'));
  }

  const xmlString = String(base64Decode(encodedRequest));

  try {
    await libsaml.isValidXml(xmlString);
  } catch {
    return Promise.reject(new Error('ERR_INVALID_XML'));
  }

  assertMessageType(xmlString, parserType as string);
  await checkStatus(xmlString, parserType as string);

  let assertion = '';

  if (parserType === urlParams.samlResponse) {
    const verifiedDoc = extract(xmlString, [{
      key: 'assertion',
      localPath: ['~Response', 'Assertion'],
      attributes: [],
      context: true,
    }]);
    if (verifiedDoc && verifiedDoc.assertion) {
      assertion = verifiedDoc.assertion as string;
    }
  }

  const extractorFields = getDefaultExtractorFields(parserType, assertion.length > 0 ? assertion : null);

  const parseResult: FlowResult = {
    samlContent: xmlString,
    sigAlg: null,
    extract: extract(xmlString, extractorFields),
  };

  if (checkSignature) {
    if (!signature || !sigAlg) {
      return Promise.reject(new Error('ERR_MISSING_SIG_ALG'));
    }

    const base64Signature = Buffer.from(signature, 'base64');

    const signedRelayState = assertSimpleSignOctetString(
      octetString,
      direction,
      xmlString,
      sigAlg,
      (body as Record<string, string | undefined>)[urlParams.relayState],
    );

    const { allowedSignatureAlgorithms } = self.entitySetting;
    if (allowedSignatureAlgorithms) {
      assertAllowedSignatureAlgorithm(sigAlg, allowedSignatureAlgorithms);
    }

    const verified = libsaml.verifyMessageSignature(
      targetEntityMetadata,
      octetString as string,
      base64Signature,
      sigAlg,
    );

    if (!verified) {
      return Promise.reject(new Error('ERR_FAILED_MESSAGE_SIGNATURE_VERIFICATION'));
    }

    parseResult.sigAlg = sigAlg;
    if (signedRelayState !== undefined) {
      parseResult.relayState = signedRelayState;
    }
  }

  const issuer = targetEntityMetadata.getEntityID();
  const extractedProperties = parseResult.extract;

  if (
    (parserType === 'LogoutRequest' || parserType === 'LogoutResponse' || parserType === 'SAMLResponse')
    && extractedProperties
    && extractedProperties.issuer !== issuer
  ) {
    return Promise.reject(new Error('ERR_UNMATCH_ISSUER'));
  }

  if (parserType === 'LogoutRequest' || parserType === 'LogoutResponse') {
    const logoutError = await checkLogoutMessage(self, parserType, extractedProperties, checkSignature);
    if (logoutError) {
      return Promise.reject(new Error(logoutError));
    }
  }

  if (parserType === 'SAMLResponse' && !isIntendedAudience(self, extractedProperties)) {
    return Promise.reject(new Error('ERR_AUDIENCE_MISMATCH'));
  }

  if (parserType === 'SAMLResponse' && !isIntendedRecipient(self, extractedProperties)) {
    return Promise.reject(new Error('ERR_RECIPIENT_MISMATCH'));
  }

  if (parserType === 'SAMLResponse') {
    const confirmationError = checkBearerConfirmation(self, extractedProperties);
    if (confirmationError) {
      return Promise.reject(new Error(confirmationError));
    }
  }

  if (parserType === 'SAMLResponse') {
    const inResponseToError = checkInResponseTo(self, extractedProperties, checkSignature, options.inResponseTo);
    if (inResponseToError) {
      return Promise.reject(new Error(inResponseToError));
    }
  }

  if (parserType === 'SAMLResponse' && !isSessionValid(self, extractedProperties)) {
    return Promise.reject(new Error('ERR_EXPIRED_SESSION'));
  }

  if (
    parserType === 'SAMLResponse'
    && extractedProperties.conditions
    && !verifyTime(
      (extractedProperties.conditions as Record<string, string>).notBefore,
      (extractedProperties.conditions as Record<string, string>).notOnOrAfter,
      self.entitySetting.clockDrifts,
    )
  ) {
    return Promise.reject(new Error('ERR_SUBJECT_UNCONFIRMED'));
  }

  if (parserType === 'SAMLResponse') {
    const replayError = await checkReplay(self, extractedProperties);
    if (replayError) {
      return Promise.reject(new Error(replayError));
    }
  }

  return Promise.resolve(parseResult);
}

/**
 * Inspect the SAML `<Status>` code on a response and reject with a
 * detailed error string when the top-tier code is not `Success`.
 *
 * @param content response XML
 * @param parserType parser type (only SAMLResponse/LogoutResponse are checked)
 * @returns `"OK"` when success or `"SKIPPED"` for non-response messages
 */
function checkStatus(content: string, parserType: string): Promise<string> {
  if (parserType !== urlParams.samlResponse && parserType !== urlParams.logoutResponse) {
    return Promise.resolve('SKIPPED');
  }

  const fields = parserType === urlParams.samlResponse
    ? loginResponseStatusFields
    : logoutResponseStatusFields;

  const { top, second } = extract(content, fields) as { top?: string; second?: string };

  if (top === StatusCode.Success) {
    return Promise.resolve('OK');
  }

  if (!top) {
    throw new Error('ERR_UNDEFINED_STATUS');
  }

  throw new Error(`ERR_FAILED_STATUS with top tier code: ${top}, second tier code: ${second}`);
}

/**
 * Entry point: dispatch an inbound SAML message to the matching binding
 * handler based on `options.binding`.
 *
 * @param options flow inputs (request, parserType, entities, binding)
 * @returns resolved {@link FlowResult} on success
 */
export function flow(options: FlowOptions): Promise<FlowResult> {
  const binding = options.binding;
  const parserType = options.parserType;

  options.supportBindings = [BindingNamespace.Redirect, BindingNamespace.Post, BindingNamespace.SimpleSign];
  if (parserType === ParserType.SAMLResponse) {
    options.supportBindings = [BindingNamespace.Post, BindingNamespace.Redirect, BindingNamespace.SimpleSign];
  }

  if (binding === bindDict.post) {
    return postFlow(options);
  }

  if (binding === bindDict.redirect) {
    return redirectFlow(options);
  }

  if (binding === bindDict.simpleSign) {
    return postSimpleSignFlow(options);
  }

  return Promise.reject(new Error('ERR_UNEXPECTED_FLOW'));
}
