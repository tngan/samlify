/**
 * @file flow.ts
 * @author tngan
 * @desc Inbound SAML message pipeline. Dispatches between POST, Redirect,
 * and POST-SimpleSign flows, handling decoding, schema validation, status
 * checks, signature verification, and time-window validation.
 */
import { inflateString, base64Decode } from './utility';
import { verifyTime } from './validator';
import libsaml from './libsaml';
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
  StatusCode,
} from './urn';

const bindDict = wording.binding;
const urlParams = wording.urlParams;

/** Result emitted by the flow dispatcher for successful inbound messages. */
export interface FlowResult {
  samlContent: string;
  extract: ExtractorResult;
  sigAlg?: string | null;
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
  }

  const issuer = targetEntityMetadata.getEntityID();
  const extractedProperties = parseResult.extract;

  if (
    (parserType === 'LogoutResponse' || parserType === 'SAMLResponse')
    && extractedProperties
    && extractedProperties.issuer !== issuer
  ) {
    return Promise.reject(new Error('ERR_UNMATCH_ISSUER'));
  }

  // Session expiration — only enforced when SessionNotOnOrAfter is present.
  if (
    parserType === 'SAMLResponse'
    && (extractedProperties.sessionIndex as Record<string, string> | undefined)?.sessionNotOnOrAfter
    && !verifyTime(
      undefined,
      (extractedProperties.sessionIndex as Record<string, string>).sessionNotOnOrAfter,
      self.entitySetting.clockDrifts,
    )
  ) {
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
    signatureAlgorithm: from.entitySetting.requestSignatureAlgorithm,
  };

  const decryptRequired = from.entitySetting.isAssertionEncrypted;

  let extractorFields: ExtractorFields = [];

  await libsaml.isValidXml(samlContent);

  if (parserType !== urlParams.samlResponse) {
    extractorFields = getDefaultExtractorFields(parserType, null);
  }

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
      const decryptedDoc = result[0];
      const [decryptedDocVerified, verifiedDecryptedAssertion] = libsaml.verifySignature(decryptedDoc, verificationOptions);
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

  const targetEntityMetadata = from.entityMeta;
  const issuer = targetEntityMetadata.getEntityID();
  const extractedProperties = parseResult.extract;

  if (
    (parserType === 'LogoutResponse' || parserType === 'SAMLResponse')
    && extractedProperties
    && extractedProperties.issuer !== issuer
  ) {
    return Promise.reject(new Error('ERR_UNMATCH_ISSUER'));
  }

  if (
    parserType === 'SAMLResponse'
    && (extractedProperties.sessionIndex as Record<string, string> | undefined)?.sessionNotOnOrAfter
    && !verifyTime(
      undefined,
      (extractedProperties.sessionIndex as Record<string, string>).sessionNotOnOrAfter,
      self.entitySetting.clockDrifts,
    )
  ) {
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
  }

  const issuer = targetEntityMetadata.getEntityID();
  const extractedProperties = parseResult.extract;

  if (
    (parserType === 'LogoutResponse' || parserType === 'SAMLResponse')
    && extractedProperties
    && extractedProperties.issuer !== issuer
  ) {
    return Promise.reject(new Error('ERR_UNMATCH_ISSUER'));
  }

  if (
    parserType === 'SAMLResponse'
    && (extractedProperties.sessionIndex as Record<string, string> | undefined)?.sessionNotOnOrAfter
    && !verifyTime(
      undefined,
      (extractedProperties.sessionIndex as Record<string, string>).sessionNotOnOrAfter,
      self.entitySetting.clockDrifts,
    )
  ) {
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
