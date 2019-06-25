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
  loginResponseStatusFields
} from './extractor';

import {
  BindingNamespace,
  ParserType,
  wording,
  MessageSignatureOrder,
  StatusCode
} from './urn';

const bindDict = wording.binding;
const urlParams = wording.urlParams;

export interface FlowResult {
  samlContent: string;
  extract: any;
}

// get the default extractor fields based on the parserType
function getDefaultExtractorFields(parserType: ParserType, assertion?: any): ExtractorFields {
  switch (parserType) {
    case ParserType.SAMLRequest:
      return loginRequestFields;
    case ParserType.SAMLResponse:
      if (!assertion) {
        // unexpected hit
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

// proceed the redirect binding flow
async function redirectFlow(options) {

  const { request, parserType, checkSignature = true, from } = options;
  const { query, octetString } = request;
  const { SigAlg: sigAlg, Signature: signature } = query;

  const targetEntityMetadata = from.entityMeta;

  // ?SAMLRequest= or ?SAMLResponse=
  const direction = libsaml.getQueryParamByType(parserType);
  const content = query[direction];

  // query must contain the saml content
  if (content === undefined) {
    return Promise.reject('ERR_REDIRECT_FLOW_BAD_ARGS');
  }

  const xmlString = inflateString(decodeURIComponent(content));

  // validate the xml (remarks: login response must be gone through post flow)
  if (
    parserType === urlParams.samlRequest ||
    parserType === urlParams.logoutRequest ||
    parserType === urlParams.logoutResponse
  ) {
    try {
      await libsaml.isValidXml(xmlString);
    } catch (e) {
      return Promise.reject('ERR_INVALID_XML');
    }
  }

  const extractorFields = getDefaultExtractorFields(parserType);

  const parseResult: { samlContent: string, extract: any, sigAlg: (string | null) } = {
    samlContent: xmlString,
    sigAlg: null,
    extract: extract(xmlString, extractorFields),
  };

  // check status based on different scenarios
  await checkStatus(xmlString, parserType);

  // see if signature check is required
  // only verify message signature is enough
  if (checkSignature) {
    if (!signature || !sigAlg) {
      return Promise.reject('ERR_MISSING_SIG_ALG');
    }

    // put the below two assignemnts into verifyMessageSignature function
    const base64Signature = new Buffer(decodeURIComponent(signature), 'base64');
    const decodeSigAlg = decodeURIComponent(sigAlg);

    const verified = libsaml.verifyMessageSignature(targetEntityMetadata, octetString, base64Signature, sigAlg);

    if (!verified) {
      // Fail to verify message signature
      return Promise.reject('ERR_FAILED_MESSAGE_SIGNATURE_VERIFICATION');
    }

    parseResult.sigAlg = decodeSigAlg;
  }

  return Promise.resolve(parseResult);
}

// proceed the post flow
async function postFlow(options): Promise<FlowResult> {

  const {
    request,
    from,
    self,
    parserType,
    checkSignature = true
  } = options;

  const { body } = request;

  const direction = libsaml.getQueryParamByType(parserType);
  const encodedRequest = body[direction];

  let samlContent = String(base64Decode(encodedRequest));

  const verificationOptions = {
    cert: from.entityMeta,
    signatureAlgorithm: from.entitySetting.requestSignatureAlgorithm,
  };

  const decryptRequired = from.entitySetting.isAssertionEncrypted;

  let extractorFields: ExtractorFields = [];

  // validate the xml first
  await libsaml.isValidXml(samlContent);

  if (parserType !== urlParams.samlResponse) {
    extractorFields = getDefaultExtractorFields(parserType, null);
  }
  
  // check status based on different scenarios
  await checkStatus(samlContent, parserType);

  // verify the signatures (the repsonse is encrypted then signed, then verify first then decrypt)
  if (
    checkSignature &&
    from.entitySetting.messageSigningOrder === MessageSignatureOrder.ETS
  ) {
    const [verified, verifiedAssertionNode] = libsaml.verifySignature(samlContent, verificationOptions);
    if (!verified) {
      return Promise.reject('ERR_FAIL_TO_VERIFY_ETS_SIGNATURE');
    }
    if (!decryptRequired) {
      extractorFields = getDefaultExtractorFields(parserType, verifiedAssertionNode);
    }
  }

  if (parserType === 'SAMLResponse' && decryptRequired) {
    const result = await libsaml.decryptAssertion(self, samlContent);
    samlContent = result[0];
    extractorFields = getDefaultExtractorFields(parserType, result[1]);
  }

  // verify the signatures (the repsonse is signed then encrypted, then decrypt first then verify)
  if (
    checkSignature &&
    from.entitySetting.messageSigningOrder === MessageSignatureOrder.STE
  ) {
    const [verified, verifiedAssertionNode] = libsaml.verifySignature(samlContent, verificationOptions);
    if (verified) {
      extractorFields = getDefaultExtractorFields(parserType, verifiedAssertionNode);
    } else {
      return Promise.reject('ERR_FAIL_TO_VERIFY_STE_SIGNATURE');
    }
  }

  const parseResult = {
    samlContent: samlContent,
    extract: extract(samlContent, extractorFields),
  };

  /**
   *  Validation part: validate the context of response after signature is verified and decrpyted (optional)
   */
  const targetEntityMetadata = from.entityMeta;
  const issuer = targetEntityMetadata.getEntityID();
  const extractedProperties = parseResult.extract;

  // unmatched issuer
  if (
    (parserType === 'LogoutResponse' || parserType === 'SAMLResponse')
    && extractedProperties
    && extractedProperties.issuer !== issuer
  ) {
    return Promise.reject('ERR_UNMATCH_ISSUER');
  }

  // invalid session time
  if (
    parserType === 'SAMLResponse'
    && !verifyTime(
      undefined,
      extractedProperties.sessionIndex.sessionNotOnOrAfter
    )
  ) {
    return Promise.reject('ERR_EXPIRED_SESSION');
  }

  // invalid time
  // 2.4.1.2 https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
  if (
    parserType === 'SAMLResponse'
    && extractedProperties.conditions
    && !verifyTime(
      extractedProperties.conditions.notBefore,
      extractedProperties.conditions.notOnOrAfter
    )
  ) {
    return Promise.reject('ERR_SUBJECT_UNCONFIRMED');
  }

  return Promise.resolve(parseResult);
}

function checkStatus(content: string, parserType: string): Promise<string> {

  // only check response parser
  if (parserType !== urlParams.samlResponse && parserType !== urlParams.logoutResponse) {
    return Promise.resolve('SKIPPED');
  }

  const fields = parserType === urlParams.samlResponse
    ? loginResponseStatusFields
    : logoutResponseStatusFields;

  const {top, second} = extract(content, fields);

  // only resolve when top-tier status code is success
  if (top === StatusCode.Success) {
    return Promise.resolve('OK');
  }

  if (!top) {
    throw new Error('ERR_UNDEFINED_STATUS');
  }

  // returns a detailed error for two-tier error code
  throw new Error(`ERR_FAILED_STATUS with top tier code: ${top}, second tier code: ${second}`);
}

export function flow(options): Promise<FlowResult> {

  const binding = options.binding;
  const parserType = options.parserType;

  options.supportBindings = [BindingNamespace.Redirect, BindingNamespace.Post];
  // saml response only allows POST
  if (parserType === ParserType.SAMLResponse) {
    options.supportBindings = [BindingNamespace.Post];
  }

  if (binding === bindDict.post) {
    return postFlow(options);
  }

  if (binding === bindDict.redirect) {
    return redirectFlow(options);
  }

  return Promise.reject('ERR_UNEXPECTED_FLOW');

}
