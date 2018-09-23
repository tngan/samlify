import { inflateString, base64Decode } from './utility';
const bindDict = wording.binding;
import libsaml from './libsaml';
import {
  extract,
  loginRequestFields,
  loginResponseFields,
  logoutRequestFields,
  logoutResponseFields
} from './extractor';

import {
  BindingNamespace,
  ParserType,
  wording,
  MessageSignatureOrder
} from './urn';

const urlParams = wording.urlParams;

// get the default extractor fields based on the parserType
function getDefaultExtractorFields(parserType: ParserType, assertion?: any) {
  switch (parserType) {
    case ParserType.SAMLRequest:
      return loginRequestFields;
    case ParserType.SAMLResponse:
      if (assertion) {
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
    throw new Error('ERR_REDIRECT_FLOW_BAD_ARGS');
  }

  const xmlString = inflateString(decodeURIComponent(content));
  // validate the response xml
  if (parserType === urlParams.samlResponse) {
    try {
      await libsaml.isValidXml(xmlString);
    } catch (e) {
      throw new Error('ERR_INVALID_XML');
    }
  }

  const extractorFields = getDefaultExtractorFields(parserType);

  const parseResult: { samlContent: string, extract: any, sigAlg: string } = {
    samlContent: xmlString,
    sigAlg: undefined,
    extract: extract(xmlString, extractorFields),
  };

  // see if signature check is required
  // only verify message signature is enough
  if (checkSignature) {
    // Throw error when missing signature or signature algorithm
    if (!signature || !sigAlg) {
      throw new Error('ERR_MISSING_SIG_ALG');
    }

    // put the below two assignemnts into verifyMessageSignature function
    const base64Signature = new Buffer(decodeURIComponent(signature), 'base64');
    const decodeSigAlg = decodeURIComponent(sigAlg);
    
    const verified = libsaml.verifyMessageSignature(targetEntityMetadata, octetString, base64Signature, sigAlg);

    if (verified) {
      parseResult.sigAlg = decodeSigAlg;
    }
    // Fail to verify message signature
    throw new Error('ERR_FAILED_MESSAGE_SIGNATURE_VERIFICATION');
  }

  return parseResult;
}

// proceed the post flow
async function postFlow(options) {

  let extractorFields = [];

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

  //verify signature before decryption if IDP encrypted then signed the message
  if (
    checkSignature &&
    from.entitySetting.messageSigningOrder === MessageSignatureOrder.ETS
  ) {
    const [verified, verifiedAssertionNode] = libsaml.verifySignature(samlContent, verificationOptions);
    if (verified) {
      extractorFields = getDefaultExtractorFields(parserType, verifiedAssertionNode);
    }
    return [false, null];
  }

  if (parserType === 'SAMLResponse' && from.entitySetting.isAssertionEncrypted) {
    samlContent = await libsaml.decryptAssertion(self, samlContent);
  }

  if (parserType === 'SAMLResponse') {
    await libsaml.isValidXml(samlContent);
  }

  // verify the signatures (for both assertion/message)
  if (
    checkSignature &&
    from.entitySetting.messageSigningOrder === MessageSignatureOrder.STE
  ) {

    const [verified, verifiedAssertionNode] = libsaml.verifySignature(samlContent, verificationOptions);

    if (verified) {
      extractorFields = getDefaultExtractorFields(parserType, verifiedAssertionNode);
    }
    
    return [false, null];
  }


  const parseResult = {
    samlContent: samlContent,
    extract: extract(samlContent, extractorFields),
  };

  // TODO: basic validator (issuer, timer)
  // const targetEntityMetadata = from.entityMeta;
  // const issuer = targetEntityMetadata.getEntityID();

  return parseResult;
}

export async function flow(options) {

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

}
