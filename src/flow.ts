import {base64Decode} from './utility.js';
import {verifyTime} from './validator.js';
import libsaml from './libsaml.js';
import * as uuid from 'uuid'
import {select} from 'xpath';
import {DOMParser} from '@xmldom/xmldom';
import {sendArtifactResolve} from "./soap.js";
import {
    extract,
    type  ExtractorFields,
    loginRequestFields,
    loginResponseFields,
    loginResponseStatusFields,
    loginArtifactResponseStatusFields,
    logoutRequestFields,
    logoutResponseFields,
    logoutResponseStatusFields
} from './extractor.js';

import {BindingNamespace, ParserType, StatusCode, wording} from './urn.js';


const bindDict = wording.binding;
const urlParams = wording.urlParams;

export interface FlowResult {
    samlContent: string;
    extract: any;
    sigAlg?: string | null;
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
async function redirectFlow(options): Promise<FlowResult> {

    const {request, parserType, self, checkSignature = true, from} = options;
    const {query, octetString} = request;
    const {SigAlg: sigAlg, Signature: signature} = query;

    const targetEntityMetadata = from.entityMeta;

    // ?SAMLRequest= or ?SAMLResponse=
    const direction = libsaml.getQueryParamByType(parserType);
    const content = query[direction];

    // query must contain the saml content
    if (content === undefined) {
        return Promise.reject('ERR_REDIRECT_FLOW_BAD_ARGS');
    }

    /*  const xmlString = inflateString(decodeURIComponent(content));*/

    // @ts-ignore
    let {xml: xmlString} = libsaml.validateAndInflateSamlResponse(content);
    // validate the xml
    try {
        let result = await libsaml.isValidXml(xmlString);
    } catch (e) {
        return Promise.reject('ERR_INVALID_XML');
    }

    // check status based on different scenarios
    await checkStatus(xmlString, parserType);

    let assertion: string = '';

    if (parserType === urlParams.samlResponse) {
        // Extract assertion shortcut
        const verifiedDoc = extract(xmlString, [{
            key: 'assertion',
            localPath: ['~Response', 'Assertion'],
            attributes: [],
            context: true
        }]);
        if (verifiedDoc && verifiedDoc.assertion) {
            assertion = verifiedDoc.assertion as string;
        }
    }

    const extractorFields = getDefaultExtractorFields(parserType, assertion.length > 0 ? assertion : null);

    const parseResult: { samlContent: string, extract: any, sigAlg: (string | null) } = {
        samlContent: xmlString,
        sigAlg: null,
        extract: extract(xmlString, extractorFields),
    };

    // see if signature check is required
    // only verify message signature is enough
    if (checkSignature) {
        if (!signature || !sigAlg) {
            return Promise.reject('ERR_MISSING_SIG_ALG');
        }

        // put the below two assignments into verifyMessageSignature function
        const base64Signature = Buffer.from(decodeURIComponent(signature), 'base64');
        const decodeSigAlg = decodeURIComponent(sigAlg);

        const verified = libsaml.verifyMessageSignature(targetEntityMetadata, octetString, base64Signature, sigAlg);

        if (!verified) {
            // Fail to verify message signature
            return Promise.reject('ERR_FAILED_MESSAGE_SIGNATURE_VERIFICATION');
        }

        parseResult.sigAlg = decodeSigAlg;
    }

    /**
     *  Validation part: validate the context of response after signature is verified and decrypted (optional)
     */
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
    // only run the verifyTime when `SessionNotOnOrAfter` exists
    if (
        parserType === 'SAMLResponse'
        && extractedProperties.sessionIndex.sessionNotOnOrAfter
        && !verifyTime(
            undefined,
            extractedProperties.sessionIndex.sessionNotOnOrAfter,
            self.entitySetting.clockDrifts
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
            extractedProperties.conditions.notOnOrAfter,
            self.entitySetting.clockDrifts
        )
    ) {
        return Promise.reject('ERR_SUBJECT_UNCONFIRMED');
    }

    if (parserType === 'SAMLResponse') {
        let destination = extractedProperties?.response?.destination
        let isExit = self.entitySetting?.assertionConsumerService?.filter((item: { Location: any; }) => {
            return item?.Location === destination
        })
        if (isExit?.length === 0) {
            return Promise.reject('ERR_Destination_URL');
        }
    }


    return Promise.resolve(parseResult);
}

// proceed the post flow
async function postFlow(options): Promise<FlowResult> {

    const {
        soap = false,
        request,
        from,
        self,
        parserType,
        checkSignature = true
    } = options;

    const {body} = request;
    const direction = libsaml.getQueryParamByType(parserType);
    let encodedRequest = '';

    let samlContent = '';
    if (soap === false) {
        encodedRequest = body[direction];
        // @ts-ignore
        samlContent = String(base64Decode(encodedRequest))
    }
    /** 增加判断是不是Soap 工件绑定*/
    if (soap) {
        const metadata = {

            idp: from.entityMeta,
            sp: self.entityMeta,
        };
        const spSetting = self.entitySetting;
        let ID = '_' + uuid.v4();
        let url = metadata.idp.getArtifactResolutionService(bindDict.soap)
        let samlSoapRaw = libsaml.replaceTagsByValue(libsaml.defaultArtifactResolveTemplate.context, {
            ID: ID,
            Destination: url,
            Issuer: metadata.sp.getEntityID(),
            IssueInstant: new Date().toISOString(),
            Art: request.Art
        })
        if (!metadata.idp.isWantAuthnRequestsSigned()) {
            samlContent = await sendArtifactResolve(url, samlSoapRaw)
        }
        if (metadata.idp.isWantAuthnRequestsSigned()) {
            const {
                privateKey,
                privateKeyPass,
                requestSignatureAlgorithm: signatureAlgorithm,
                transformationAlgorithms
            } = spSetting;
            let signatureSoap = libsaml.constructSAMLSignature({
                referenceTagXPath: "//*[local-name(.)='ArtifactResolve']",
                isMessageSigned: false,
                isBase64Output: false,
                transformationAlgorithms: transformationAlgorithms,
                privateKey,
                privateKeyPass,
                signatureAlgorithm,
                rawSamlMessage: samlSoapRaw,
                signingCert: metadata.sp.getX509Certificate('signing'),
                signatureConfig: {
                    prefix: 'ds',
                    location: {
                        reference: "//*[local-name(.)='Issuer']",
                        action: 'after'
                    }
                }
            })
            samlContent = await sendArtifactResolve(url, signatureSoap)
        }
    }


    const verificationOptions = {
        metadata: from.entityMeta,
        signatureAlgorithm: from.entitySetting.requestSignatureAlgorithm,
    };
    /** 断言是否加密应根据响应里面的字段判断*/
    let decryptRequired = from.entitySetting.isAssertionEncrypted;
    let extractorFields: ExtractorFields = [];

    // validate the xml first
    let res = await libsaml.isValidXml(samlContent).catch((error) => {
        return Promise.reject('ERR_EXCEPTION_VALIDATE_XML');
    });

    if (res !== true) {
        return Promise.reject('ERR_EXCEPTION_VALIDATE_XML');
    }
    if (parserType !== urlParams.samlResponse) {
        extractorFields = getDefaultExtractorFields(parserType, null);
    }
    // check status based on different scenarios
         await checkStatus(samlContent, parserType,soap);
    /**检查签名顺序 */

    /*  if (
        checkSignature &&
        from.entitySetting.messageSigningOrder === MessageSignatureOrder.ETS
      ) {
        console.log("===============我走的这里=========================")
        const [verified, verifiedAssertionNode,isDecryptRequired] = libsaml.verifySignature(samlContent, verificationOptions);
        console.log(verified);
        console.log("verified")
        decryptRequired = isDecryptRequired
        if (!verified) {
          return Promise.reject('ERR_FAIL_TO_VERIFY_ETS_SIGNATURE');
        }
        if (!decryptRequired) {
          extractorFields = getDefaultExtractorFields(parserType, verifiedAssertionNode);
        }
      }*/
    if (soap === true) {
        const [verified, verifiedAssertionNode, isDecryptRequired] = libsaml.verifySignatureSoap(samlContent, verificationOptions);
        decryptRequired = isDecryptRequired
        if (!verified) {
            return Promise.reject('ERR_FAIL_TO_VERIFY_ETS_SIGNATURE');
        }

        if (!decryptRequired) {
            extractorFields = getDefaultExtractorFields(parserType, verifiedAssertionNode);
        }
        if (parserType === 'SAMLResponse' && decryptRequired) {
            // 1. 解密断言
            const [decryptedSAML, decryptedAssertion] = await libsaml.decryptAssertionSoap(self, samlContent);
            // 2. 检查解密后的断言是否包含签名
            const assertionDoc = new DOMParser().parseFromString(decryptedAssertion, 'text/xml');
            const assertionSignatureNodes = select("./*[local-name()='Signature']", assertionDoc.documentElement);

            // 3. 如果存在签名则验证
            if (assertionSignatureNodes.length > 0) {
                // 3.1 创建新的验证选项（保持原配置）
                const assertionVerificationOptions = {
                    ...verificationOptions,
                    isAssertion: true // 添加标识表示正在验证断言
                };

                // 3.2 验证断言签名
                const [assertionVerified, result] = libsaml.verifySignatureSoap(decryptedAssertion, assertionVerificationOptions);
                if (!assertionVerified) {
                    console.error("解密后的断言签名验证失败");
                    return Promise.reject('ERR_FAIL_TO_VERIFY_ASSERTION_SIGNATURE');
                }
                if (assertionVerified) {
                    // @ts-ignore

                    samlContent = result
                    extractorFields = getDefaultExtractorFields(parserType, result);
                }
            } else {
                samlContent = decryptedAssertion
                extractorFields = getDefaultExtractorFields(parserType, decryptedAssertion);
            }
        }
    }
    if (soap === false) {
        const [verified, verifiedAssertionNode, isDecryptRequired] = libsaml.verifySignature(samlContent, verificationOptions);
        decryptRequired = isDecryptRequired
        if (!verified) {
            return Promise.reject('ERR_FAIL_TO_VERIFY_ETS_SIGNATURE');
        }
        if (!decryptRequired) {
            extractorFields = getDefaultExtractorFields(parserType, verifiedAssertionNode);
        }
        if (parserType === 'SAMLResponse' && decryptRequired) {
            const result = await libsaml.decryptAssertion(self, samlContent);
            samlContent = result[0];
            extractorFields = getDefaultExtractorFields(parserType, result[1]);
        }
    }

    // verify the signatures (the response is signed then encrypted, then decrypt first then verify)

    /*  if (
        checkSignature &&
        from.entitySetting.messageSigningOrder === MessageSignatureOrder.STE
      ) {
        const [verified, verifiedAssertionNode,isDecryptRequired] = libsaml.verifySignature(samlContent, verificationOptions);
        decryptRequired = isDecryptRequired
        if (verified) {
          extractorFields = getDefaultExtractorFields(parserType, verifiedAssertionNode);
        } else {
          return Promise.reject('ERR_FAIL_TO_VERIFY_STE_SIGNATURE');
        }
      }*/

    const parseResult = {
        samlContent: samlContent,
        extract: extract(samlContent, extractorFields),
    };

    /**
     *  Validation part: validate the context of response after signature is verified and decrypted (optional)
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
    // only run the verifyTime when `SessionNotOnOrAfter` exists
    if (
        parserType === 'SAMLResponse'
        && extractedProperties.sessionIndex.sessionNotOnOrAfter
        && !verifyTime(
            undefined,
            extractedProperties.sessionIndex.sessionNotOnOrAfter,
            self.entitySetting.clockDrifts
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
            extractedProperties.conditions.notOnOrAfter,
            self.entitySetting.clockDrifts
        )
    ) {
        return Promise.reject('ERR_SUBJECT_UNCONFIRMED');
    }
    //valid destination
    //There is no validation of the response here. The upper-layer application
    // should verify the result by itself to see if the destination is equal to the SP acs and
    // whether the response.id is used to prevent replay attacks.
    /*
        let destination = extractedProperties?.response?.destination
        let isExit = self.entitySetting?.assertionConsumerService?.filter((item) => {
            return item?.Location === destination
        })
        if (isExit?.length === 0) {
            return Promise.reject('ERR_Destination_URL');
        }
        if (parserType === 'SAMLResponse') {
            let destination = extractedProperties?.response?.destination
            let isExit = self.entitySetting?.assertionConsumerService?.filter((item: { Location: any; }) => {
                return item?.Location === destination
            })
            if (isExit?.length === 0) {
                return Promise.reject('ERR_Destination_URL');
            }
        }
    */


    return Promise.resolve(parseResult);
}

// proceed the post Artifact flow
async function postArtifactFlow(options): Promise<FlowResult> {

    const {
        request,
        from,
        self,
        parserType,
        checkSignature = true
    } = options;

    const {body} = request;

    const direction = libsaml.getQueryParamByType(parserType);
    const encodedRequest = body[direction];

    let samlContent = String(base64Decode(encodedRequest));

    const verificationOptions = {
        metadata: from.entityMeta,
        signatureAlgorithm: from.entitySetting.requestSignatureAlgorithm,
    };
    /** 断言是否加密应根据响应里面的字段判断*/
    let decryptRequired = from.entitySetting.isAssertionEncrypted;
    let extractorFields: ExtractorFields = [];

    // validate the xml first
    let res = await libsaml.isValidXml(samlContent);
    if (parserType !== urlParams.samlResponse) {
        extractorFields = getDefaultExtractorFields(parserType, null);
    }
    // check status based on different scenarios
    await checkStatus(samlContent, parserType);
    /**检查签名顺序 */

    /*  if (
        checkSignature &&
        from.entitySetting.messageSigningOrder === MessageSignatureOrder.ETS
      ) {
        console.log("===============我走的这里=========================")
        const [verified, verifiedAssertionNode,isDecryptRequired] = libsaml.verifySignature(samlContent, verificationOptions);
        console.log(verified);
        console.log("verified")
        decryptRequired = isDecryptRequired
        if (!verified) {
          return Promise.reject('ERR_FAIL_TO_VERIFY_ETS_SIGNATURE');
        }
        if (!decryptRequired) {
          extractorFields = getDefaultExtractorFields(parserType, verifiedAssertionNode);
        }
      }*/

    const [verified, verifiedAssertionNode, isDecryptRequired] = libsaml.verifySignature(samlContent, verificationOptions);
    decryptRequired = isDecryptRequired
    if (!verified) {
        return Promise.reject('ERR_FAIL_TO_VERIFY_ETS_SIGNATURE');
    }
    if (!decryptRequired) {
        extractorFields = getDefaultExtractorFields(parserType, verifiedAssertionNode);
    }
    if (parserType === 'SAMLResponse' && decryptRequired) {
        const result = await libsaml.decryptAssertion(self, samlContent);
        samlContent = result[0];
        extractorFields = getDefaultExtractorFields(parserType, result[1]);
    }

    // verify the signatures (the response is signed then encrypted, then decrypt first then verify)

    /*  if (
        checkSignature &&
        from.entitySetting.messageSigningOrder === MessageSignatureOrder.STE
      ) {
        const [verified, verifiedAssertionNode,isDecryptRequired] = libsaml.verifySignature(samlContent, verificationOptions);
        decryptRequired = isDecryptRequired
        if (verified) {
          extractorFields = getDefaultExtractorFields(parserType, verifiedAssertionNode);
        } else {
          return Promise.reject('ERR_FAIL_TO_VERIFY_STE_SIGNATURE');
        }
      }*/

    const parseResult = {
        samlContent: samlContent,
        extract: extract(samlContent, extractorFields),
    };

    /**
     *  Validation part: validate the context of response after signature is verified and decrypted (optional)
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
    // only run the verifyTime when `SessionNotOnOrAfter` exists
    if (
        parserType === 'SAMLResponse'
        && extractedProperties.sessionIndex.sessionNotOnOrAfter
        && !verifyTime(
            undefined,
            extractedProperties.sessionIndex.sessionNotOnOrAfter,
            self.entitySetting.clockDrifts
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
            extractedProperties.conditions.notOnOrAfter,
            self.entitySetting.clockDrifts
        )
    ) {
        return Promise.reject('ERR_SUBJECT_UNCONFIRMED');
    }
    //valid destination
    //There is no validation of the response here. The upper-layer application
    // should verify the result by itself to see if the destination is equal to the SP acs and
    // whether the response.id is used to prevent replay attacks.
    let destination = extractedProperties?.response?.destination
    let isExit = self.entitySetting?.assertionConsumerService?.filter((item) => {
        return item?.Location === destination
    })
    if (isExit?.length === 0) {
        return Promise.reject('ERR_Destination_URL');
    }
    if (parserType === 'SAMLResponse') {
        let destination = extractedProperties?.response?.destination
        let isExit = self.entitySetting?.assertionConsumerService?.filter((item: { Location: any; }) => {
            return item?.Location === destination
        })
        if (isExit?.length === 0) {
            return Promise.reject('ERR_Destination_URL');
        }
    }


    return Promise.resolve(parseResult);
}


// proceed the post simple sign binding flow
async function postSimpleSignFlow(options): Promise<FlowResult> {

    const {request, parserType, self, checkSignature = true, from} = options;

    const {body, octetString} = request;

    const targetEntityMetadata = from.entityMeta;

    // ?SAMLRequest= or ?SAMLResponse=
    const direction = libsaml.getQueryParamByType(parserType);
    const encodedRequest: string = body[direction];
    const sigAlg: string = body['SigAlg'];
    const signature: string = body['Signature'];

    // query must contain the saml content
    if (encodedRequest === undefined) {
        return Promise.reject('ERR_SIMPLESIGN_FLOW_BAD_ARGS');
    }

    const xmlString = String(base64Decode(encodedRequest));

    // validate the xml
    try {
        await libsaml.isValidXml(xmlString);
    } catch (e) {
        return Promise.reject('ERR_INVALID_XML');
    }

    // check status based on different scenarios
    await checkStatus(xmlString, parserType);

    let assertion: string = '';

    if (parserType === urlParams.samlResponse) {
        // Extract assertion shortcut
        const verifiedDoc = extract(xmlString, [{
            key: 'assertion',
            localPath: ['~Response', 'Assertion'],
            attributes: [],
            context: true
        }]);
        if (verifiedDoc && verifiedDoc.assertion) {
            assertion = verifiedDoc.assertion as string;
        }
    }

    const extractorFields = getDefaultExtractorFields(parserType, assertion.length > 0 ? assertion : null);

    const parseResult: { samlContent: string, extract: any, sigAlg: (string | null) } = {
        samlContent: xmlString,
        sigAlg: null,
        extract: extract(xmlString, extractorFields),
    };

    // see if signature check is required
    // only verify message signature is enough
    if (checkSignature) {
        if (!signature || !sigAlg) {
            return Promise.reject('ERR_MISSING_SIG_ALG');
        }

        // put the below two assignments into verifyMessageSignature function
        const base64Signature = Buffer.from(signature, 'base64');

        const verified = libsaml.verifyMessageSignature(targetEntityMetadata, octetString, base64Signature, sigAlg);

        if (!verified) {
            // Fail to verify message signature
            return Promise.reject('ERR_FAILED_MESSAGE_SIGNATURE_VERIFICATION');
        }

        parseResult.sigAlg = sigAlg;
    }

    /**
     *  Validation part: validate the context of response after signature is verified and decrypted (optional)
     */
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
    // only run the verifyTime when `SessionNotOnOrAfter` exists
    if (
        parserType === 'SAMLResponse'
        && extractedProperties.sessionIndex.sessionNotOnOrAfter
        && !verifyTime(
            undefined,
            extractedProperties.sessionIndex.sessionNotOnOrAfter,
            self.entitySetting.clockDrifts
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
            extractedProperties.conditions.notOnOrAfter,
            self.entitySetting.clockDrifts
        )
    ) {
        return Promise.reject('ERR_SUBJECT_UNCONFIRMED');
    }

    if (parserType === 'SAMLResponse') {
        let destination = extractedProperties?.response?.destination
        let isExit = self.entitySetting?.assertionConsumerService?.filter((item: { Location: any; }) => {
            return item?.Location === destination
        })
        if (isExit?.length === 0) {
            return Promise.reject('ERR_Destination_URL');
        }
    }


    return Promise.resolve(parseResult);
}


function checkStatus(content: string, parserType: string, soap?: boolean): Promise<string> {

    // only check response parser
    if (parserType !== urlParams.samlResponse && parserType !== urlParams.logoutResponse) {
        return Promise.resolve('SKIPPED');
    }

    let  fields = parserType === urlParams.samlResponse
        ? loginResponseStatusFields
        : logoutResponseStatusFields;
 if(soap === true){
     fields = parserType === urlParams.samlResponse
         ? loginArtifactResponseStatusFields
         : logoutResponseStatusFields;
 }

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

    options.supportBindings = [BindingNamespace.Redirect, BindingNamespace.Post, BindingNamespace.SimpleSign];
    // saml response  allows POST, REDIRECT
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


    return Promise.reject('ERR_UNEXPECTED_FLOW');

}
