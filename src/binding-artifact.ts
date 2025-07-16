/**
 * @file binding-post.ts
 * @author tngan
 * @desc Binding-level API, declare the functions using POST binding
 */
import {checkStatus} from "./flow.js";
import {ParserType, StatusCode, wording} from './urn.js';
import type {BindingContext} from './entity.js';
import libsaml from './libsaml.js';
import libsamlSoap from './libsamlSoap.js';
import utility, {get} from './utility.js';
import {fileURLToPath} from "node:url";
import * as uuid from 'uuid'
import {
    IdentityProviderConstructor as IdentityProvider,
    ServiceProviderConstructor as ServiceProvider
} from "./types.js";
import {
    artifactResolveFields,
    extract,
    ExtractorFields,
    loginRequestFields,
    loginResponseFields,
    logoutRequestFields,
    logoutResponseFields
} from "./extractor.js";
import {verifyTime} from "./validator.js";
import {sendArtifactResolve} from "./soap.js";
import path from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


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

const binding = wording.binding;

/**
 * @desc Generate a base64 encoded login request
 * @param  {string} referenceTagXPath           reference uri
 * @param  {object} entity                      object includes both idp and sp
 * @param customTagReplacement
 */
function soapLoginRequest(referenceTagXPath: string, entity: any, customTagReplacement?: (template: string) => BindingContext): any {
    const metadata = {
        idp: entity.idp.entityMeta,
        sp: entity.sp.entityMeta,
        inResponse: entity?.inResponse,
        relayState: entity?.relayState
    };
    const spSetting = entity.sp.entitySetting;
    let id: string = '';
    let id2: string = spSetting.generateID()
    let soapTemplate = '';
    let Response = ''
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
        const {
            privateKey,
            privateKeyPass,
            requestSignatureAlgorithm: signatureAlgorithm,
            transformationAlgorithms
        } = spSetting;
                if (metadata.idp.isWantAuthnRequestsSigned()) {
                  Response = libsaml.constructSAMLSignature({
                        referenceTagXPath,
                        privateKey,
                        privateKeyPass,
                        signatureAlgorithm,
                        transformationAlgorithms,
                        rawSamlMessage: rawSamlRequest,
                        isBase64Output: false,
                        signingCert: metadata.sp.getX509Certificate('signing'),
                      signatureConfig: spSetting.signatureConfig || {
                          prefix: 'ds',
                          location: {reference: "/*[local-name(.)='AuthnRequest']/!*[local-name(.)='Issuer']", action: 'after'},
                      }
                    })
                    soapTemplate = libsaml.replaceTagsByValue(libsaml.defaultArtAuthnRequestTemplate.context, {
                        ID: id2,
                        IssueInstant: new Date().toISOString(),
                        InResponseTo: metadata.inResponse ?? "",
                        Issuer: metadata.sp.getEntityID(),
                        AuthnRequest: Response
                    } as any);
                }else{
                    soapTemplate = libsaml.replaceTagsByValue(libsaml.defaultArtAuthnRequestTemplate.context, {
                        ID: id2,
                        IssueInstant: new Date().toISOString(),
                        InResponseTo: metadata.inResponse ?? "",
                        Issuer: metadata.sp.getEntityID(),
                        AuthnRequest: rawSamlRequest
                    } as any);
                }


        /** 构建响应签名*/
        // No need to embeded XML signature
        return libsaml.constructSAMLSignature({
            referenceTagXPath: "/*[local-name(.)='Envelope']/*[local-name(.)='Body']/*[local-name(.)='ArtifactResponse']",
            privateKey,
            privateKeyPass,
            signatureAlgorithm,
            transformationAlgorithms,
            rawSamlMessage: soapTemplate,
            isBase64Output: false,
            isMessageSigned: false,
            signingCert: metadata.sp.getX509Certificate('signing'),
            signatureConfig: {
                prefix: 'ds',
                location: {
                    reference: "/*[local-name(.)='Envelope']/*[local-name(.)='Body']/*[local-name(.)='ArtifactResponse']/*[local-name(.)='Issuer']",
                    action: 'after'
                }
            },
        });
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
async function soapLoginResponse(requestInfo: any = {}, entity: any, user: any = {}, customTagReplacement?: (template: string) => BindingContext, encryptThenSign: boolean = false, AttributeStatement = []): Promise<BindingContext> {
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
            const template = customTagReplacement(idpSetting.loginResponseTemplate.context);
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

        // console.debug('after message signed', rawSamlResponse);

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
        if (encryptThenSign && (spSetting.wantMessageSigned || !metadata.sp.isWantAssertionsSigned())) {
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
        return Promise.resolve({
            id,
            context: utility.base64Encode(rawSamlResponse),
        });

    }


    throw new Error('ERR_GENERATE_POST_LOGIN_RESPONSE_MISSING_METADATA');
}

async function parseLoginRequestResolve(params: {
    idp: IdentityProvider,
    sp: ServiceProvider,
    xml: string
}) {
    let {idp, sp, xml,} = params;
    const verificationOptions = {
        metadata: idp.entityMeta,
        signatureAlgorithm: idp.entitySetting.requestSignatureAlgorithm,
    };

    let res = await libsaml.isValidXml(xml, true).catch((error) => {
        return Promise.reject('ERR_EXCEPTION_VALIDATE_XML');
    });

    if (res !== true) {
        return Promise.reject('ERR_EXCEPTION_VALIDATE_XML');
    }

    /** 首先先验证签名*/

// @ts-ignore

    let [verify, xmlString, isEncrypted, noSignature] = await libsamlSoap.verifyAndDecryptSoapMessage(xml, verificationOptions)
    if (!verify) {
        return Promise.reject('ERR_FAIL_TO_VERIFY_SIGNATURE');
    }
    const parseResult = {
        samlContent: xmlString,
        extract: extract(xmlString as string, artifactResolveFields),
    };
    /**
     *  Validation part: validate the context of response after signature is verified and decrypted (optional)
     */
    const targetEntityMetadata = sp.entityMeta;
    const issuer = targetEntityMetadata.getEntityID();
    const extractedProperties = parseResult.extract;
    // unmatched issuer
    if (extractedProperties.issuer !== issuer
    ) {
        return Promise.reject('ERR_UNMATCH_ISSUER');
    }


    // invalid session time
    // only run the verifyTime when `SessionNotOnOrAfter` exists
    if (!verifyTime(
        undefined,
        new Date(new Date(extractedProperties.request.issueInstant).getTime() + 5 * 60 * 1000).toISOString(),
        sp.entitySetting.clockDrifts
    )
    ) {
        return Promise.reject('ERR_EXPIRED_SESSION');
    }


    return Promise.resolve(parseResult);
}

async function parseLoginResponseResolve(params: { idp: IdentityProvider, sp: ServiceProvider, art: string }) {
    let {idp, sp, art} = params;

    const metadata = {
        idp: idp.entityMeta,
        sp: sp.entityMeta,
    };
    const verificationOptions = {
        metadata: idp.entityMeta,
        signatureAlgorithm: idp.entitySetting.requestSignatureAlgorithm,
    };
    let parserType = 'SAMLResponse' as ParserType
    /** 断言是否加密应根据响应里面的字段判断*/
    let decryptRequired = idp.entitySetting.isAssertionEncrypted;
    let extractorFields: ExtractorFields = [];
    let samlContent = ''
    const spSetting = sp.entitySetting;
    let ID = '_' + uuid.v4();
    let url = metadata.idp.getArtifactResolutionService('soap') as string
    let samlSoapRaw = libsaml.replaceTagsByValue(libsaml.defaultArtifactResolveTemplate.context, {
        ID: ID,
        Destination: url,
        Issuer: metadata.sp.getEntityID(),
        IssueInstant: new Date().toISOString(),
        Art: art
    })
    if (!metadata.idp.isWantAuthnRequestsSigned()) {

        samlContent = await sendArtifactResolve(url, samlSoapRaw)
        // check status based on different scenarios
        // validate the xml
        try {
            await libsaml.isValidXml(samlContent, true);
        } catch (e) {
            return Promise.reject('ERR_INVALID_XML');
        }
        await checkStatus(samlContent, parserType,true);
    }

    if (metadata.idp.isWantAuthnRequestsSigned()) {
        const {
            privateKey,
            privateKeyPass,
            requestSignatureAlgorithm: signatureAlgorithm,
            transformationAlgorithms
        } = spSetting;
        //@ts-ignore
        let signatureSoap = libsaml.constructSAMLSignature({
            referenceTagXPath: "//*[local-name(.)='ArtifactResolve']",
            isMessageSigned: false,
            isBase64Output: false,
            transformationAlgorithms: transformationAlgorithms,
            //@ts-ignore
            privateKey,
            privateKeyPass,
            //@ts-ignore
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
        // check status based on different scenarios
        // validate the xml
        try {
            await libsaml.isValidXml(samlContent, true);
        } catch (e) {
            return Promise.reject('ERR_INVALID_XML');
        }
        await checkStatus(samlContent, parserType,true);
        const [verified1, verifiedAssertionNode1, isDecryptRequired1, noSignature1] = await libsamlSoap.verifyAndDecryptSoapMessage(samlContent, verificationOptions);
        /*            decryptRequired = isDecryptRequired*/
        if (!verified1) {
            return Promise.reject('ERR_FAIL_TO_VERIFY_ETS_SIGNATURE');
        }
        samlContent = verifiedAssertionNode1 as string
        const [verified, verifiedAssertionNode, isDecryptRequired, noSignature] = libsaml.verifySignature(samlContent, verificationOptions);

        if (isDecryptRequired && noSignature) {
            const result = await libsaml.decryptAssertion(sp, samlContent);
            samlContent = result[0];
            extractorFields = getDefaultExtractorFields(parserType, result[1]);
        }
        if (!verified && !noSignature && !isDecryptRequired) {
            return Promise.reject('ERR_FAIL_TO_VERIFY_ETS_SIGNATURE');
        }
        if (!isDecryptRequired) {

            extractorFields = getDefaultExtractorFields(parserType, verifiedAssertionNode);
        }
        if (parserType === 'SAMLResponse' && isDecryptRequired && !noSignature) {
            const result = await libsaml.decryptAssertion(sp, samlContent);
            samlContent = result[0];
            extractorFields = getDefaultExtractorFields(parserType, result[1]);

        }
        const parseResult = {
            samlContent: samlContent,
            extract: extract(samlContent, extractorFields),
        };

        /**
         *  Validation part: validate the context of response after signature is verified and decrypted (optional)
         */
        const targetEntityMetadata = idp.entityMeta;
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
                sp.entitySetting.clockDrifts
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
                sp.entitySetting.clockDrifts
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


    const parseResult = {
        samlContent: samlContent,
        extract: extract(samlContent, extractorFields),
    };
    /**
     *  Validation part: validate the context of response after signature is verified and decrypted (optional)
     */
    const targetEntityMetadata = idp.entityMeta;
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
            sp.entitySetting.clockDrifts
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
            sp.entitySetting.clockDrifts
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

const artifactSignBinding = {
    parseLoginRequestResolve,
    soapLoginRequest,
    parseLoginResponseResolve,
    soapLoginResponse,


};

export default artifactSignBinding;
