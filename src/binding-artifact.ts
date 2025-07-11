/**
 * @file binding-post.ts
 * @author tngan
 * @desc Binding-level API, declare the functions using POST binding
 */

import {wording, namespace, StatusCode} from './urn.js';
import type {BindingContext} from './entity.js';
import libsaml from './libsaml.js';
import utility, {get} from './utility.js';

import * as uuid from 'uuid'
import {
    IdentityProviderConstructor as IdentityProvider,
    ServiceProviderConstructor as ServiceProvider
} from "./types.js";
import {extract, ExtractorFields, artifactResponseFields, artifactResolveFields} from "./extractor.js";
import {ExtractorResult} from "@microsoft/api-extractor";
import {
    loginRequestFields,
    loginResponseFields,
    loginResponseStatusFields,
    loginArtifactResponseStatusFields,
    logoutRequestFields,
    logoutResponseFields,
    logoutResponseStatusFields
} from './extractor.js'
import {verifyTime} from "./validator.js";

const binding = wording.binding;

/**
 * @desc Generate a base64 encoded login request
 * @param  {string} referenceTagXPath           reference uri
 * @param  {object} entity                      object includes both idp and sp
 * @param customTagReplacement
 */
function soapLoginRequest(referenceTagXPath: string, entity: any, customTagReplacement?: (template: string) => BindingContext): any {
    const metadata = {idp: entity.idp.entityMeta, sp: entity.sp.entityMeta, inResponse: entity?.inResponse,relayState:entity?.relayState};
    const spSetting = entity.sp.entitySetting;
    let id: string = '';
    let soapTemplate = ''
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

            let Response = libsaml.constructSAMLSignature({
                referenceTagXPath,
                privateKey,
                privateKeyPass,
                signatureAlgorithm,
                transformationAlgorithms,
                rawSamlMessage: rawSamlRequest,
                isBase64Output: false,
                isMessageSigned: true,
                signingCert: metadata.sp.getX509Certificate('signing'),
                signatureConfig: spSetting.signatureConfig || {
                    prefix: 'ds',
                    location: {
                        reference: "/*[local-name(.)='AuthnRequest']/*[local-name(.)='Issuer']",
                        action: 'after'
                    },
                }
            })
              soapTemplate = libsaml.replaceTagsByValue(libsaml.defaultArtAuthnRequestTemplate.context, {
                ID: id,
                IssueInstant: new Date().toISOString(),
                InResponseTo: metadata.inResponse ?? "",
                Issuer: metadata.sp.getEntityID(),
                AuthnRequest: Response
            } as any);
        }
        let Response2 = libsaml.constructSAMLSignature({
            referenceTagXPath: "//*[local-name()='ArtifactResponse']",
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
                    reference: "//*[local-name()='ArtifactResponse']/*[local-name()='Issuer']",
                    action: 'after'
                }
            },
        })
        /** 构建响应签名*/
        console.log(Response2)
        console.log("==================看一下==========================")
        // No need to embeded XML signature
        return Response2;
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
            // console.debug('sp wants assertion signed');
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
    console.log(xml)
    console.log("=============哈哈哈哈哈==================")
    let res = await libsaml.isValidXml(xml, true).catch((error) => {
        console.log(error)
        console.log("不符合Soap 规范")
        return Promise.reject('ERR_EXCEPTION_VALIDATE_XML');
    });

    if (res !== true) {
        return Promise.reject('ERR_EXCEPTION_VALIDATE_XML');
    }
    console.log('soapxml验证结果: ' + res)
    console.log("==================接下来开始验证签名======================")
    console.log(xml)
    /** 首先先验证签名*/
    let [verified, verifiedAssertionNode, isDecryptRequired, noSignature] = libsaml.verifySignatureSoap(xml, verificationOptions)

    if (noSignature || !verified) {
        return Promise.reject('ERR_FAIL_TO_VERIFY_SIGNATURE');
    }
    const parseResult = {
        samlContent: xml,
        extract: extract(xml, artifactResolveFields),
    };
    /**
     *  Validation part: validate the context of response after signature is verified and decrypted (optional)
     */
    const targetEntityMetadata = sp.entityMeta;
    const issuer = targetEntityMetadata.getEntityID();
    const extractedProperties = parseResult.extract;
    console.log(extractedProperties)
    console.log(issuer)
    console.log("================看一下==================")
    // unmatched issuer
    if (extractedProperties.issuer !== issuer
    ) {
        return Promise.reject('ERR_UNMATCH_ISSUER');
    }
    console.log(extractedProperties.request.issueInstant,
    )
    console.log(sp.entitySetting.clockDrifts)
    console.log("99999999999999999999")
    // invalid session time
    // only run the verifyTime when `SessionNotOnOrAfter` exists
    /*    if ( !verifyTime(
                undefined,
                extractedProperties.request.issueInstant,
                sp.entitySetting.clockDrifts
            )
        ) {
            return Promise.reject('ERR_EXPIRED_SESSION');
        }*/


    return Promise.resolve(parseResult);
}

async function parseLoginResponseResolve(params: { idp: IdentityProvider, sp: ServiceProvider, xml: string }) {
    let {idp, sp} = params;
}

const artifactSignBinding = {
    soapLoginRequest,
    soapLoginResponse,
    parseLoginRequestResolve,
    parseLoginResponseResolve
};

export default artifactSignBinding;
