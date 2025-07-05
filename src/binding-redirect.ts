/**
 * @file binding-redirect.ts
 * @author tngan
 * @desc Binding-level API, declare the functions using Redirect binding
 */
import utility, {get} from './utility.js';
import libsaml from './libsaml.js';
import type {BindingContext} from './entity.js';
import {IdentityProvider as Idp} from './entity-idp.js';
import {ServiceProvider as Sp} from './entity-sp.js';

import {namespace, wording} from './urn.js';

const binding = wording.binding;
const urlParams = wording.urlParams;

export interface BuildRedirectConfig {
    baseUrl: string;
    type: string;
    isSigned: boolean;
    context: string;
    entitySetting: any;
    relayState?: string;
}

/**
 * @private
 * @desc Helper of generating URL param/value pair
 * @param  {string} param     key
 * @param  {string} value     value of key
 * @param  {boolean} first    determine whether the param is the starting one in order to add query header '?'
 * @return {string}
 */
function pvPair(param: string, value: string, first?: boolean): string {
    return (first === true ? '?' : '&') + param + '=' + value;
}

/**
 * @private
 * @desc Refractored part of URL generation for login/logout request
 * @param  {string} type
 * @param  {boolean} isSigned
 * @param  {string} rawSamlRequest
 * @param  {object} entitySetting
 * @return {string}
 */
function buildRedirectURL(opts: BuildRedirectConfig) {
    const {
        baseUrl,
        type,
        isSigned,
        context,
        entitySetting,
    } = opts;
    let {relayState = ''} = opts;
    let noParams = true
    try {
        noParams = new URL(baseUrl)?.searchParams?.size === 0
    } catch {
        noParams = true
    }

    const queryParam = libsaml.getQueryParamByType(type);
    // In general, this xmlstring is required to do deflate -> base64 -> urlencode
    const samlRequest = encodeURIComponent(utility.base64Encode(utility.deflateString(context)));
    if (relayState !== '') {
        relayState = pvPair(urlParams.relayState, encodeURIComponent(relayState));
    }
    if (isSigned) {
        const sigAlg = pvPair(urlParams.sigAlg, encodeURIComponent(entitySetting.requestSignatureAlgorithm));
        const octetString = samlRequest + relayState + sigAlg;
        return baseUrl
            + pvPair(queryParam, octetString, noParams)
            + pvPair(urlParams.signature, encodeURIComponent(
                    libsaml.constructMessageSignature(
                        queryParam + '=' + octetString,
                        entitySetting.privateKey,
                        entitySetting.privateKeyPass,
                        undefined,
                        entitySetting.requestSignatureAlgorithm
                    ).toString()
                )
            );
    }
    return baseUrl + pvPair(queryParam, samlRequest + relayState, noParams);
}


/**
 * @desc Redirect URL for login request
 * @param  {object} entity                       object includes both idp and sp
 * @param  {function} customTagReplacement      used when developers have their own login response template
 * @return {string} redirect URL
 */
// @ts-ignore
function loginRequestRedirectURL(entity: {
    idp: Idp,
    sp: Sp,
    soap?: Boolean
}, customTagReplacement?: (template: string) => BindingContext): any {

    const metadata: any = {idp: entity.idp.entityMeta, sp: entity.sp.entityMeta, soap: entity.soap ?? false};
    const spSetting: any = entity.sp.entitySetting;
    let id: string = '';

    if (metadata && metadata.idp && metadata.sp) {
        const base = metadata.idp.getSingleSignOnService(binding.redirect);
        let rawSamlRequest: string;
        if (spSetting.loginRequestTemplate && customTagReplacement) {
            const info = customTagReplacement(spSetting.loginRequestTemplate);
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
                NameIDFormat: selectedNameIDFormat,
                AssertionConsumerServiceURL: metadata.sp.getAssertionConsumerService(binding.post),
                EntityID: metadata.sp.getEntityID(),
                AllowCreate: spSetting.allowCreate,
            } as any);
        }
        return {
            id,
            context: buildRedirectURL({
                context: rawSamlRequest,
                type: urlParams.samlRequest,
                isSigned: metadata.sp.isAuthnRequestSigned(),
                entitySetting: spSetting,
                baseUrl: base,
                relayState: spSetting.relayState,
            }),
        };
    }
    throw new Error('ERR_GENERATE_REDIRECT_LOGIN_REQUEST_MISSING_METADATA');

}
/**
 * @desc Redirect URL for login request
 * @param  {object} entity                       object includes both idp and sp
 * @param  {function} customTagReplacement      used when developers have their own login response template
 * @return {string} redirect URL
 */
// @ts-ignore
function loginRequestRedirectURLArt(entity: {
    idp: Idp,
    sp: Sp, inResponse?: string
}, customTagReplacement?: (template: string) => BindingContext): any {

    const metadata: any = {idp: entity.idp.entityMeta, sp: entity.sp.entityMeta, inResponse: entity.inResponse ?? false};
    const spSetting: any = entity.sp.entitySetting;
    let id: string = '';

        if (metadata && metadata.idp && metadata.sp) {
            const base = metadata.idp.getSingleSignOnService(binding.redirect);
            let rawSamlRequest: string;
            if (spSetting.loginRequestTemplate && customTagReplacement) {
                const info = customTagReplacement(spSetting.loginRequestTemplate);
                id = get(info, 'id', null);
                rawSamlRequest = get(info, 'context', null);
            } else {
                const nameIDFormat = spSetting.nameIDFormat;
                const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;
                id = spSetting.generateID();
                rawSamlRequest = libsaml.replaceTagsByValue(libsaml.defaultLoginRequestTemplate.context, {
                    ID:  id,
                    Destination: base,
                    Issuer: metadata.sp.getEntityID(),
                    IssueInstant: new Date().toISOString(),
                    NameIDFormat: selectedNameIDFormat,
                    AssertionConsumerServiceURL: metadata.sp.getAssertionConsumerService(binding.post),
                    EntityID: metadata.sp.getEntityID(),
                    AllowCreate: spSetting.allowCreate,
                } as any);
            }
            console.log(rawSamlRequest)
            console.log("-----------------这是原始请求模板-------------------")
            const {
                privateKey,
                privateKeyPass,
                requestSignatureAlgorithm: signatureAlgorithm,
                transformationAlgorithms
            } = spSetting;
            if (metadata.idp.isWantAuthnRequestsSigned()) {

                let signAuthnRequest = libsaml.constructSAMLSignature({
                    referenceTagXPath: "/*[local-name(.)='AuthnRequest']",
                    privateKey,
                    privateKeyPass,
                    signatureAlgorithm,
                    transformationAlgorithms,
                    isBase64Output: false,
                    rawSamlMessage: rawSamlRequest,
                    signingCert: metadata.sp.getX509Certificate('signing'),
                    signatureConfig: spSetting.signatureConfig || {
                        prefix: 'ds',
                        location: {
                            reference: "/*[local-name(.)='AuthnRequest']/*[local-name(.)='Issuer']",
                            action: 'after'
                        },
                    }
                })
                console.log(signAuthnRequest)
                console.log("签名后的模板")
                rawSamlRequest = signAuthnRequest
            }
            /*            console.log(metadata.idp)
                        console.log(entity.idp.getEntitySetting())*/
            let soapTemplate = libsaml.replaceTagsByValue(libsaml.defaultArtAuthnRequestTemplate.context, {
                ID: id,
                IssueInstant: new Date().toISOString(),
                InResponseTo: metadata.inResponse ?? "",
                Issuer: metadata.sp.getEntityID(),
                AuthnRequest: rawSamlRequest
            } as any);
            console.log(soapTemplate)
            console.log("======================最后结果========================")
            console.log("======================开始签名根节点========================")
            let rootSignSoap = libsaml.constructSAMLSignature({

                isMessageSigned: true,
                isBase64Output: false,
                privateKey,
                privateKeyPass,
                signatureAlgorithm,
                transformationAlgorithms,
                rawSamlMessage: soapTemplate,
                signingCert: metadata.sp.getX509Certificate('signing'),
                signatureConfig: {
                    prefix: 'ds',
                    location: {reference: "//*[local-name()='Header']", action: 'after'},
                }
            })
            console.log(rootSignSoap)
            console.log("======================已经签名========================")
            return {
                authnRequest:rootSignSoap
            };
        }
        throw new Error('ERR_GENERATE_REDIRECT_LOGIN_REQUEST_MISSING_METADATA');



}



/**
 * @desc Redirect URL for login response
 * @param  {object} requestInfo             corresponding request, used to obtain the id
 * @param  {object} entity                      object includes both idp and sp
 * @param  {object} user                         current logged user (e.g. req.user)
 * @param  {String} relayState                the relaystate sent by sp corresponding request
 * @param  {function} customTagReplacement     used when developers have their own login response template
 * @param AttributeStatement
 */
function loginResponseRedirectURL(requestInfo: any, entity: any, user: any = {}, relayState?: string, customTagReplacement?: (template: string) => BindingContext, AttributeStatement = []): BindingContext {
    const idpSetting = entity.idp.entitySetting;
    const spSetting = entity.sp.entitySetting;
    const metadata = {
        idp: entity.idp.entityMeta,
        sp: entity.sp.entityMeta,
    };

    let id: string = idpSetting.generateID();
    if (metadata && metadata.idp && metadata.sp) {
        const base = metadata.sp.getAssertionConsumerService(binding.redirect);
        if (!base) {
            throw new Error('dont have a base url');
        }
        let rawSamlResponse: string;
        //
        const nameIDFormat = idpSetting.nameIDFormat;
        const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;
        const nowTime = new Date();
        // Five minutes later : nowtime  + 5 * 60 * 1000 (in milliseconds)
        const fiveMinutesLaterTime = new Date(nowTime.getTime() + 300_000);
        const now = nowTime.toISOString();
        console.log(`现在是北京时间:${nowTime.toLocaleString()}`)
        const sessionIndex = 'session' + idpSetting.generateID(); // 这个是当前系统的会话索引，用于单点注销
        const tenHoursLaterTime = new Date(nowTime.getTime());
        tenHoursLaterTime.setHours(tenHoursLaterTime.getHours() + 10);
        const tenHoursLater = tenHoursLaterTime.toISOString();
        const tvalue: any = {
            ID: id,
            AssertionID: idpSetting.generateID(),
            Destination: base,
            SubjectRecipient: base,
            Issuer: metadata.idp.getEntityID(),
            Audience: metadata.sp.getEntityID(),
            EntityID: metadata.sp.getEntityID(),
            IssueInstant: nowTime.toISOString(),
            AssertionConsumerServiceURL: base,
            StatusCode: namespace.statusCode.success,
            // can be customized
            ConditionsNotBefore: nowTime.toISOString(),
            ConditionsNotOnOrAfter: fiveMinutesLaterTime.toISOString(),
            SubjectConfirmationDataNotOnOrAfter: fiveMinutesLaterTime.toISOString(),
            NameIDFormat: selectedNameIDFormat,
            NameID: user.NameID || '',
            InResponseTo: get(requestInfo, 'extract.request.id', ''),
            AuthnStatement: `<saml:AuthnStatement AuthnInstant="${now}" SessionNotOnOrAfter="${tenHoursLater}" SessionIndex="${sessionIndex}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`,
            AttributeStatement: libsaml.attributeStatementBuilder(AttributeStatement),
        };

        if (idpSetting.loginResponseTemplate && customTagReplacement) {
            const template = customTagReplacement(idpSetting.loginResponseTemplate.context);
            id = get(template, 'id', null);
            rawSamlResponse = get(template, 'context', null);
        } else {

            if (requestInfo !== null) {
                tvalue.InResponseTo = requestInfo?.extract?.request?.id;
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

        // Like in post binding, SAML response is always signed
        return {
            id,
            context: buildRedirectURL({
                baseUrl: base,
                type: urlParams.samlResponse,
                isSigned: true,
                context: rawSamlResponse,
                entitySetting: idpSetting,
                relayState,
            }),
        };
    }
    throw new Error('ERR_GENERATE_REDIRECT_LOGIN_RESPONSE_MISSING_METADATA');
}

/**
 * @desc Redirect URL for logout request
 * @param  {object} user                        current logged user (e.g. req.user)
 * @param  {object} entity                      object includes both idp and sp
 * @param  {function} customTagReplacement     used when developers have their own login response template
 * @return {string} redirect URL
 */
function logoutRequestRedirectURL(user, entity, relayState?: string, customTagReplacement?: (template: string, tags: object) => BindingContext): BindingContext {
    const metadata = {init: entity.init.entityMeta, target: entity.target.entityMeta};
    const initSetting = entity.init.entitySetting;
    let id: string = initSetting.generateID();
    const nameIDFormat = initSetting.nameIDFormat;
    const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;

    if (metadata && metadata.init && metadata.target) {
        const base = metadata.target.getSingleLogoutService(binding.redirect);
        let rawSamlRequest: string = '';
        const requiredTags = {
            ID: id,
            Destination: base,
            EntityID: metadata.init.getEntityID(),
            Issuer: metadata.init.getEntityID(),
            IssueInstant: new Date().toISOString(),
            NameIDFormat: selectedNameIDFormat,
            NameID: user.NameID || '',
            SessionIndex: user.sessionIndex,
        };
        if (initSetting.logoutRequestTemplate && customTagReplacement) {
            const info = customTagReplacement(initSetting.logoutRequestTemplate, requiredTags);
            id = get(info, 'id', null);
            rawSamlRequest = get(info, 'context', null);
        } else {
            rawSamlRequest = libsaml.replaceTagsByValue(libsaml.defaultLogoutRequestTemplate.context, requiredTags as any);
        }
        return {
            id,
            context: buildRedirectURL({
                context: rawSamlRequest,
                relayState,
                type: urlParams.logoutRequest,
                isSigned: entity.target.entitySetting.wantLogoutRequestSigned,
                entitySetting: initSetting,
                baseUrl: base,
            }),
        };
    }
    throw new Error('ERR_GENERATE_REDIRECT_LOGOUT_REQUEST_MISSING_METADATA');
}

/**
 * @desc Redirect URL for logout response
 * @param  {object} requescorresponding request, used to obtain the id
 * @param  {object} entity                      object includes both idp and sp
 * @param  {function} customTagReplacement     used when developers have their own login response template
 */
function logoutResponseRedirectURL(requestInfo: any, entity: any, relayState?: string, customTagReplacement?: (template: string) => BindingContext): BindingContext {
    const metadata = {
        init: entity.init.entityMeta,
        target: entity.target.entityMeta,
    };
    const initSetting = entity.init.entitySetting;
    let id: string = initSetting.generateID();
    if (metadata && metadata.init && metadata.target) {
        const base = metadata.target.getSingleLogoutService(binding.redirect);
        let rawSamlResponse: string;
        if (initSetting.logoutResponseTemplate && customTagReplacement) {
            const template = customTagReplacement(initSetting.logoutResponseTemplate);
            id = get(template, 'id', null);
            rawSamlResponse = get(template, 'context', null);
        } else {
            const tvalue: any = {
                ID: id,
                Destination: base,
                Issuer: metadata.init.getEntityID(),
                EntityID: metadata.init.getEntityID(),
                IssueInstant: new Date().toISOString(),
                StatusCode: namespace.statusCode.success,
            };
            if (requestInfo && requestInfo.extract && requestInfo.extract.request) {
                tvalue.InResponseTo = requestInfo?.extract?.request?.id;
            }
            rawSamlResponse = libsaml.replaceTagsByValue(libsaml.defaultLogoutResponseTemplate.context, tvalue);
        }
        return {
            id,
            context: buildRedirectURL({
                baseUrl: base,
                type: urlParams.logoutResponse,
                isSigned: entity.target.entitySetting.wantLogoutResponseSigned,
                context: rawSamlResponse,
                entitySetting: initSetting,
                relayState,
            }),
        };
    }
    throw new Error('ERR_GENERATE_REDIRECT_LOGOUT_RESPONSE_MISSING_METADATA');
}

const redirectBinding = {
    loginRequestRedirectURLArt,
    loginRequestRedirectURL,
    loginResponseRedirectURL,
    logoutRequestRedirectURL,
    logoutResponseRedirectURL,
};

export default redirectBinding;
