"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * @file binding-redirect.ts
 * @author tngan
 * @desc Binding-level API, declare the functions using Redirect binding
 */
var utility_1 = require("./utility");
var libsaml_1 = require("./libsaml");
var url = require("url");
var urn_1 = require("./urn");
var binding = urn_1.wording.binding;
var urlParams = urn_1.wording.urlParams;
/**
 * @private
 * @desc Helper of generating URL param/value pair
 * @param  {string} param     key
 * @param  {string} value     value of key
 * @param  {boolean} first    determine whether the param is the starting one in order to add query header '?'
 * @return {string}
 */
function pvPair(param, value, first) {
    return (first === true ? "?" : "&") + param + "=" + value;
}
/**
 * @private
 * @desc Refractored part of URL generation for login/logout request
 * @return {string}
 * @param opts type, isSigned, rawSamlRequest, entitySetting
 */
function buildRedirectURL(opts) {
    var baseUrl = opts.baseUrl, type = opts.type, isSigned = opts.isSigned, context = opts.context, entitySetting = opts.entitySetting;
    var _a = opts.relayState, relayState = _a === void 0 ? "" : _a;
    var noParams = (url.parse(baseUrl).query || []).length === 0;
    var queryParam = libsaml_1.default.getQueryParamByType(type);
    // In general, this xmlstring is required to do deflate -> base64 -> urlencode
    var samlRequest = encodeURIComponent(utility_1.default.base64Encode(utility_1.default.deflateString(context)));
    if (relayState !== "") {
        relayState = pvPair(urlParams.relayState, encodeURIComponent(relayState));
    }
    if (isSigned) {
        var sigAlg = pvPair(urlParams.sigAlg, encodeURIComponent(entitySetting.requestSignatureAlgorithm));
        var octetString = samlRequest + relayState + sigAlg;
        return (baseUrl +
            pvPair(queryParam, octetString, noParams) +
            pvPair(urlParams.signature, encodeURIComponent(libsaml_1.default.constructMessageSignature(queryParam + "=" + octetString, entitySetting.privateKey, entitySetting.privateKeyPass, undefined, entitySetting.requestSignatureAlgorithm))));
    }
    return baseUrl + pvPair(queryParam, samlRequest + relayState, noParams);
}
/**
 * @desc Redirect URL for login request
 * @param  {object} entity                       object includes both idp and sp
 * @param  {function} customTagReplacement      used when developers have their own login response template
 * @return {string} redirect URL
 */
function loginRequestRedirectURL(entity, customTagReplacement) {
    var metadata = {
        idp: entity.idp.entityMeta,
        sp: entity.sp.entityMeta,
    };
    var spSetting = entity.sp.entitySetting;
    var id = "";
    if (metadata && metadata.idp && metadata.sp) {
        var base = metadata.idp.getSingleSignOnService(binding.redirect);
        var rawSamlRequest = void 0;
        if (spSetting.loginRequestTemplate && customTagReplacement) {
            var info = customTagReplacement(spSetting.loginRequestTemplate);
            id = utility_1.get(info, "id", null);
            rawSamlRequest = utility_1.get(info, "context", null);
        }
        else {
            var nameIDFormat = spSetting.nameIDFormat;
            var selectedNameIDFormat = Array.isArray(nameIDFormat)
                ? nameIDFormat[0]
                : nameIDFormat;
            id = spSetting.generateID();
            rawSamlRequest = libsaml_1.default.replaceTagsByValue(libsaml_1.default.defaultLoginRequestTemplate.context, {
                ID: id,
                Destination: base,
                Issuer: metadata.sp.getEntityID(),
                IssueInstant: new Date().toISOString(),
                NameIDFormat: selectedNameIDFormat,
                AssertionConsumerServiceURL: metadata.sp.getAssertionConsumerService(binding.post),
                EntityID: metadata.sp.getEntityID(),
                AllowCreate: spSetting.allowCreate,
            });
        }
        return {
            id: id,
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
    throw new Error("ERR_GENERATE_REDIRECT_LOGIN_REQUEST_MISSING_METADATA");
}
/**
 * @desc Redirect URL for logout request
 * @param  {object} user                        current logged user (e.g. req.user)
 * @param  {object} entity                      object includes both idp and sp
 * @param relayState
 * @param  {function} customTagReplacement     used when developers have their own login response template
 * @return {string} redirect URL
 */
function logoutRequestRedirectURL(user, entity, relayState, customTagReplacement) {
    var metadata = {
        init: entity.init.entityMeta,
        target: entity.target.entityMeta,
    };
    var initSetting = entity.init.entitySetting;
    var id = initSetting.generateID();
    var nameIDFormat = initSetting.nameIDFormat;
    var selectedNameIDFormat = Array.isArray(nameIDFormat)
        ? nameIDFormat[0]
        : nameIDFormat;
    if (metadata && metadata.init && metadata.target) {
        var base = metadata.target.getSingleLogoutService(binding.redirect);
        var rawSamlRequest = void 0;
        var requiredTags = {
            ID: id,
            Destination: base,
            EntityID: metadata.init.getEntityID(),
            Issuer: metadata.init.getEntityID(),
            IssueInstant: new Date().toISOString(),
            NameIDFormat: selectedNameIDFormat,
            NameID: user.logoutNameID,
            SessionIndex: user.sessionIndex,
        };
        if (initSetting.logoutRequestTemplate && customTagReplacement) {
            var info = customTagReplacement(initSetting.logoutRequestTemplate, requiredTags);
            id = utility_1.get(info, "id", null);
            rawSamlRequest = utility_1.get(info, "context", null);
        }
        else {
            rawSamlRequest = libsaml_1.default.replaceTagsByValue(libsaml_1.default.defaultLogoutRequestTemplate.context, requiredTags);
        }
        return {
            id: id,
            context: buildRedirectURL({
                context: rawSamlRequest,
                relayState: relayState,
                type: urlParams.logoutRequest,
                isSigned: entity.target.entitySetting.wantLogoutRequestSigned,
                entitySetting: initSetting,
                baseUrl: base,
            }),
        };
    }
    throw new Error("ERR_GENERATE_REDIRECT_LOGOUT_REQUEST_MISSING_METADATA");
}
/**
 * @desc Redirect URL for logout response
 * @param requestInfo
 * @param  {object} entity                      object includes both idp and sp
 * @param relayState
 * @param  {function} customTagReplacement     used when developers have their own login response template
 */
function logoutResponseRedirectURL(requestInfo, entity, relayState, customTagReplacement) {
    var metadata = {
        init: entity.init.entityMeta,
        target: entity.target.entityMeta,
    };
    var initSetting = entity.init.entitySetting;
    var id = initSetting.generateID();
    if (metadata && metadata.init && metadata.target) {
        var base = metadata.target.getSingleLogoutService(binding.redirect);
        var rawSamlResponse = void 0;
        if (initSetting.logoutResponseTemplate && customTagReplacement) {
            var template = customTagReplacement(initSetting.logoutResponseTemplate);
            id = utility_1.get(template, "id", null);
            rawSamlResponse = utility_1.get(template, "context", null);
        }
        else {
            var tvalue = {
                ID: id,
                Destination: base,
                Issuer: metadata.init.getEntityID(),
                EntityID: metadata.init.getEntityID(),
                IssueInstant: new Date().toISOString(),
                StatusCode: urn_1.namespace.statusCode.success,
            };
            if (requestInfo &&
                requestInfo.extract &&
                requestInfo.extract.logoutRequest) {
                tvalue.InResponseTo = requestInfo.extract.logoutRequest.id;
            }
            rawSamlResponse = libsaml_1.default.replaceTagsByValue(libsaml_1.default.defaultLogoutResponseTemplate.context, tvalue);
        }
        return {
            id: id,
            context: buildRedirectURL({
                baseUrl: base,
                type: urlParams.logoutResponse,
                isSigned: entity.target.entitySetting.wantLogoutResponseSigned,
                context: rawSamlResponse,
                entitySetting: initSetting,
                relayState: relayState,
            }),
        };
    }
    throw new Error("ERR_GENERATE_REDIRECT_LOGOUT_RESPONSE_MISSING_METADATA");
}
var redirectBinding = {
    loginRequestRedirectURL: loginRequestRedirectURL,
    logoutRequestRedirectURL: logoutRequestRedirectURL,
    logoutResponseRedirectURL: logoutResponseRedirectURL,
};
exports.default = redirectBinding;
//# sourceMappingURL=binding-redirect.js.map