"use strict";
/**
 * @file SamlLib.js
 * @author tngan
 * @desc  A simple library including some common functions
 */
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var xmldom_1 = require("xmldom");
var utility_1 = require("./utility");
var urn_1 = require("./urn");
var xpath_1 = require("xpath");
var NodeRSA = require("node-rsa");
var xml_crypto_1 = require("xml-crypto");
var xmlenc = require("xml-encryption");
var extractor_1 = require("./extractor");
var camelcase_1 = require("camelcase");
var api_1 = require("./api");
var signatureAlgorithms = urn_1.algorithms.signature;
var digestAlgorithms = urn_1.algorithms.digest;
var certUse = urn_1.wording.certUse;
var urlParams = urn_1.wording.urlParams;
var dom = xmldom_1.DOMParser;
var libSaml = function () {
    /**
     * @desc helper function to get back the query param for redirect binding for SLO/SSO
     * @type {string}
     */
    function getQueryParamByType(type) {
        if ([urlParams.logoutRequest, urlParams.samlRequest].indexOf(type) !== -1) {
            return "SAMLRequest";
        }
        if ([urlParams.logoutResponse, urlParams.samlResponse].indexOf(type) !== -1) {
            return "SAMLResponse";
        }
        throw new Error("ERR_UNDEFINED_QUERY_PARAMS");
    }
    /**
     *
     */
    var nrsaAliasMapping = {
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1": "sha1",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": "sha256",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": "sha512",
    };
    /**
     * @desc Default login request template
     * @type {LoginRequestTemplate}
     */
    var defaultLoginRequestTemplate = {
        context: '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>',
    };
    /**
     * @desc Default logout request template
     * @type {LogoutRequestTemplate}
     */
    var defaultLogoutRequestTemplate = {
        context: '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}"><saml:Issuer>{Issuer}</saml:Issuer><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID></samlp:LogoutRequest>',
    };
    /**
     * @desc Default login response template
     * @type {LoginResponseTemplate}
     */
    var defaultLoginResponseTemplate = {
        context: '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AuthnStatement}{AttributeStatement}</saml:Assertion></samlp:Response>',
        attributes: [],
    };
    /**
     * @desc Default logout response template
     * @type {LogoutResponseTemplate}
     */
    var defaultLogoutResponseTemplate = {
        context: '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status></samlp:LogoutResponse>',
    };
    /**
     * @private
     * @desc Get the signing scheme alias by signature algorithms, used by the node-rsa module
     * @param {string} sigAlg    signature algorithm
     * @return {string/null} signing algorithm short-hand for the module node-rsa
     */
    function getSigningScheme(sigAlg) {
        if (sigAlg) {
            var algAlias = nrsaAliasMapping[sigAlg];
            if (!(algAlias === undefined)) {
                return algAlias;
            }
        }
        return nrsaAliasMapping[signatureAlgorithms.RSA_SHA1]; // default value
    }
    /**
     * @private
     * @desc Get the digest algorithms by signature algorithms
     * @param {string} sigAlg    signature algorithm
     * @return {string/null} digest algorithm
     */
    function getDigestMethod(sigAlg) {
        var digestAlg = digestAlgorithms[sigAlg];
        if (!(digestAlg === undefined)) {
            return digestAlg;
        }
        return undefined; // default value
    }
    /**
     * @public
     * @desc Create XPath
     * @param  {string/object} local     parameters to create XPath
     * @param  {boolean} isExtractAll    define whether returns whole content according to the XPath
     * @return {string} xpath
     */
    function createXPath(local, isExtractAll) {
        if (utility_1.isString(local)) {
            return isExtractAll === true
                ? "//*[local-name(.)='" + local + "']/text()"
                : "//*[local-name(.)='" + local + "']";
        }
        return "//*[local-name(.)='" + local.name + "']/@" + local.attr;
    }
    /**
     * @private
     * @desc Tag normalization
     * @param {string} prefix     prefix of the tag
     * @param {content} content   normalize it to capitalized camel case
     * @return {string}
     */
    function tagging(prefix, content) {
        var camelContent = camelcase_1.default(content);
        return (prefix + camelContent.charAt(0).toUpperCase() + camelContent.slice(1));
    }
    return {
        createXPath: createXPath,
        getQueryParamByType: getQueryParamByType,
        defaultLoginRequestTemplate: defaultLoginRequestTemplate,
        defaultLoginResponseTemplate: defaultLoginResponseTemplate,
        defaultLogoutRequestTemplate: defaultLogoutRequestTemplate,
        defaultLogoutResponseTemplate: defaultLogoutResponseTemplate,
        /**
         * @desc Repalce the tag (e.g. {tag}) inside the raw XML
         * @param  {string} rawXML      raw XML string used to do keyword replacement
         * @param  {array} tagValues    tag values
         * @return {string}
         */
        replaceTagsByValue: function (rawXML, tagValues) {
            Object.keys(tagValues).forEach(function (t) {
                if (typeof tagValues[t] !== "undefined") {
                    rawXML = rawXML.replace(new RegExp("{" + t + "}", "g"), tagValues[t]);
                }
            });
            return rawXML;
        },
        /**
         * @desc Helper function to build the AttributeStatement tag
         * @param  {LoginResponseAttribute} attributes    an array of attribute configuration
         * @return {string}
         */
        attributeStatementBuilder: function (attributes) {
            var attr = attributes
                .map(function (_a) {
                var name = _a.name, nameFormat = _a.nameFormat, valueTag = _a.valueTag, valueXsiType = _a.valueXsiType, valueXmlnsXs = _a.valueXmlnsXs, valueXmlnsXsi = _a.valueXmlnsXsi;
                var defaultValueXmlnsXs = "http://www.w3.org/2001/XMLSchema";
                var defaultValueXmlnsXsi = "http://www.w3.org/2001/XMLSchema-instance";
                return "<saml:Attribute Name=\"" + name + "\" NameFormat=\"" + nameFormat + "\"><saml:AttributeValue xmlns:xs=\"" + (valueXmlnsXs ? valueXmlnsXs : defaultValueXmlnsXs) + "\" xmlns:xsi=\"" + (valueXmlnsXsi ? valueXmlnsXsi : defaultValueXmlnsXsi) + "\" xsi:type=\"" + valueXsiType + "\">{" + tagging("attr", valueTag) + "}</saml:AttributeValue></saml:Attribute>";
            })
                .join("");
            return "<saml:AttributeStatement>" + attr + "</saml:AttributeStatement>";
        },
        /**
         * @desc Construct the XML signature for POST binding
         * @return {string} base64 encoded string
         * @param opts
         */
        constructSAMLSignature: function (opts) {
            var rawSamlMessage = opts.rawSamlMessage, referenceTagXPath = opts.referenceTagXPath, privateKey = opts.privateKey, privateKeyPass = opts.privateKeyPass, _a = opts.signatureAlgorithm, signatureAlgorithm = _a === void 0 ? signatureAlgorithms.RSA_SHA256 : _a, _b = opts.transformationAlgorithms, transformationAlgorithms = _b === void 0 ? [
                "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                "http://www.w3.org/2001/10/xml-exc-c14n#",
            ] : _b, signingCert = opts.signingCert, signatureConfig = opts.signatureConfig, _c = opts.isBase64Output, isBase64Output = _c === void 0 ? true : _c, _d = opts.isMessageSigned, isMessageSigned = _d === void 0 ? false : _d;
            var sig = new xml_crypto_1.SignedXml();
            // Add assertion sections as reference
            if (referenceTagXPath) {
                sig.addReference(referenceTagXPath, opts.transformationAlgorithms, getDigestMethod(signatureAlgorithm));
            }
            if (isMessageSigned) {
                sig.addReference(
                // reference to the root node
                "/*", transformationAlgorithms, getDigestMethod(signatureAlgorithm), "", "", "", false);
            }
            sig.signatureAlgorithm = signatureAlgorithm;
            sig.keyInfoProvider = new this.getKeyInfo(signingCert, signatureConfig);
            sig.signingKey = utility_1.default.readPrivateKey(privateKey, privateKeyPass, true);
            if (signatureConfig) {
                sig.computeSignature(rawSamlMessage, signatureConfig);
            }
            else {
                sig.computeSignature(rawSamlMessage);
            }
            return isBase64Output
                ? utility_1.default.base64Encode(sig.getSignedXml())
                : sig.getSignedXml();
        },
        /**
         * @desc Verify the XML signature
         * @param  {string} xml xml
         * @param  {SignatureVerifierOptions} opts cert declares the X509 certificate
         * @return {boolean} verification result
         */
        verifySignature: function (xml, opts) {
            var _this = this;
            var doc = new dom().parseFromString(xml);
            // In order to avoid the wrapping attack, we have changed to use absolute xpath instead of naively fetching the signature element
            // message signature (logout response / saml response)
            var messageSignatureXpath = "/*[contains(local-name(), 'Response') or contains(local-name(), 'Request')]/*[local-name(.)='Signature']";
            // assertion signature (logout response / saml response)
            var assertionSignatureXpath = "/*[contains(local-name(), 'Response') or contains(local-name(), 'Request')]/*[local-name(.)='Assertion']/*[local-name(.)='Signature']";
            // check if there is a potential malicious wrapping signature
            var wrappingElementsXPath = "/*[contains(local-name(), 'Response')]/*[local-name(.)='Assertion']/*[local-name(.)='Subject']/*[local-name(.)='SubjectConfirmation']/*[local-name(.)='SubjectConfirmationData']//*[local-name(.)='Assertion' or local-name(.)='Signature']";
            // select the signature node
            var selection = [];
            var assertionNode = null;
            var messageSignatureNode = xpath_1.select(messageSignatureXpath, doc);
            var assertionSignatureNode = xpath_1.select(assertionSignatureXpath, doc);
            var wrappingElementNode = xpath_1.select(wrappingElementsXPath, doc);
            selection = selection.concat(messageSignatureNode);
            selection = selection.concat(assertionSignatureNode);
            // try to catch potential wrapping attack
            if (wrappingElementNode.length !== 0) {
                throw new Error("ERR_POTENTIAL_WRAPPING_ATTACK");
            }
            // guarantee to have a signature in saml response
            if (selection.length === 0) {
                throw new Error("ERR_ZERO_SIGNATURE");
            }
            var sig = new xml_crypto_1.SignedXml();
            var verified = true;
            // need to refactor later on
            selection.forEach(function (signatureNode) {
                if (opts && opts.signatureAlgorithm) {
                    sig.signatureAlgorithm = opts.signatureAlgorithm;
                }
                if (opts && !opts.keyFile && !opts.metadata) {
                    throw new Error("ERR_UNDEFINED_SIGNATURE_VERIFIER_OPTIONS");
                }
                if (opts && opts.keyFile) {
                    sig.keyInfoProvider = new xml_crypto_1.FileKeyInfo(opts.keyFile);
                }
                if (opts && opts.metadata) {
                    var certificateNode = xpath_1.select(".//*[local-name(.)='X509Certificate']", signatureNode);
                    // certificate in metadata
                    var metadataCert = opts.metadata.getX509Certificate(certUse.signing);
                    // flattens the nested array of Certificates from each KeyDescriptor
                    if (Array.isArray(metadataCert)) {
                        metadataCert = utility_1.flattenDeep(metadataCert);
                    }
                    else if (typeof metadataCert === "string") {
                        metadataCert = [metadataCert];
                    }
                    // normalise the certificate string
                    metadataCert = metadataCert.map(utility_1.default.normalizeCerString);
                    if (certificateNode.length === 0) {
                        throw new Error("NO_SELECTED_CERTIFICATE");
                    }
                    // no certificate node in response
                    if (certificateNode.length !== 0) {
                        var x509CertificateData = certificateNode[0].firstChild.data;
                        var x509Certificate_1 = utility_1.default.normalizeCerString(x509CertificateData);
                        if (metadataCert.length >= 1 &&
                            !metadataCert.find(function (cert) { return cert.trim() === x509Certificate_1.trim(); })) {
                            // keep this restriction for rolling certificate usage
                            // to make sure the response certificate is one of those specified in metadata
                            throw new Error("ERROR_UNMATCH_CERTIFICATE_DECLARATION_IN_METADATA");
                        }
                        sig.keyInfoProvider = new _this.getKeyInfo(x509Certificate_1);
                    }
                }
                sig.loadSignature(signatureNode);
                doc.removeChild(signatureNode);
                verified = verified && sig.checkSignature(doc.toString());
                // immediately throw error when any one of the signature is failed to get verified
                if (!verified) {
                    throw new Error("ERR_FAILED_TO_VERIFY_SIGNATURE");
                }
            });
            // response must be signed, either entire document or assertion
            // default we will take the assertion section under root
            if (messageSignatureNode.length === 1) {
                var node = xpath_1.select("/*[contains(local-name(), 'Response') or contains(local-name(), 'Request')]/*[local-name(.)='Assertion']", doc);
                if (node.length === 1) {
                    assertionNode = node[0].toString();
                }
            }
            if (assertionSignatureNode.length === 1) {
                var verifiedAssertionInfo = extractor_1.extract(assertionSignatureNode[0].toString(), [
                    {
                        key: "refURI",
                        localPath: ["Signature", "SignedInfo", "Reference"],
                        attributes: ["URI"],
                    },
                ]);
                // get the assertion supposed to be the one should be verified
                var desiredAssertionInfo = extractor_1.extract(doc.toString(), [
                    {
                        key: "id",
                        localPath: ["~Response", "Assertion"],
                        attributes: ["ID"],
                    },
                ]);
                // 5.4.2 References
                // SAML assertions and protocol messages MUST supply a value for the ID attribute on the root element of
                // the assertion or protocol message being signed. The assertion’s or protocol message's root element may
                // or may not be the root element of the actual XML document containing the signed assertion or protocol
                // message (e.g., it might be contained within a SOAP envelope).
                // Signatures MUST contain a single <ds:Reference> containing a same-document reference to the ID
                // attribute value of the root element of the assertion or protocol message being signed. For example, if the
                // ID attribute value is "foo", then the URI attribute in the <ds:Reference> element MUST be "#foo".
                if (verifiedAssertionInfo.refURI !== "#" + desiredAssertionInfo.id) {
                    throw new Error("ERR_POTENTIAL_WRAPPING_ATTACK");
                }
                var verifiedDoc = extractor_1.extract(doc.toString(), [
                    {
                        key: "assertion",
                        localPath: ["~Response", "Assertion"],
                        attributes: [],
                        context: true,
                    },
                ]);
                assertionNode = verifiedDoc.assertion.toString();
            }
            return [verified, assertionNode];
        },
        /**
         * @desc Helper function to create the key section in metadata (abstraction for signing and encrypt use)
         * @param  {string} use          type of certificate (e.g. signing, encrypt)
         * @param  {string} certString    declares the certificate String
         * @return {object} object used in xml module
         */
        createKeySection: function (use, certString) {
            var _a, _b, _c;
            return _a = {},
                _a["KeyDescriptor"] = [
                    {
                        _attr: { use: use },
                    },
                    (_b = {},
                        _b["ds:KeyInfo"] = [
                            {
                                _attr: {
                                    "xmlns:ds": "http://www.w3.org/2000/09/xmldsig#",
                                },
                            },
                            (_c = {},
                                _c["ds:X509Data"] = [
                                    {
                                        "ds:X509Certificate": utility_1.default.normalizeCerString(certString),
                                    },
                                ],
                                _c),
                        ],
                        _b),
                ],
                _a;
        },
        /**
         * @desc Constructs SAML message
         * @param  {string} octetString               see "Bindings for the OASIS Security Assertion Markup Language (SAML V2.0)" P.17/46
         * @param  {string} key                       declares the pem-formatted private key
         * @param  {string} passphrase                passphrase of private key [optional]
         * @param isBase64
         * @param  {string} signingAlgorithm          signing algorithm
         * @return {string} message signature
         */
        constructMessageSignature: function (octetString, key, passphrase, isBase64, signingAlgorithm) {
            // Default returning base64 encoded signature
            // Embed with node-rsa module
            var decryptedKey = new NodeRSA(utility_1.default.readPrivateKey(key, passphrase), undefined, {
                signingScheme: getSigningScheme(signingAlgorithm),
            });
            var signature = decryptedKey.sign(octetString);
            // Use private key to sign data
            return isBase64 !== false
                ? signature.toString("base64")
                : signature;
        },
        /**
         * @desc Verifies message signature
         * @param  {Metadata} metadata                 metadata object of identity provider or service provider
         * @param  {string} octetString                see "Bindings for the OASIS Security Assertion Markup Language (SAML V2.0)" P.17/46
         * @param  {string} signature                  context of XML signature
         * @param  {string} verifyAlgorithm            algorithm used to verify
         * @return {boolean} verification result
         */
        verifyMessageSignature: function (metadata, octetString, signature, verifyAlgorithm) {
            var signCert = metadata.getX509Certificate(certUse.signing);
            var signingScheme = getSigningScheme(verifyAlgorithm);
            var key = new NodeRSA(utility_1.default.getPublicKeyPemFromCertificate(signCert), undefined, { signingScheme: signingScheme });
            return key.verify(new Buffer(octetString), Buffer.from(signature));
        },
        /**
         * @desc Get the public key in string format
         * @param  {string} x509Certificate certificate
         * @param signatureConfig
         * @return {string} public key
         */
        getKeyInfo: function (x509Certificate, signatureConfig) {
            if (signatureConfig === void 0) { signatureConfig = {}; }
            this.getKeyInfo = function () {
                var prefix = signatureConfig.prefix
                    ? signatureConfig.prefix + ":"
                    : "";
                return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" + x509Certificate + "</" + prefix + "X509Certificate></" + prefix + "X509Data>";
            };
            this.getKey = function (keyInfo) {
                return utility_1.default
                    .getPublicKeyPemFromCertificate(x509Certificate)
                    .toString();
            };
        },
        /**
         * @desc Encrypt the assertion section in Response
         * @param  {Entity} sourceEntity             source entity
         * @param  {Entity} targetEntity             target entity
         * @param  {string} xml                      response in xml string format
         * @return {Promise} a promise to resolve the finalized xml
         */
        encryptAssertion: function (sourceEntity, targetEntity, xml) {
            // Implement encryption after signature if it has
            return new Promise(function (resolve, reject) {
                if (!xml) {
                    return reject(new Error("ERR_UNDEFINED_ASSERTION"));
                }
                var sourceEntitySetting = sourceEntity.entitySetting;
                var targetEntityMetadata = targetEntity.entityMeta;
                var doc = new dom().parseFromString(xml);
                var assertions = xpath_1.select("//*[local-name(.)='Assertion']", doc);
                if (!Array.isArray(assertions)) {
                    throw new Error("ERR_NO_ASSERTION");
                }
                if (assertions.length !== 1) {
                    throw new Error("ERR_MULTIPLE_ASSERTION");
                }
                // Perform encryption depends on the setting, default is false
                if (sourceEntitySetting.isAssertionEncrypted) {
                    xmlenc.encrypt(assertions[0].toString(), {
                        // use xml-encryption module
                        rsa_pub: Buffer.from(utility_1.default
                            .getPublicKeyPemFromCertificate(targetEntityMetadata.getX509Certificate(certUse.encrypt))
                            .replace(/\r?\n|\r/g, "")),
                        pem: Buffer.from("-----BEGIN CERTIFICATE-----" +
                            targetEntityMetadata.getX509Certificate(certUse.encrypt) +
                            "-----END CERTIFICATE-----"),
                        encryptionAlgorithm: sourceEntitySetting.dataEncryptionAlgorithm,
                        keyEncryptionAlgorithm: sourceEntitySetting.keyEncryptionAlgorithm,
                    }, function (err, res) {
                        if (err) {
                            console.error(err);
                            return reject(new Error("ERR_EXCEPTION_OF_ASSERTION_ENCRYPTION"));
                        }
                        if (!res) {
                            return reject(new Error("ERR_UNDEFINED_ENCRYPTED_ASSERTION"));
                        }
                        var encAssertionPrefix = sourceEntitySetting.tagPrefix.encryptedAssertion;
                        var encryptAssertionNode = new dom().parseFromString("<" + encAssertionPrefix + ":EncryptedAssertion xmlns:" + encAssertionPrefix + "=\"" + urn_1.namespace.names.assertion + "\">" + res + "</" + encAssertionPrefix + ":EncryptedAssertion>");
                        doc.replaceChild(encryptAssertionNode, assertions[0]);
                        return resolve(utility_1.default.base64Encode(doc.toString()));
                    });
                }
                else {
                    return resolve(utility_1.default.base64Encode(xml)); // No need to do encrpytion
                }
            });
        },
        /**
         * @desc Decrypt the assertion section in Response
         * @param  {Entity} here             this entity
         * @param {string} entireXML         response in xml string format
         * @return {function} a promise to get back the entire xml with decrypted assertion
         */
        decryptAssertion: function (here, entireXML) {
            return new Promise(function (resolve, reject) {
                // Implement decryption first then check the signature
                if (!entireXML) {
                    return reject(new Error("ERR_UNDEFINED_ASSERTION"));
                }
                // Perform encryption depends on the setting of where the message is sent, default is false
                var hereSetting = here.entitySetting;
                var xml = new dom().parseFromString(entireXML);
                var encryptedAssertions = xpath_1.select("/*[contains(local-name(), 'Response')]/*[local-name(.)='EncryptedAssertion']", xml);
                if (!Array.isArray(encryptedAssertions)) {
                    throw new Error("ERR_UNDEFINED_ENCRYPTED_ASSERTION");
                }
                if (encryptedAssertions.length !== 1) {
                    throw new Error("ERR_MULTIPLE_ASSERTION");
                }
                return xmlenc.decrypt(encryptedAssertions[0].toString(), {
                    key: utility_1.default.readPrivateKey(hereSetting.encPrivateKey, hereSetting.encPrivateKeyPass),
                }, function (err, res) {
                    if (err) {
                        console.error(err);
                        return reject(new Error("ERR_EXCEPTION_OF_ASSERTION_DECRYPTION"));
                    }
                    if (!res) {
                        return reject(new Error("ERR_UNDEFINED_ENCRYPTED_ASSERTION"));
                    }
                    var assertionNode = new dom().parseFromString(res);
                    xml.replaceChild(assertionNode, encryptedAssertions[0]);
                    return resolve([xml.toString(), res]);
                });
            });
        },
        /**
         * @desc Check if the xml string is valid and bounded
         */
        isValidXml: function (input) {
            return __awaiter(this, void 0, void 0, function () {
                var validate, e_1;
                return __generator(this, function (_a) {
                    switch (_a.label) {
                        case 0:
                            validate = api_1.getContext().validate;
                            /**
                             * user can write a validate function that always returns
                             * a resolved promise and skip the validator even in
                             * production, user will take the responsibility if
                             * they intend to skip the validation
                             */
                            if (!validate) {
                                // otherwise, an error will be thrown
                                return [2 /*return*/, Promise.reject("Your application is potentially vulnerable because no validation function found. Please read the documentation on how to setup the validator. (https://github.com/tngan/samlify#installation)")];
                            }
                            _a.label = 1;
                        case 1:
                            _a.trys.push([1, 3, , 4]);
                            return [4 /*yield*/, validate(input)];
                        case 2: return [2 /*return*/, _a.sent()];
                        case 3:
                            e_1 = _a.sent();
                            throw e_1;
                        case 4: return [2 /*return*/];
                    }
                });
            });
        },
    };
};
exports.default = libSaml();
//# sourceMappingURL=libsaml.js.map