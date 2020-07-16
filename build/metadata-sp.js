"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.SpMetadata = void 0;
/**
 * @file metadata-sp.ts
 * @author tngan
 * @desc  Metadata of service provider
 */
var metadata_1 = require("./metadata");
var urn_1 = require("./urn");
var libsaml_1 = require("./libsaml");
var utility_1 = require("./utility");
var xml = require("xml");
/*
 * @desc interface function
 */
function default_1(meta) {
    return new SpMetadata(meta);
}
exports.default = default_1;
/**
 * @desc SP Metadata is for creating Service Provider, provides a set of API to manage the actions in SP.
 */
var SpMetadata = /** @class */ (function (_super) {
    __extends(SpMetadata, _super);
    /**
     * @param  {object/string} meta (either xml string or configuation in object)
     * @return {object} prototypes including public functions
     */
    function SpMetadata(meta) {
        var _this = this;
        var isFile = utility_1.isString(meta) || meta instanceof Buffer;
        // use object configuation instead of importing metadata file directly
        if (!isFile) {
            var _a = meta, _b = _a.elementsOrder, elementsOrder = _b === void 0 ? urn_1.elementsOrder.default : _b, entityID = _a.entityID, signingCert = _a.signingCert, encryptCert = _a.encryptCert, _c = _a.authnRequestsSigned, authnRequestsSigned = _c === void 0 ? false : _c, _d = _a.wantAssertionsSigned, wantAssertionsSigned = _d === void 0 ? false : _d, _e = _a.wantMessageSigned, wantMessageSigned = _e === void 0 ? false : _e, signatureConfig = _a.signatureConfig, _f = _a.nameIDFormat, nameIDFormat = _f === void 0 ? [] : _f, _g = _a.singleLogoutService, singleLogoutService = _g === void 0 ? [] : _g, _h = _a.assertionConsumerService, assertionConsumerService = _h === void 0 ? [] : _h;
            var descriptors_1 = {
                KeyDescriptor: [],
                NameIDFormat: [],
                SingleLogoutService: [],
                AssertionConsumerService: [],
                AttributeConsumingService: [],
            };
            var SPSSODescriptor_1 = [
                {
                    _attr: {
                        AuthnRequestsSigned: String(authnRequestsSigned),
                        WantAssertionsSigned: String(wantAssertionsSigned),
                        protocolSupportEnumeration: urn_1.namespace.names.protocol,
                    },
                },
            ];
            if (wantMessageSigned && signatureConfig === undefined) {
                console.warn("Construct service provider - missing signatureConfig");
            }
            if (signingCert) {
                descriptors_1.KeyDescriptor.push(libsaml_1.default.createKeySection("signing", signingCert).KeyDescriptor);
            }
            else {
                //console.warn('Construct service provider - missing signing certificate');
            }
            if (encryptCert) {
                descriptors_1.KeyDescriptor.push(libsaml_1.default.createKeySection("encryption", encryptCert).KeyDescriptor);
            }
            else {
                //console.warn('Construct service provider - missing encrypt certificate');
            }
            if (utility_1.isNonEmptyArray(nameIDFormat)) {
                nameIDFormat.forEach(function (f) { return descriptors_1.NameIDFormat.push(f); });
            }
            else {
                // default value
                descriptors_1.NameIDFormat.push(urn_1.namespace.format.emailAddress);
            }
            if (utility_1.isNonEmptyArray(singleLogoutService)) {
                singleLogoutService.forEach(function (a) {
                    var attr = {
                        Binding: a.Binding,
                        Location: a.Location,
                    };
                    if (a.isDefault) {
                        attr.isDefault = true;
                    }
                    descriptors_1.SingleLogoutService.push([{ _attr: attr }]);
                });
            }
            if (utility_1.isNonEmptyArray(assertionConsumerService)) {
                var indexCount_1 = 0;
                assertionConsumerService.forEach(function (a) {
                    var attr = {
                        index: String(indexCount_1++),
                        Binding: a.Binding,
                        Location: a.Location,
                    };
                    if (a.isDefault) {
                        attr.isDefault = true;
                    }
                    descriptors_1.AssertionConsumerService.push([{ _attr: attr }]);
                });
            }
            else {
                // console.warn('Missing endpoint of AssertionConsumerService');
            }
            // handle element order
            var existedElements = elementsOrder.filter(function (name) {
                return utility_1.isNonEmptyArray(descriptors_1[name]);
            });
            existedElements.forEach(function (name) {
                descriptors_1[name].forEach(function (e) {
                    var _a;
                    return SPSSODescriptor_1.push((_a = {}, _a[name] = e, _a));
                });
            });
            // Re-assign the meta reference as a XML string|Buffer for use with the parent constructor
            meta = xml([
                {
                    EntityDescriptor: [
                        {
                            _attr: {
                                entityID: entityID,
                                xmlns: urn_1.namespace.names.metadata,
                                "xmlns:assertion": urn_1.namespace.names.assertion,
                                "xmlns:ds": "http://www.w3.org/2000/09/xmldsig#",
                            },
                        },
                        { SPSSODescriptor: SPSSODescriptor_1 },
                    ],
                },
            ]);
        }
        // Use the re-assigned meta object reference here
        _this = _super.call(this, meta, [
            {
                key: "spSSODescriptor",
                localPath: ["EntityDescriptor", "SPSSODescriptor"],
                attributes: ["WantAssertionsSigned", "AuthnRequestsSigned"],
            },
            {
                key: "assertionConsumerService",
                localPath: [
                    "EntityDescriptor",
                    "SPSSODescriptor",
                    "AssertionConsumerService",
                ],
                attributes: ["Binding", "Location", "isDefault", "index"],
            },
        ]) || this;
        return _this;
    }
    /**
     * @desc Get the preference whether it wants a signed assertion response
     * @return {boolean} Wantassertionssigned
     */
    SpMetadata.prototype.isWantAssertionsSigned = function () {
        return this.meta.spSSODescriptor.wantAssertionsSigned === "true";
    };
    /**
     * @desc Get the preference whether it signs request
     * @return {boolean} Authnrequestssigned
     */
    SpMetadata.prototype.isAuthnRequestSigned = function () {
        return this.meta.spSSODescriptor.authnRequestsSigned === "true";
    };
    /**
     * @desc Get the entity endpoint for assertion consumer service
     * @param  {string} binding         protocol binding (e.g. redirect, post)
     * @return {string/[string]} URL of endpoint(s)
     */
    SpMetadata.prototype.getAssertionConsumerService = function (binding) {
        if (utility_1.isString(binding)) {
            var location_1;
            var bindName_1 = urn_1.namespace.binding[binding];
            if (utility_1.isNonEmptyArray(this.meta.assertionConsumerService)) {
                this.meta.assertionConsumerService.forEach(function (obj) {
                    if (obj.binding === bindName_1) {
                        location_1 = obj.location;
                        return;
                    }
                });
            }
            else {
                if (this.meta.assertionConsumerService.binding === bindName_1) {
                    location_1 = this.meta.assertionConsumerService.location;
                }
            }
            return location_1;
        }
        return this.meta.assertionConsumerService;
    };
    return SpMetadata;
}(metadata_1.default));
exports.SpMetadata = SpMetadata;
//# sourceMappingURL=metadata-sp.js.map