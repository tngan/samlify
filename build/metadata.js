"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * @file metadata.ts
 * @author tngan
 * @desc An abstraction for metadata of identity provider and service provider
 */
var fs = require("fs");
var urn_1 = require("./urn");
var extractor_1 = require("./extractor");
var utility_1 = require("./utility");
var Metadata = /** @class */ (function () {
    /**
     * @param xml
     * @param  {object} extraParse for custom metadata extractor
     */
    function Metadata(xml, extraParse) {
        if (extraParse === void 0) { extraParse = []; }
        this.xmlString = xml.toString();
        this.meta = extractor_1.extract(this.xmlString, extraParse.concat([
            {
                key: "entityDescriptor",
                localPath: ["EntityDescriptor"],
                attributes: [],
                context: true,
            },
            {
                key: "entityID",
                localPath: ["EntityDescriptor"],
                attributes: ["entityID"],
            },
            {
                // shared certificate for both encryption and signing
                key: "sharedCertificate",
                localPath: [
                    "EntityDescriptor",
                    "~SSODescriptor",
                    "KeyDescriptor",
                    "KeyInfo",
                    "X509Data",
                    "X509Certificate",
                ],
                attributes: [],
            },
            {
                // explicit certificate declaration for encryption and signing
                key: "certificate",
                localPath: ["EntityDescriptor", "~SSODescriptor", "KeyDescriptor"],
                index: ["use"],
                attributePath: ["KeyInfo", "X509Data", "X509Certificate"],
                attributes: [],
            },
            {
                key: "singleLogoutService",
                localPath: [
                    "EntityDescriptor",
                    "~SSODescriptor",
                    "SingleLogoutService",
                ],
                attributes: ["Binding", "Location"],
            },
            {
                key: "nameIDFormat",
                localPath: ["EntityDescriptor", "~SSODescriptor", "NameIDFormat"],
                attributes: [],
            },
        ]));
        // get shared certificate
        var sharedCertificate = this.meta.sharedCertificate;
        if (typeof sharedCertificate === "string") {
            this.meta.certificate = {
                signing: sharedCertificate,
                encryption: sharedCertificate,
            };
            delete this.meta.sharedCertificate;
        }
        if (Array.isArray(this.meta.entityDescriptor) &&
            this.meta.entityDescriptor.length > 1) {
            throw new Error("ERR_MULTIPLE_METADATA_ENTITYDESCRIPTOR");
        }
    }
    /**
     * @desc Get the metadata in xml format
     * @return {string} metadata in xml format
     */
    Metadata.prototype.getMetadata = function () {
        return this.xmlString;
    };
    /**
     * @desc Export the metadata to specific file
     * @param {string} exportFile is the output file path
     */
    Metadata.prototype.exportMetadata = function (exportFile) {
        fs.writeFileSync(exportFile, this.xmlString);
    };
    /**
     * @desc Get the entityID in metadata
     * @return {string} entityID
     */
    Metadata.prototype.getEntityID = function () {
        return this.meta.entityID;
    };
    /**
     * @desc Get the x509 certificate declared in entity metadata
     * @param  {string} use declares the type of certificate
     * @return {string} certificate in string format
     */
    Metadata.prototype.getX509Certificate = function (use) {
        return this.meta.certificate[use] || null;
    };
    /**
     * @desc Get the support NameID format declared in entity metadata
     * @return {array} support NameID format
     */
    Metadata.prototype.getNameIDFormat = function () {
        return this.meta.nameIDFormat;
    };
    /**
     * @desc Get the entity endpoint for single logout service
     * @param  {string} binding e.g. redirect, post
     * @return {string/object} location
     */
    Metadata.prototype.getSingleLogoutService = function (binding) {
        if (binding && utility_1.isString(binding)) {
            var bindType_1 = urn_1.namespace.binding[binding];
            var singleLogoutService = this.meta.singleLogoutService;
            if (!(singleLogoutService instanceof Array)) {
                singleLogoutService = [singleLogoutService];
            }
            var service = singleLogoutService.find(function (obj) { return obj.binding === bindType_1; });
            if (service) {
                return service.location;
            }
        }
        return this.meta.singleLogoutService;
    };
    /**
     * @desc Get the support bindings
     * @param  {[string]} services
     * @return {[string]} support bindings
     */
    Metadata.prototype.getSupportBindings = function (services) {
        var supportBindings = [];
        if (services) {
            supportBindings = services.reduce(function (acc, service) {
                var supportBinding = Object.keys(service)[0];
                return acc.push(supportBinding);
            }, []);
        }
        return supportBindings;
    };
    return Metadata;
}());
exports.default = Metadata;
//# sourceMappingURL=metadata.js.map