"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.setSchemaValidator = exports.ServiceProviderInstance = exports.ServiceProvider = exports.IdentityProviderInstance = exports.IdentityProvider = exports.Extractor = exports.Constants = void 0;
// version <= 1.25
var entity_idp_1 = require("./entity-idp");
exports.IdentityProvider = entity_idp_1.default;
Object.defineProperty(exports, "IdentityProviderInstance", { enumerable: true, get: function () { return entity_idp_1.IdentityProvider; } });
var entity_sp_1 = require("./entity-sp");
exports.ServiceProvider = entity_sp_1.default;
Object.defineProperty(exports, "ServiceProviderInstance", { enumerable: true, get: function () { return entity_sp_1.ServiceProvider; } });
var metadata_idp_1 = require("./metadata-idp");
Object.defineProperty(exports, "IdPMetadata", { enumerable: true, get: function () { return metadata_idp_1.default; } });
var metadata_sp_1 = require("./metadata-sp");
Object.defineProperty(exports, "SPMetadata", { enumerable: true, get: function () { return metadata_sp_1.default; } });
var utility_1 = require("./utility");
Object.defineProperty(exports, "Utility", { enumerable: true, get: function () { return utility_1.default; } });
var libsaml_1 = require("./libsaml");
Object.defineProperty(exports, "SamlLib", { enumerable: true, get: function () { return libsaml_1.default; } });
// roadmap
// new name convention in version >= 3.0
var Constants = require("./urn");
exports.Constants = Constants;
var Extractor = require("./extractor");
exports.Extractor = Extractor;
// exposed methods for customising samlify
var api_1 = require("./api");
Object.defineProperty(exports, "setSchemaValidator", { enumerable: true, get: function () { return api_1.setSchemaValidator; } });
//# sourceMappingURL=index.js.map