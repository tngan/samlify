/*!
 * express-saml2
 * Copyright(c) 2015 Tony Ngan
 * MIT Licensed
 */

var libPath = './lib/';

module.exports.IdentityProvider = require(libPath + 'IdentityProvider');
module.exports.ServiceProvider = require(libPath + 'ServiceProvider');

module.exports.IdPMetadata = require(libPath + 'IdPMetadata');
module.exports.SPMetadata = require(libPath + 'SPMetadata');

module.exports.Utility = require(libPath + 'Utility');
module.exports.SamlLib = require(libPath + 'SamlLib');

module.exports.Constants = require(libPath + 'urn');
