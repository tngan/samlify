/**
* @file Metadata.js
* @author Tony Ngan
* @desc An abstraction for metadata of identity provider and service provider
*/
var fs = require('fs');
var samlLib = require('./SamlLib');
var namespace = require('./urn').namespace;
var certUse = require('./urn').wording.certUse;
var Utility = require('./Utility');
/**
* @param  {string} meta is either xmlString or file name
* @param  {object} extraParse for custom metadata extractor
* @param  {Boolean} isXml declares whether meta is xmlString or filePath
*/
module.exports = function(meta, extraParse, isXml) {
  /**
  * @desc Constructor
  * @param {string} meta is either xmlString or file name
  */
  function Metadata(meta) {
    var that = this;
    this.xmlString = isXml === true ? meta.toString() :　fs.readFileSync(meta).toString();
    this.meta = samlLib.extractor(this.xmlString, Array.prototype.concat([{
      localName: 'EntityDescriptor',
      attributes: ['entityID']
    },{
      localName: {
        tag: 'KeyDescriptor',
        key: 'use'
      },
      valueTag: 'X509Certificate'
    },{
      localName: {
        tag: 'SingleLogoutService',
        key: 'Binding'
      },
      attributeTag: 'Location'
    }, 'NameIDFormat'], extraParse || [])); // function overloading
  }
  /**
  * @desc Get the metadata in xml format
  * @return {string} metadata in xml format
  */
  Metadata.prototype.getMetadata = function getMetadata() {
    return this.xmlString;
  };
  /**
  * @desc Export the metadata to specific file
  * @param {string} exportFile is the output file path
  */
  Metadata.prototype.exportMetadata = function exportMetadata(exportFile) {
    fs.writeFileSync(exportFile, this.xmlString);
  };
  /**
  * @desc Get the entityID in metadata
  * @return {string} entityID
  */
  Metadata.prototype.getEntityID = function getEntityID() {
    return this.meta.entitydescriptor.entityid;
  };
  /**
  * @desc Get the x509 certificate declared in entity metadata
  * @param  {string} use declares the type of certificate
  * @return {string} certificate in string format
  */
  Metadata.prototype.getX509Certificate = function getX509Certificate(use) {
    return use === certUse.signing || use === certUse.encrypt ? this.meta.keydescriptor[use] : this.meta.keydescriptor.signing;
  };
  /**
  * @desc Get the support NameID format declared in entity metadata
  * @return {array} support NameID format
  */
  Metadata.prototype.getNameIDFormat = function getNameIDFormat() {
    return this.meta.nameidformat;
  };
  /**
  * @desc Get the entity endpoint for single logout service
  * @param  {string} binding e.g. redirect, post
  * @return {string/object} location
  */
  Metadata.prototype.getSingleLogoutService = function getSingleLogoutService(binding) {
    if(typeof binding === 'string') {
      var _location;
      var _binding = namespace.binding[binding];
      this.meta.singlelogoutservice.forEach(function(obj) {
        if(obj[_binding]) {
          _location = obj[_binding];
          return;
        }
      });
      return _location;
    } else {
      return this.meta.singlelogoutservice;
    }
  };
  /**
  * @desc Get the support bindings
  * @param  {[string]} services
  * @return {[string]} support bindings
  */
  Metadata.prototype.getSupportBindings = function getSupportBindings(services) {
    var _supportBindings = [];
    if(services) {
      services.forEach(function(obj) {
        _supportBindings.push(Object.keys(obj)[0]);
      });
    }
    return _supportBindings;
  };
  /**
  * return a new instance
  */
  return new Metadata(meta);
};
