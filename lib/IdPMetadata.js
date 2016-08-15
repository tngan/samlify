/**
* @file IdPMetadata.js
* @author Tony Ngan
* @desc  Metadata of identity provider
*/
var Metadata = require('./Metadata');
var namespace = require('./urn').namespace;
var SamlLib = require('./SamlLib');
var xml = require('xml');
/**
* @param  {object/string} meta (either file path in string format or configuation in object)
* @return {object} prototype including public functions
*/
module.exports = function(meta) {
  var byMetadata = typeof meta === 'string';
  if(!byMetadata) {
    var entityID = meta.entityID;
    var wantAuthnRequestsSigned = meta.wantAuthnRequestsSigned === true;
    var signingCertFile = meta.signingCertFile;
    var encryptCertFile = meta.encryptCertFile;
    var nameIDFormat = meta.nameIDFormat || [];
    var singleSignOnService = meta.singleSignOnService || [];
    var singleLogoutService = meta.singleLogoutService || [];
    var IDPSSODescriptor = [{
      _attr: {
        WantAuthnRequestsSigned:wantAuthnRequestsSigned.toString(),
        protocolSupportEnumeration: namespace.names.protocol
      }
    }];

    if(signingCertFile) {
      IDPSSODescriptor.push(SamlLib.createKeySection('signing', signingCertFile));
    } else {
      console.warn('Construct identity provider - missing signing certificate');
    }

    if(encryptCertFile) {
      IDPSSODescriptor.push(SamlLib.createKeySection('encrypt', encryptCertFile));
    } else {
      console.warn('Construct identity provider - missing encrypt certificate');
    }

    if(nameIDFormat && nameIDFormat.length > 0) {
      nameIDFormat.forEach(function(f) {
        IDPSSODescriptor.push({
          NameIDFormat: f
        });
      });
    }

    if(singleSignOnService && singleSignOnService.length > 0) {
      singleSignOnService.forEach(function(a) {
        var _attr = {};
        var _indexCount = 0;
        if(a.isDefault) {
          _attr.isDefault = true;
        }
        _attr.index = (_indexCount++).toString();
        _attr.Binding = a.Binding;
        _attr.Location = a.Location;
        IDPSSODescriptor.push({
          SingleSignOnService: [{
            _attr: _attr
          }]
        });
      });
    } else {
      throw new Error('Missing endpoint of SingleSignOnService');
    }

    if(singleLogoutService && singleLogoutService.length > 0) {
      singleLogoutService.forEach(function(a) {
        var _attr = {};
        var _indexCount = 0;
        if(a.isDefault) {
          _attr.isDefault = true;
        }
        _attr.index = (_indexCount++).toString();
        _attr.Binding = a.Binding;
        _attr.Location = a.Location;
        IDPSSODescriptor.push({
          SingleLogoutService: [{
            _attr: _attr
          }]
        });
      });
    } else {
      console.warn('Construct identity  provider - missing endpoint of SingleLogoutService');
    }
    // Create a new metadata by setting
    meta = xml([{
      EntityDescriptor: [{
        _attr: {
          'xmlns:md': namespace.names.metadata,
          'xmlns:assertion': namespace.names.assertion,
          'xmlns:ds':'http://www.w3.org/2000/09/xmldsig#',
          entityID: entityID
        }
      },{
        IDPSSODescriptor: IDPSSODescriptor
      }]
    }]);
  }
  /**
  * @desc IdP Metadata is for creating Identity Provider, provides a set of API to manage the actions in IdP.
  */
  function IdPMetadata() {}
  /**
  * @desc  Initialize with creating a new metadata object
  * @param {string/objects} meta      declares path of the metadata
  * @param {array of Objects}         high-level XML element selector
  */
  IdPMetadata.prototype = new Metadata(meta, [{
    localName: 'IDPSSODescriptor',
    attributes: ['WantAuthnRequestsSigned']
  },{
    localName: {
      tag: 'SingleSignOnService',
      key: 'Binding'
    },
    attributeTag: 'Location'
  }], !byMetadata);
  /**
  * @desc Get the preference whether it wants a signed request
  * @return {boolean} WantAuthnRequestsSigned
  */
  IdPMetadata.prototype.isWantAuthnRequestsSigned = function isWantAuthnRequestsSigned() {
    var was = this.meta.idpssodescriptor.wantauthnrequestssigned;
    if(was === undefined) {
      return false;
    } else {
      return was.toString() === 'true';
    }
  };
  /**
  * @desc Get the entity endpoint for single sign on service
  * @param  {string} binding      protocol binding (e.g. redirect, post)
  * @return {string/object} location
  */
  IdPMetadata.prototype.getSingleSignOnService = function getSingleSignOnService(binding) {
    if(typeof binding === 'string') {
      var _location;
      var _binding = namespace.binding[binding];
      this.meta.singlesignonservice.forEach(function(obj) {
        if(obj[_binding]) {
          _location = obj[_binding];
          return;
        }
      });
      return _location;
    } else {
      return this.meta.singlesignonservice;
    }
  };
  /**
  * @desc return the prototype
  */
  return IdPMetadata.prototype;
};
