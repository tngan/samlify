/**
* @file SPMetadata.js
* @author Tony Ngan
* @desc  Metadata of service provider
*/
var namespace = require('./urn').namespace;
var Metadata = require('./Metadata');
var xml = require('xml');
var SamlLib = require('./SamlLib');
/**
* @param  {object/string} meta (either file path in string format or configuation in object)
* @return {object} prototypes including public functions
*/
module.exports = function(meta) {
  var byMetadata = typeof meta === 'string';

  if(!byMetadata) {
    var entityID = meta.entityID,
    authnRequestsSigned = meta.authnRequestsSigned === true,
    wantAssertionsSigned = meta.wantAssertionsSigned === true,
    signingCertFile = meta.signingCertFile,
    encryptCertFile = meta.encryptCertFile,
    nameIDFormat = meta.nameIDFormat || [],
    singleLogoutService = meta.singleLogoutService || [];
    assertionConsumerService = meta.assertionConsumerService || [];

    var SPSSODescriptor = [{
      _attr: {
        AuthnRequestsSigned: authnRequestsSigned.toString(),
        WantAssertionsSigned: wantAssertionsSigned.toString(),
        protocolSupportEnumeration: namespace.names.protocol
      }
    }];

    if(signingCertFile) {
      SPSSODescriptor.push(SamlLib.createKeySection('signing', signingCertFile));
    } else {
      console.warn('Construct service provider - missing signing certificate');
    }

    if(encryptCertFile) {
      SPSSODescriptor.push(SamlLib.createKeySection('encrypt', encryptCertFile));
    } else {
      console.warn('Construct service provider - missing encrypt certificate');
    }

    if(nameIDFormat && nameIDFormat.length > 0) {
      nameIDFormat.forEach(function(f) {
        SPSSODescriptor.push({
          NameIDFormat: f
        });
      });
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
        SPSSODescriptor.push({
          SingleLogoutService: [{
            _attr: _attr
          }]
        });
      });
    }

    if(assertionConsumerService && assertionConsumerService.length > 0) {
      assertionConsumerService.forEach(function(a) {
        var _attr = {};
        var _indexCount = 0;
        if(a.isDefault) {
          _attr.isDefault = true;
        }
        _attr.index = (_indexCount++).toString();
        _attr.Binding = a.Binding;
        _attr.Location = a.Location;
        SPSSODescriptor.push({
          AssertionConsumerService: [{
            _attr: _attr
          }]
        });
      });
    } else {
      throw new Error('Missing endpoint of AssertionConsumerService');
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
        SPSSODescriptor: SPSSODescriptor
      }]
    }]);
  }
  /**
  * @desc SP Metadata is for creating Service Provider, provides a set of API to manage the actions in SP.
  */
  function SPMetadata() {}
  /**
  * @desc  Initialize with creating a new metadata object
  * @param {string/objects} meta     declares path of the metadata
  * @param {array of Objects}        high-level XML element selector
  */
  SPMetadata.prototype = new Metadata(meta, [{
    localName: 'SPSSODescriptor',
    attributes: ['WantAssertionsSigned', 'AuthnRequestsSigned']
  },{
    localName: 'AssertionConsumerService',
    attributes: ['Binding', 'Location', 'isDefault', 'index']
  }], !byMetadata);
  /**
  * @desc Get the preference whether it wants a signed assertion response
  * @return {boolean} Wantassertionssigned
  */
  SPMetadata.prototype.isWantAssertionsSigned = function isWantAssertionsSigned() {
    return this.meta.spssodescriptor.wantassertionssigned === 'true';
  };
  /**
  * @desc Get the preference whether it signs request
  * @return {boolean} Authnrequestssigned
  */
  SPMetadata.prototype.isAuthnRequestSigned = function isAuthnRequestSigned() {
    return this.meta.spssodescriptor.authnrequestssigned === 'true';
  };
  /**
  * @desc Get the entity endpoint for assertion consumer service
  * @param  {string} binding         protocol binding (e.g. redirect, post)
  * @return {string/[string]} URL of endpoint(s)
  */
  SPMetadata.prototype.getAssertionConsumerService = function getAssertionConsumerService(binding) {
    if(typeof binding === 'string') {
      var _location;
      var _binding = namespace.binding[binding];

      if(this.meta.assertionconsumerservice.length > 0) {
        this.meta.assertionconsumerservice.forEach(function(obj) {
          if(obj.binding === _binding) {
            _location = obj.location;
            return;
          }
        });
      } else {
        if(this.meta.assertionconsumerservice.binding === _binding) {
          _location = this.meta.assertionconsumerservice.location;
        }
      }
      return _location;
    } else {
      return this.meta.singlelogoutservice;
    }
  };
  /**
  * @desc return the prototype
  */
  return SPMetadata.prototype;
};
