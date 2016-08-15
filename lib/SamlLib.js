/**
* @file SamlLib.js
* @author Tony Ngan
* @desc  A simple library including some common functions
*
* CHANGELOG keyword
* v1.1  SS-1.1
*/
var dom = require('xmldom').DOMParser;
var urn = require('./urn');
var tags = urn.tags;
var requestTags = tags.request;
var SignedXml = require('xml-crypto').SignedXml;
var FileKeyInfo = require('xml-crypto').FileKeyInfo;
var Utility = require('./Utility');
var forge = require('node-forge');
var nrsa = require('node-rsa');
var pki = forge.pki;
var algorithms = urn.algorithms;
var signatureAlgorithms = algorithms.signature;
var digestAlgorithms = algorithms.digest;
var certUsage = urn.wording.certUse;
var fs = require('fs');
var xml = require('xml');
var xmlenc = require('xml-encryption');
var xpath = require('xpath');

var SamlLib = function SamlLib() {
  /**
  *
  */
  var nrsaAliasMapping = {
    'http://www.w3.org/2000/09/xmldsig#rsa-sha1' : 'sha1',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' : 'sha256',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512' : 'sha512'
  };
  /**
  * @private
  * @desc Get the signing scheme alias by signature algorithms, used by the node-rsa module
  * @param {string} sigAlg    signature algorithm
  * @return {string/null} signing algorithm short-hand for the module node-rsa
  */
  var getSigningScheme = function(sigAlg) {
    var algAlias = nrsaAliasMapping[sigAlg];
    if (algAlias !== undefined) {
      return algAlias;
    } else {
      return nrsaAliasMapping[signatureAlgorithms.RSA_SHA1]; // default value
    }
  };
  /**
  * @private
  * @desc Get the digest algorithms by signature algorithms
  * @param {string} sigAlg    signature algorithm
  * @return {string/null} digest algorithm
  */
  var getDigestMethod = function(sigAlg) {
    var digestAlg = digestAlgorithms[sigAlg];
    if (digestAlg !== undefined) {
      return digestAlg;
    } else {
      return null; // default value
    }
  }
  /**
  * @private
  * @desc Create XPath
  * @param  {string/object} local     parameters to create XPath
  * @param  {boolean} isExtractAll    define whether returns whole content according to the XPath
  * @return {string} xpath
  * @example
  */
  var createXPath = function createXPath(local, isExtractAll) {
    var xpath = '';
    if(typeof local == 'object') {
      xpath = "//*[local-name(.)='" + local.name + "']/@" + local.attr;
    } else {
      xpath = isExtractAll === true ? "//*[local-name(.)='" + local + "']/text()" : "//*[local-name(.)='" + local + "']";
    }
    return xpath;
  };
  /**
  * @private
  * @desc Get the attibutes
  * @param  {xml} xmlDoc              used xml document
  * @param  {string} localName        tag name without prefix
  * @param  {[string]} attributes     array consists of name of attributes
  * @return {string/array}
  */
  var getAttributes = function getAttributes(xmlDoc, localName, attributes) {
    var _xpath = createXPath(localName);
    var _selection = xpath.select(_xpath, xmlDoc);

    if(_selection.length === 0) {
      return undefined;
    } else {
      var data = [];
      _selection.forEach(function(_s) {
        var _dat = {};
        var doc = new dom().parseFromString(_s.toString());
        attributes.forEach(function(_attribute) {
          _dat[_attribute.toLowerCase()] = getAttribute(doc, localName, _attribute);
        });
        data.push(_dat);
      });
      return data.length === 1 ? data[0] : data;
    }
  };
  /**
  * @private
  * @desc Helper function used by another private function: getAttributes
  * @param  {xml} xmlDoc          used xml document
  * @param  {string} localName    tag name without prefix
  * @param  {string} attribute    name of attribute
  * @return {string} attribute value
  */
  var getAttribute = function getAttribute(xmlDoc, localName, attribute) {
    var _xpath = createXPath({
      name: localName,
      attr: attribute
    });
    var _selection = xpath.select(_xpath, xmlDoc);

    if(_selection.length !== 1) {
      return undefined;
    } else {
      return _selection[0].nodeValue.toString();
    }
  };
  /**
  * @private
  * @desc Get the entire body according to the XPath
  * @param  {xml} xmlDoc              used xml document
  * @param  {string} localName        tag name without prefix
  * @param  {boolean} isOutputString  output is string format (default is true)
  * @return {string/array}
  */
  var getEntireBody = function getEntireBody(xmlDoc, localName, isOutputString) {
    var _xpath = createXPath(localName);
    var _selection = xpath.select(_xpath, xmlDoc);

    if(_selection.length === 0) {
      return undefined;
    } else {
      var data = [];
      _selection.forEach(function(_s) {
        data.push(Utility.convertToString(_s, isOutputString !== false));
      });
      return data.length === 1 ? data[0] : data;
    }
  };
  /**
  * @private
  * @desc  Get the inner xml according to the XPath
  * @param  {xml} xmlDoc          used xml document
  * @param  {string} localName    tag name without prefix
  * @return {string/array} value
  */
  var getInnerText = function getInnerText(xmlDoc, localName) {
    var _xpath = createXPath(localName, true);
    var _selection = xpath.select(_xpath, xmlDoc);

    if(_selection.length === 0) {
      return undefined;
    } else {
      var data = [];
      _selection.forEach(function(_s) {
        data.push(_s.nodeValue.toString());
      });
      return data.length === 1 ? data[0] : data;
    }
  };
  /**
  * @private
  * @desc Helper function used to return result with complex format
  * @param  {xml} xmlDoc              used xml document
  * @param  {string} localName        tag name without prefix
  * @param  {string} localNameKey     key associated with tag name
  * @param  {string} valueTag         tag of the value
  */
  var getInnerTextWithOuterKey = function getInnerTextWithOuterKey(xmlDoc, localName, localNameKey, valueTag) {
    var _xpath = createXPath(localName);
    var _selection = xpath.select(_xpath, xmlDoc);
    var obj = {};

    _selection.forEach(function(_s) {
      var xd = new dom().parseFromString(_s.toString());
      var key = xpath.select("//*[local-name(.)='" + localName + "']/@" + localNameKey, xd);
      var value = xpath.select("//*[local-name(.)='" + valueTag + "']/text()", xd);
      var res;

      if(key && key.length == 1 && value && value.length > 0) {
        if(value.length == 1) {
          res = value[0].nodeValue.toString();
        } else {
          var _dat = [];
          value.forEach(function(v) {
            _dat.push(v.nodeValue.toString());
          });
          res = _dat;
        }
        obj[key[0].nodeValue.toString()] = res;
      } else{
        //console.warn('Multiple keys or null value is found');
      }
    });
    return Object.keys(obj).length === 0 ? undefined : obj;
  };
  /**
  * @private
  * @desc  Get the attribute according to the key
  * @param  {string} localName            tag name without prefix
  * @param  {string} localNameKey         key associated with tag name
  * @param  {string} attributeTag         tag of the attribute
  */
  var getAttributeKey = function getAttributeKey(xmlDoc, localName, localNameKey, attributeTag) {
    var _xpath = createXPath(localName);
    var _selection = xpath.select(_xpath, xmlDoc);
    var data = [];

    _selection.forEach(function(_s) {
      var xd = new dom().parseFromString(_s.toString());
      var key = xpath.select("//*[local-name(.)='" + localName + "']/@" + localNameKey, xd);
      var value = xpath.select("//*[local-name(.)='" + localName + "']/@" + attributeTag, xd);

      if(value && value.length == 1 && key && key.length == 1) {
        var obj = {};
        obj[key[0].nodeValue.toString()] = value[0].nodeValue.toString();
        data.push(obj);
      } else {
        //console.warn('Multiple keys or null value is found');
      }
    });
    return data.length === 0 ? undefined : data;
  };

  return {
    /**
    * @desc  Create xpath, see the above private function
    * @return {string} xpath
    */
    createXPath: createXPath,
    /**
    * @desc Default login request template
    * @type {string}
    */
    defaultLoginRequestTemplate: '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>',
    /**
    * @desc Default logout request template
    * @type {string}
    */
    defaultLogoutRequestTemplate: '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}"><saml:Issuer>{Issuer}</saml:Issuer><saml:NameID SPNameQualifier="{EntityID}" Format="{NameIDFormat}">{NameID}</saml:NameID></samlp:LogoutRequest>',
    /**
    * @desc Default login response template
    * @type {String}
    */
    defaultLoginResponseTemplate: '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status><saml:Assertion ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AuthnStatement}{AttributeStatement}</saml:Assertion></samlp:Response>',
    /**
    * @desc Default logout response template
    * @type {String}
    */
    defaultLogoutResponseTemplate: '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status></samlp:LogoutResponse>',
    /**
    * @desc Repalce the tag (e.g. {tag}) inside the raw XML
    * @param  {string} rawXML      raw XML string used to do keyword replacement
    * @param  {array} tagValues    tag values
    * @return {string}
    */
    replaceTagsByValue: function replaceTagsByValue(rawXML, tagValues) {
      Object.keys(requestTags).forEach(function(t) {
        rawXML = rawXML.replace(new RegExp(requestTags[t], 'g'), tagValues[t]);
      });
      return rawXML;
    },
    /**
    * @desc Construct the XML signature for POST binding
    * @param  {string} xmlString            request/response xml string
    * @param  {string} referenceXPath       reference uri
    * @param  {string} keyFile              declares the .pem file storing the private key (e.g. path/privkey.pem)
    * @param  {string} passphrase           passphrase of .pem file [optional]
    * @param  {string} signatureAlgorithm   signature algorithm (SS-1.1)
    * @return {string} base64 encoded string
    */
    constructSAMLSignature: function constructSAMLSignature(xmlString, referenceXPath, x509, keyFile, passphrase, signatureAlgorithm, isBase64Output) {
      var sig = new SignedXml();
      // Add assertion sections as reference
      if(referenceXPath&&referenceXPath!=='') {
        sig.addReference(referenceXPath,null,getDigestMethod(signatureAlgorithm)); // SS-1.1
      }
      sig.signatureAlgorithm = signatureAlgorithm; // SS-1.1
      sig.keyInfoProvider = new this.getKeyInfo(x509);
      sig.signingKey = Utility.readPrivateKeyFromFile(keyFile, passphrase, true);
      sig.computeSignature(xmlString);
      return isBase64Output !== false ? Utility.base64Encode(sig.getSignedXml()) : sig.getSignedXml();
    },
    /**
    * @desc Verify the XML signature
    * @param  {string} xml                  xml
    * @param  {signature} signature         context of XML signature
    * @param  {object} opts                 keyFile or cert declares the X509 certificate
    * @return {boolean} verification result
    */
    verifySignature: function verifySignature(xml, signature, opts) {
      var options = opts || {};
      var refXPath = options.referenceXPath;
      var signatureAlgorithm = options.signatureAlgorithm || signatureAlgorithms.RSA_SHA1; // SS1.1
      var sig = new SignedXml();
      sig.signatureAlgorithm = signatureAlgorithm; // SS1.1
      // Add assertion sections as reference
      if(options.keyFile) {
        sig.keyInfoProvider = new FileKeyInfo(options.keyFile);
      } else if(options.cert) {
        sig.keyInfoProvider = new this.getKeyInfo(options.cert.getX509Certificate(certUsage.SIGNING));
      } else {
        throw new Error('Undefined certificate or keyfile in \'opts\' object');
      }
      sig.loadSignature(signature.toString());
      var res = sig.checkSignature(xml);
      if (!res) {
        throw new Error(sig.validationErrors);
      } else {
        return true;
      }
    },
    /**
    * @desc High-level XML extractor
    * @param  {string} xmlString
    * @param  {[object]} fields
    */
    extractor: function extractor(xmlString, fields) {
      var doc = new dom().parseFromString(xmlString);
      var _meta = {};

      fields.forEach(function(field) {
        var _objKey;
        var res;

        if(typeof field === 'string') {
          _meta[field.toLowerCase()] = getInnerText(doc, field);
        }else if(typeof field === 'object') {
          var _localName = field.localName;
          var _extractEntireBody = field.extractEntireBody === true;
          var _attributes = field.attributes || [];
          var _customKey = field.customKey || '';

          if(typeof _localName === 'string') {
            _objKey = _localName;
            if(_extractEntireBody) {
              res = getEntireBody(doc,_localName);
            } else {
              if(_attributes.length !== 0) {
                res = getAttributes(doc, _localName, _attributes);
              } else {
                res = getInnerText(doc,_localName);
              }
            }
          } else {
            _objKey = _localName.tag;
            if(field.attributeTag) {
              res = getAttributeKey(doc, _objKey, _localName.key, field.attributeTag);
            } else if (field.valueTag) {
              res = getInnerTextWithOuterKey(doc, _objKey, _localName.key, field.valueTag);
            }
          }
          _meta[_customKey === '' ? _objKey.toLowerCase() : _customKey] = res;
        }
      });
      return _meta;
    },
    /**
    * @desc Helper function to create the key section in metadata (abstraction for signing and encrypt use)
    * @param  {string} use          type of certificate (e.g. signing, encrypt)
    * @param  {string} certFile     declares the .cer file (e.g. path/certificate.cer)
    * @return {object} object used in xml module
    */
    createKeySection: function createKeySection(use, certFile) {
      return {
        KeyDescriptor:[{
          _attr: {
            use: use
          }
        },{
          KeyInfo: [{
            _attr: {
              'xmlns:ds':'http://www.w3.org/2000/09/xmldsig#'
            }
          },{
            X509Data: [{
              X509Certificate: Utility.parseCerFile(certFile)
            }]
          }]
        }]
      };
    },
    /**
    * @desc Constructs SAML message
    * @param  {string} octetString               see "Bindings for the OASIS Security Assertion Markup Language (SAML V2.0)" P.17/46
    * @param  {string} keyFile                   declares the .pem file storing the private key (e.g. path/privkey.pem)
    * @param  {string} passphrase                passphrase of .pem file [optional]
    * @param  {string} signingAlgorithm          signing algorithm (SS-1.1)
    * @return {string} message signature
    */
    constructMessageSignature: function constructMessageSignature(octetString, keyFile, passphrase, isBase64, signingAlgorithm) {
      // Default returning base64 encoded signature
      // Embed with node-rsa module
      key = new nrsa(Utility.readPrivateKeyFromFile(keyFile, passphrase), {
        signingScheme: getSigningScheme(signingAlgorithm) // SS-1.1
      });
      var signature = key.sign(octetString);
      // Use private key to sign data
      return isBase64 !== false ? signature.toString('base64') : signature;
    },
    /**
    * @desc Verifies message signature
    * @param  {Metadata} metadata                 metadata object of identity provider or service provider
    * @param  {string} octetString                see "Bindings for the OASIS Security Assertion Markup Language (SAML V2.0)" P.17/46
    * @param  {string} signature                  context of XML signature
    * @param  {string} verifyAlgorithm            algorithm used to verify (SS-1.1)
    * @return {boolean} verification result
    *
    * SS1.1 Code refractoring
    */
    verifyMessageSignature: function verifyMessageSignature(metadata, octetString, signature, verifyAlgorithm) {
      var key = new nrsa(Utility.getPublicKeyPemFromCertificate(metadata.getX509Certificate(certUsage.SIGNING)), {
        signingScheme: getSigningScheme(verifyAlgorithm)
      });
      return key.verify(new Buffer(octetString), signature);
    },
    /**
    * @desc Get the public key in string format
    * @param  {string} x509Certificate          certificate
    * @return {string} public key
    *
    * SS1.1 Code refractoring
    */
    getKeyInfo: function getKeyInfo(x509Certificate) {
      this.getKeyInfo = function(key) {
        return '<X509Data><X509Certificate>' + x509Certificate + '</X509Certificate></X509Data>';
      };
      this.getKey = function(keyInfo) {
        return Utility.getPublicKeyPemFromCertificate(x509Certificate).toString();
      };
    },
    /**
    * @desc Encrypt the assertion section in Response
    * @param  {Entity} sourceEntity             source entity
    * @param  {Entity} targetEntity             target entity
    * @param {string} entireXML                 response in xml string format
    * @return {function} a callback to receive the finalized xml
    *
    * SS1.1
    */
    encryptAssertion: function encryptAssertion(sourceEntity, targetEntity, entireXML, callback) {
      // Implement encryption after signature if it has
      if(entireXML) {
        var sourceEntitySetting = sourceEntity.entitySetting;
        var targetEntitySetting = targetEntity.entitySetting;
        var sourceEntityMetadata = sourceEntity.entityMeta;
        var targetEntityMetadata = targetEntity.entityMeta;
        var assertionNode = getEntireBody(new dom().parseFromString(entireXML), 'Assertion');
        var assertion = assertionNode !== undefined ? Utility.parseString(assertionNode.toString()) : '';

        if(assertion === '') throw new Error('Undefined assertion or invalid syntax');
        // Perform encryption depends on the setting, default is false
        if(sourceEntitySetting.isAssertionEncrypted) {
          // callback should be function (res) { ... }
          xmlenc.encrypt(assertion, {
            // use xml-encryption module
            rsa_pub: new Buffer(Utility.getPublicKeyPemFromCertificate(targetEntityMetadata.getX509Certificate(certUsage.ENCRYPT), true).replace(/\r?\n|\r/g, '')), // public key from certificate
            pem: new Buffer('-----BEGIN CERTIFICATE-----' + targetEntityMetadata.getX509Certificate(certUsage.ENCRYPT) + '-----END CERTIFICATE-----'),
            encryptionAlgorithm: sourceEntitySetting.dataEncryptionAlgorithm,
            keyEncryptionAlgorighm: sourceEntitySetting.keyEncryptionAlgorithm // typo in xml-encryption
          }, function(err, res) {
            if(err) throw new Error('Exception in encrpytedAssertion ' + err);
            if (res) {
              callback(Utility.base64Encode(entireXML.replace(assertion, '<saml:EncryptedAssertion>' + res + '</saml:EncryptedAssertion>')));
            } else {
              throw new Error('Undefined encrypted assertion');
            }
          });
        } else {
          callback(Utility.base64Encode(entireXML)); // No need to do encrpytion
        }
      } else {
        throw new Error('Empty or undefined xml string');
      }
    },
    /**
    * @desc Decrypt the assertion section in Response
    * @param  {string} type             only accept SAMLResponse to proceed decryption
    * @param  {Entity} here             this entity
    * @param  {Entity} from             from the entity where the message is sent
    * @param {string} entireXML         response in xml string format
    * @return {function} a callback to get back the entire xml with decrypted assertion
    *
    * SS1.1
    */
    decryptAssertion: function decryptAssertion(type, here, from, entireXML, callback) {
      // Implement decryption first then check the signature
      if(entireXML) {
        // Perform encryption depends on the setting of where the message is sent, default is false
        if(type === 'SAMLResponse' && from.entitySetting.isAssertionEncrypted) {
          var hereSetting = here.entitySetting;
          // callback should be function (res) { ... }
          var parseEntireXML = new dom().parseFromString(entireXML);
          var encryptedDataNode = getEntireBody(parseEntireXML, 'EncryptedData');
          var encryptedData = encryptedDataNode !== undefined ? Utility.parseString(encryptedDataNode.toString()) : '';

          if(encryptedData === '') throw new Error('Undefined assertion or invalid syntax');
          xmlenc.decrypt(encryptedData, {
            key: Utility.readPrivateKeyFromFile(hereSetting.privateKeyFile, hereSetting.privateKeyFilePass), // use this entity's private to decrypt
          }, function(err, res) {
            if(err) throw new Error('Exception in decryptAssertion ' + err);
            if (res) {
              callback(parseEntireXML.toString().replace('<saml:EncryptedAssertion>', '').replace('</saml:EncryptedAssertion>', '').replace(encryptedData, res));
            } else {
              throw new Error('Undefined encrypted assertion');
            }
          });
        } else {
          callback(entireXML); // No need to do encrpytion
        }
      } else {
        throw new Error('Empty or undefined xml string');
      }
    }
  };
};

module.exports = SamlLib();
