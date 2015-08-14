/**
* @file SamlLib.js
* @author Tony Ngan
* @desc  A simple library including some common functions
*/
var dom = require('xmldom').DOMParser,
tags = require('./urn').tags,
requestTags = tags.request,
SignedXml = require('xml-crypto').SignedXml,
FileKeyInfo = require('xml-crypto').FileKeyInfo,
Utility = require('./Utility'),
forge = require('node-forge'),
nrsa = require('node-rsa'),
pki = forge.pki,
fs = require('fs'),
xml = require('xml'),
xpath = require('xpath');

var SamlLib = function SamlLib(){
    /**
    * @private
    * @desc Create XPath
    * @param  {string/object} local     parameters to create XPath
    * @param  {boolean} isExtractAll    define whether returns whole content according to the XPath
    * @return {string} xpath
    * @example
    */
    var createXPath = function createXPath(local,isExtractAll){
        var xpath = '';
        if(typeof local == 'object'){
            xpath = "//*[local-name(.)='"+local.name+"']/@"+local.attr;
        }else{
            xpath = isExtractAll === true ? "//*[local-name(.)='"+local+"']/text()" : "//*[local-name(.)='"+local+"']";
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
    var getAttributes = function getAttributes(xmlDoc,localName,attributes){
        var _xpath = createXPath(localName);
        var _selection = xpath.select(_xpath,xmlDoc);
        if(_selection.length === 0){
            return undefined;
        }else{
            var data = [];
            _selection.forEach(function(_s){
                var _dat = {};
                var doc = new dom().parseFromString(_s.toString());
                attributes.forEach(function(_attribute){
                    _dat[_attribute.toLowerCase()] = getAttribute(doc,localName,_attribute);
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
    var getAttribute = function getAttribute(xmlDoc,localName,attribute){
        var _xpath = createXPath({name:localName,attr:attribute});
        var _selection = xpath.select(_xpath,xmlDoc);
        if(_selection.length !== 1){
            return undefined;
        }else{
            return _selection[0].nodeValue.toString();
        }
    };
    /**
    * @private
    * @desc Get the entire body according to the XPath
    * @param  {xml} xmlDoc          used xml document
    * @param  {string} localName    tag name without prefix
    * @return {string/array}
    */
    var getEntireBody = function getEntireBody(xmlDoc,localName){
        var _xpath = createXPath(localName);
        var _selection = xpath.select(_xpath,xmlDoc);
        if(_selection.length === 0){
            return undefined;
        }else{
            var data = [];
            _selection.forEach(function(_s){
                data.push(_s.toString());
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
    var getInnerText = function getInnerText(xmlDoc,localName){
        var _xpath = createXPath(localName,true);
        var _selection = xpath.select(_xpath,xmlDoc);
        if(_selection.length === 0){
            return undefined;
        }else{
            var data = [];
            _selection.forEach(function(_s){
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
    var getInnerTextWithOuterKey = function getInnerTextWithOuterKey(xmlDoc,localName,localNameKey,valueTag){
        var _xpath = createXPath(localName);
        var _selection = xpath.select(_xpath,xmlDoc);
        var obj = {};
        _selection.forEach(function(_s){
            var xd = new dom().parseFromString(_s.toString());
            var key = xpath.select("//*[local-name(.)='"+localName+"']/@"+localNameKey,xd);
            var value = xpath.select("//*[local-name(.)='"+valueTag+"']/text()",xd);
            var res;
            if(key && key.length == 1 && value && value.length > 0){
                if(value.length == 1) {
                    res = value[0].nodeValue.toString();
                } else {
                    var _dat = [];
                    value.forEach(function(v){
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
    var getAttributeKey = function getAttributeKey(xmlDoc,localName,localNameKey,attributeTag){
        var _xpath = createXPath(localName);
        var _selection = xpath.select(_xpath,xmlDoc);
        var data = [];
        _selection.forEach(function(_s){
            var xd = new dom().parseFromString(_s.toString());
            var key = xpath.select("//*[local-name(.)='"+localName+"']/@"+localNameKey,xd);
            var value = xpath.select("//*[local-name(.)='"+localName+"']/@"+attributeTag,xd);
            if(value && value.length == 1 && key && key.length == 1){
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
        replaceTagsByValue: function replaceTagsByValue(rawXML,tagValues){
            Object.keys(requestTags).forEach(function(t){
                rawXML = rawXML.replace(new RegExp(requestTags[t],'g'),tagValues[t]);
            });
            return rawXML;
        },
        /**
        * @desc Construct the XML signature for POST binding
        * @param  {string} xmlString        request/response xml string
        * @param  {string} referenceXPath   reference uri
        * @param  {string} keyFile          declares the .pem file storing the private key (e.g. path/privkey.pem)
        * @param  {string} passphrase       passphrase of .pem file [optional]
        * @return {string} base64 encoded string
        */
        constructSAMLSignature: function constructSAMLSignature(xmlString,referenceXPath,x509,keyFile,passphrase){
            var sig = new SignedXml(),
            pem;
            // Add assertion sections as reference
            if(referenceXPath&&referenceXPath!==''){
                sig.addReference(referenceXPath);
            }
            // If passphrase is used to protect the .pem file (recommend)
            if(typeof passphrase === 'string'){
                var privateKey = pki.decryptRsaPrivateKey(fs.readFileSync(keyFile), passphrase);
                pem = pki.privateKeyToPem(privateKey).toString();
            } else {
                pem = fs.readFileSync(keyFile);
            }
            sig.keyInfoProvider = new this.getKeyInfo(x509);
            sig.signingKey = pem;
            sig.computeSignature(xmlString);
            return Utility.base64Encode(sig.getSignedXml());
        },
        /**
        * @desc Verify the XML signature
        * @param  {string} xml                  xml
        * @param  {signature} signature         context of XML signature
        * @param  {object} opts                 keyFile or cert declares the X509 certificate
        * @return {boolean} verification result
        */
        verifySignature: function verifySignature(xml,signature,opts){
            var options = opts || {},
            refXPath = options.referenceXPath,
            sig = new SignedXml();
            // Add assertion sections as reference
            if(options.keyFile){
                sig.keyInfoProvider = new FileKeyInfo(options.keyFile);
            } else if(options.cert){
                sig.keyInfoProvider = new this.getKeyInfo(options.cert.getX509Certificate('signing'));
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
        extractor: function extractor(xmlString,fields){
            var doc = new dom().parseFromString(xmlString);
            var _meta = {};

            fields.forEach(function(field){
                var _objKey, res;
                if(typeof field === 'string'){
                    _meta[field.toLowerCase()] = getInnerText(doc,field);
                }else if(typeof field === 'object'){
                    var _localName = field.localName,
                    _extractEntireBody = field.extractEntireBody === true,
                    _attributes = field.attributes || [],
                    _customKey = field.customKey || '';
                    if(typeof _localName === 'string'){
                        _objKey = _localName;
                        if(_extractEntireBody){
                            res = getEntireBody(doc,_localName);
                        }else{
                            if(_attributes.length !== 0) res = getAttributes(doc,_localName,_attributes);
                            else res = getInnerText(doc,_localName);
                        }
                    } else {
                        _objKey = _localName.tag;
                        if(field.attributeTag) {
                            res = getAttributeKey(doc,_objKey,_localName.key,field.attributeTag);
                        } else if (field.valueTag){
                            res = getInnerTextWithOuterKey(doc,_objKey,_localName.key,field.valueTag);
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
        createKeySection: function createKeySection(use,certFile){
            return {
                KeyDescriptor:[{
                    _attr: {use: use}
                },{
                    KeyInfo: [{
                        _attr: {'xmlns:ds':'http://www.w3.org/2000/09/xmldsig#'}
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
        * @return {string} message signature
        */
        constructMessageSignature: function constructMessageSignature(octetString,keyFile,passphrase,isBase64) {
            // Default returning base64 encoded signature
            var _isBase64 = isBase64 !== false;
            // Read from .pem file
            var pem = fs.readFileSync(keyFile);
            // If passphrase is used to protect the .pem file (recommend)
            if(typeof passphrase === 'string'){
                var privateKey = pki.decryptRsaPrivateKey(pem, passphrase);
                pem = pki.privateKeyToPem(privateKey);
            }
            // Embed with node-rsa module
            key = new nrsa(pem);
            var signature = key.sign(octetString);
            // Use private key to sign data
            return _isBase64 ? signature.toString('base64') : signature;
        },
        /**
        * @desc Verifies message signature
        * @param  {Metadata} metadata                 metadata object of identity provider or service provider
        * @param  {string} octetString                see "Bindings for the OASIS Security Assertion Markup Language (SAML V2.0)" P.17/46
        * @param  {string} signature                  context of XML signature
        * @return {boolean} verification result
        */
        verifyMessageSignature: function verifyMessageSignature(metadata,octetString,signature){
            var certString = metadata.getX509Certificate('signing'),
            certDerBytes = forge.util.decode64(certString),
            obj = forge.asn1.fromDer(certDerBytes),
            cert = forge.pki.certificateFromAsn1(obj),
            publicKey = cert.publicKey,
            pem = forge.pki.publicKeyToPem(publicKey),
            key = new nrsa(pem);
            return key.verify(new Buffer(octetString),signature);
        },
        /**
        * @desc Get the public key in string format
        * @param  {string} x509Certificate
        * @return {string} public key embeded in certificate
        */
        getKeyInfo: function getKeyInfo(x509Certificate){
            this.getKeyInfo = function(key) {
                return '<X509Data><X509Certificate>'+x509Certificate+'</X509Certificate></X509Data>';
            };
            this.getKey = function(keyInfo) {
                var certDerBytes = forge.util.decode64(x509Certificate),
                obj = forge.asn1.fromDer(certDerBytes),
                cert = forge.pki.certificateFromAsn1(obj),
                publicKey = cert.publicKey,
                pem = forge.pki.publicKeyToPem(publicKey).toString();
                return pem;
            };
        }
    };
};

module.exports = SamlLib();
