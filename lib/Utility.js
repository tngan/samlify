/**
* @file Utility.js
* @author Tony Ngan
* @desc  Library for some common functions (e.g. de/inflation, en/decoding)
*/
var rfc1951 = require('deflate-js');
var forge = require('node-forge');
var pki = forge.pki;
var fs = require('fs');

var utility = function() {
  return {
    /**
    * @desc Encode string with base64 format
    * @param  {string} message                       plain-text message
    * @return {string} base64 encoded string
    */
    base64Encode: function base64Encode(message) {
      return new Buffer(message).toString('base64');
    },
    /**
    * @desc Decode string from base64 format
    * @param  {string} base64Message                 encoded string
    * @param  {boolean} isBytes                      determine the return value type (True: bytes False: string)
    * @return {bytes/string}  decoded bytes/string depends on isBytes, default is {string}
    */
    base64Decode: function base64Decode(base64Message, isBytes) {
      var _isBytes = isBytes === true;
      var _bytes = new Buffer(base64Message, 'base64');
      return _isBytes ? _bytes : _bytes.toString('ascii');
    },
    /**
    * @desc Compress the string
    * @param  {string} message
    * @return {string} compressed string
    */
    deflateString: function deflateString(message) {
      return rfc1951.deflate(Array.prototype.map.call(message, function(char) {
        return char.charCodeAt(0);
      }));
    },
    /**
    * @desc Decompress the compressed string
    * @param  {string} compressedString
    * @return {string} decompressed string
    */
    inflateString: function inflateString(compressedString) {
      return rfc1951.inflate(Array.prototype.map.call(new Buffer(compressedString, 'base64').toString('binary'), function(char) {
        return char.charCodeAt(0);
      })).map(function (byte) {
        return String.fromCharCode(byte);
      }).join('');
    },
    /**
    * @desc Parse the .cer to string format without line break, header and footer
    * @param  {string} certFile     declares the .cer file (e.g. path/certificate.cer)
    * @return {string} certificiate in string format
    */
    parseCerFile: function parseCerFile(certFile){
      return fs.readFileSync(certFile).toString().replace(/\n/g, '').replace(/\r/g, '').replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '');
    },
    /**
    * @desc Normalize the string in .pem format without line break, header and footer
    * @param  {string} pemString
    * @return {string} private key in string format
    */
    normalizePemString: function normalizePemString(pemString){
      return pemString.toString().replace(/\n/g, '').replace(/\r/g, '').replace('-----BEGIN RSA PRIVATE KEY-----', '').replace('-----END RSA PRIVATE KEY-----', '');
    },
    /**
    * @desc Return the complete URL
    * @param  {object} req                   HTTP request
    * @return {string} URL
    */
    getFullURL: function getFullURL(req){
      return req.protocol + '://' + req.get('host') + req.originalUrl;
    },
    /**
    * @desc Check whether the input is true
    * @param  {string/boolean} t
    * @return {boolean}
    */
    isTrue: function isTrue(t){
      var res = false;
      if(t !== undefined){
        if(t.constructor == Boolean){
          res = t;
        } else if(t.constructor == String){
          res = t === 'true';
        }
      }
      return res;
    },
    /**
    * @desc Parse input string, return default value if it is undefined
    * @param  {string/boolean}
    * @return {boolean}
    */
    parseString: function parseString(str, defaultValue){
      return str || (defaultValue || '');
    },
    /**
    * @desc Override the object by another object (rtl)
    * @param  {object} default object
    * @param  {object} object applied to the default object
    * @return {object} result object
    */
    applyDefault: function applyDefault(obj1, obj2){
      for(var _key in obj2){
        obj1[_key] = obj2[_key];
      }
      return obj1;
    },
    /**
    * @desc Get public key in pem format from the certificate included in the metadata
    * @param {string} x509 certificate
    * @return {string} public key fetched from the certificate
    */
    getPublicKeyPemFromCertificate: function getPublicKeyPemFromCertificate(x509Certificate){
      var certDerBytes = forge.util.decode64(x509Certificate);
      var obj = forge.asn1.fromDer(certDerBytes);
      var cert = forge.pki.certificateFromAsn1(obj);
      return pki.publicKeyToPem(cert.publicKey);
    },
    /**
    * @desc Read private key from .pem file
    * @param {string} path of the .pem file
    * @param {string} protected passphrase of the keyFile
    * @return {string} string in pem format
    * If passphrase is used to protect the .pem file (recommend)
    */
    readPrivateKeyFromFile: function readPrivateKeyFromFile(keyFile, passphrase, isOutputString){
      return typeof passphrase === 'string' ? this.convertToString(pki.privateKeyToPem(pki.decryptRsaPrivateKey(fs.readFileSync(keyFile), passphrase)), isOutputString) : fs.readFileSync(keyFile);
    },
    /**
    * @desc Inline syntax sugar
    */
    convertToString: function convertToString(input, isOutputString){
      return isOutputString === true ? input.toString() : input;
    }
  };
};

module.exports = utility();
