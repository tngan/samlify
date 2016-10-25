/**
* @file utility.ts
* @author tngan
* @desc  Library for some common functions (e.g. de/inflation, en/decoding)
*/
import * as fs from 'fs';
import { pki, util, asn1 } from 'node-forge';
import { inflate, deflate } from 'deflate-js';
import * as _ from 'lodash';

const BASE64_STR = 'base64';
const ASCII_STR = 'ascii';
/**
* @desc Encode string with base64 format
* @param  {string} message                       plain-text message
* @return {string} base64 encoded string
*/
function base64Encode(message: string) {
  return new Buffer(message).toString(BASE64_STR);
}
/**
* @desc Decode string from base64 format
* @param  {string} base64Message                 encoded string
* @param  {boolean} isBytes                      determine the return value type (True: bytes False: string)
* @return {bytes/string}  decoded bytes/string depends on isBytes, default is {string}
*/
function base64Decode(base64Message: string, isBytes?: boolean): string | Buffer {
  const bytes = new Buffer(base64Message, BASE64_STR);
  return Boolean(isBytes) ? bytes : bytes.toString(ASCII_STR);
}
/**
* @desc Compress the string
* @param  {string} message
* @return {string} compressed string
*/
function deflateString(message: string): string {
  return deflate(Array.prototype.map.call(message, char => char.charCodeAt(0)));
}
/**
* @desc Decompress the compressed string
* @param  {string} compressedString
* @return {string} decompressed string
*/
function inflateString(compressedString: string): string {
  return inflate(Array.prototype.map.call(new Buffer(compressedString, BASE64_STR).toString('binary'), char => char.charCodeAt(0)))
  .map(byte => String.fromCharCode(byte))
  .join('');
}
/**
* @desc Abstract the parseCerFile and normalizePemString
* @param {buffer} File stream
* @param {string} String for header and tail of file
* @return {string} A formatted certificate string
*/
function normalizeCerString(bin, format: string) {
  return bin.toString().replace(/\n/g, '').replace(/\r/g, '').replace(`-----BEGIN ${format}-----`, '').replace(`-----END ${format}-----`, '');
}
/**
* @desc Parse the .cer to string format without line break, header and footer
* @param  {string} certFile     declares the .cer file (e.g. path/certificate.cer)
* @return {string} certificiate in string format
*/
function parseCerFile(certFile: string){
  return normalizeCerString(fs.readFileSync(certFile), 'CERTIFICATE');
}
/**
* @desc Normalize the string in .pem format without line break, header and footer
* @param  {string} pemString
* @return {string} private key in string format
*/
function normalizePemString(pemString: string){
  return normalizeCerString(pemString.toString(), 'RSA PRIVATE KEY');
}
/**
* @desc Return the complete URL
* @param  {object} req                   HTTP request
* @return {string} URL
*/
function getFullURL(req){
  return `${req.protocol}://${req.get('host')}${req.originalUrl}`;
}
/**
* @desc Parse input string, return default value if it is undefined
* @param  {string/boolean}
* @return {boolean}
*/
function parseString(str, defaultValue = ''){
  return str || defaultValue;
}
/**
* @desc Override the object by another object (rtl)
* @param  {object} default object
* @param  {object} object applied to the default object
* @return {object} result object
*/
function applyDefault(obj1, obj2){
  return Object.assign({}, obj1, obj2);
}
/**
* @desc Get public key in pem format from the certificate included in the metadata
* @param {string} x509 certificate
* @return {string} public key fetched from the certificate
*/
function getPublicKeyPemFromCertificate(x509Certificate: string){
  const certDerBytes = util.decode64(x509Certificate);
  const obj = asn1.fromDer(certDerBytes);
  const cert = pki.certificateFromAsn1(obj);
  return pki.publicKeyToPem(cert.publicKey);
}
/**
* @desc Read private key from .pem file
* @param {string} path of the .pem file
* @param {string} protected passphrase of the keyFile
* @return {string} string in pem format
* If passphrase is used to protect the .pem file (recommend)
*/
function readPrivateKeyFromFile(keyFile: string, passphrase: string, isOutputString?: boolean){
  return typeof passphrase === 'string' ? this.convertToString(pki.privateKeyToPem(pki.decryptRsaPrivateKey(fs.readFileSync(keyFile), passphrase)), isOutputString) : fs.readFileSync(keyFile);
}
/**
* @desc Inline syntax sugar
*/
function convertToString(input, isOutputString){
  return Boolean(isOutputString) ? String(input) : input;
}

const utility = {
  base64Encode,
  base64Decode,
  deflateString,
  inflateString,
  parseCerFile,
  normalizePemString,
  getFullURL,
  parseString,
  applyDefault,
  getPublicKeyPemFromCertificate,
  readPrivateKeyFromFile,
  convertToString
};

export default utility;
