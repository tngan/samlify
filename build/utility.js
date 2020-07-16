"use strict";
var __read = (this && this.__read) || function (o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
};
var __spread = (this && this.__spread) || function () {
    for (var ar = [], i = 0; i < arguments.length; i++) ar = ar.concat(__read(arguments[i]));
    return ar;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.notEmpty = exports.isNonEmptyArray = exports.readPrivateKey = exports.inflateString = exports.base64Decode = exports.isString = exports.get = exports.uniq = exports.last = exports.flattenDeep = exports.zipObject = void 0;
/**
 * @file utility.ts
 * @author tngan
 * @desc  Library for some common functions (e.g. de/inflation, en/decoding)
 */
var node_forge_1 = require("node-forge");
var pako_1 = require("pako");
var BASE64_STR = "base64";
/**
 * @desc Mimic lodash.zipObject
 * @param arr1 {string[]}
 * @param arr2 {[]}
 * @param skipDuplicated
 */
function zipObject(arr1, arr2, skipDuplicated) {
    if (skipDuplicated === void 0) { skipDuplicated = true; }
    return arr1.reduce(function (res, l, i) {
        if (skipDuplicated) {
            res[l] = arr2[i];
            return res;
        }
        // if key exists, aggregate with array in order to get rid of duplicate key
        if (res[l] !== undefined) {
            res[l] = Array.isArray(res[l])
                ? res[l].concat(arr2[i])
                : [res[l]].concat(arr2[i]);
            return res;
        }
        res[l] = arr2[i];
        return res;
    }, {});
}
exports.zipObject = zipObject;
/**
 * @desc Alternative to lodash.flattenDeep
 * @reference https://github.com/you-dont-need/You-Dont-Need-Lodash-Underscore#_flattendeep
 * @param input {[]}
 */
function flattenDeep(input) {
    return Array.isArray(input)
        ? input.reduce(function (a, b) { return a.concat(flattenDeep(b)); }, [])
        : [input];
}
exports.flattenDeep = flattenDeep;
/**
 * @desc Alternative to lodash.last
 * @reference https://github.com/you-dont-need/You-Dont-Need-Lodash-Underscore#_last
 * @param input {[]}
 */
function last(input) {
    return input.slice(-1)[0];
}
exports.last = last;
/**
 * @desc Alternative to lodash.uniq
 * @reference https://github.com/you-dont-need/You-Dont-Need-Lodash-Underscore#_uniq
 * @param input {string[]}
 */
function uniq(input) {
    var set = new Set(input);
    return __spread(set);
}
exports.uniq = uniq;
/**
 * @desc Alternative to lodash.get
 * @reference https://github.com/you-dont-need/You-Dont-Need-Lodash-Underscore#_get
 * @param obj
 * @param path
 * @param defaultValue
 */
function get(obj, path, defaultValue) {
    return path
        .split(".")
        .reduce(function (a, c) { return (a && a[c] ? a[c] : defaultValue || null); }, obj);
}
exports.get = get;
/**
 * @desc Check if the input is string
 * @param input
 */
function isString(input) {
    return typeof input === "string";
}
exports.isString = isString;
/**
 * @desc Encode string with base64 format
 * @param  {string} message                       plain-text message
 * @return {string} base64 encoded string
 */
function base64Encode(message) {
    return Buffer.from(message).toString(BASE64_STR);
}
/**
 * @desc Decode string from base64 format
 * @param  {string} base64Message                 encoded string
 * @param  {boolean} isBytes                      determine the return value type (True: bytes False: string)
 * @return {bytes/string}  decoded bytes/string depends on isBytes, default is {string}
 */
function base64Decode(base64Message, isBytes) {
    var bytes = Buffer.from(base64Message, BASE64_STR);
    return Boolean(isBytes) ? bytes : bytes.toString();
}
exports.base64Decode = base64Decode;
/**
 * @desc Compress the string
 * @param  {string} message
 * @return {string} compressed string
 */
function deflateString(message) {
    var input = Array.prototype.map.call(message, function (char) {
        return char.charCodeAt(0);
    });
    return Array.from(pako_1.deflate(input, { raw: true }));
}
/**
 * @desc Decompress the compressed string
 * @param  {string} compressedString
 * @return {string} decompressed string
 */
function inflateString(compressedString) {
    var inputBuffer = Buffer.from(compressedString, BASE64_STR);
    var input = Array.prototype.map.call(inputBuffer.toString("binary"), function (char) { return char.charCodeAt(0); });
    return Array.from(pako_1.inflate(input, { raw: true }))
        .map(function (byte) { return String.fromCharCode(byte); })
        .join("");
}
exports.inflateString = inflateString;
/**
 * @desc Abstract the normalizeCerString and normalizePemString
 * @return {string} A formatted certificate string
 * @param bin
 * @param format
 */
function _normalizeCerString(bin, format) {
    return bin
        .toString()
        .replace(/\n/g, "")
        .replace(/\r/g, "")
        .replace("-----BEGIN " + format + "-----", "")
        .replace("-----END " + format + "-----", "")
        .replace(/ /g, "");
}
/**
 * @desc Parse the .cer to string format without line break, header and footer
 * @param  {string} certString     declares the certificate contents
 * @return {string} certificiate in string format
 */
function normalizeCerString(certString) {
    return _normalizeCerString(certString, "CERTIFICATE");
}
/**
 * @desc Normalize the string in .pem format without line break, header and footer
 * @param  {string} pemString
 * @return {string} private key in string format
 */
function normalizePemString(pemString) {
    return _normalizeCerString(pemString.toString(), "RSA PRIVATE KEY");
}
/**
 * @desc Return the complete URL
 * @param  {object} req                   HTTP request
 * @return {string} URL
 */
function getFullURL(req) {
    return req.protocol + "://" + req.get("host") + req.originalUrl;
}
/**
 * @desc Parse input string, return default value if it is undefined
 * @return {boolean}
 * @param str
 * @param defaultValue
 */
function parseString(str, defaultValue) {
    if (defaultValue === void 0) { defaultValue = ""; }
    return str || defaultValue;
}
/**
 * @desc Override the object by another object (rtl)
 * @return {object} result object
 * @param obj1
 * @param obj2
 */
function applyDefault(obj1, obj2) {
    return Object.assign({}, obj1, obj2);
}
/**
 * @desc Get public key in pem format from the certificate included in the metadata
 * @return {string} public key fetched from the certificate
 * @param x509Certificate
 */
function getPublicKeyPemFromCertificate(x509Certificate) {
    var certDerBytes = node_forge_1.util.decode64(x509Certificate);
    var obj = node_forge_1.asn1.fromDer(certDerBytes);
    var cert = node_forge_1.pki.certificateFromAsn1(obj);
    return node_forge_1.pki.publicKeyToPem(cert.publicKey);
}
/**
 * @desc Read private key from pem-formatted string
 * @param {string | Buffer} keyString pem-formattted string
 * @param passphrase
 * @param isOutputString
 * @return {string} string in pem format
 * If passphrase is used to protect the .pem content (recommend)
 */
function readPrivateKey(keyString, passphrase, isOutputString) {
    return isString(passphrase)
        ? this.convertToString(node_forge_1.pki.privateKeyToPem(node_forge_1.pki.decryptRsaPrivateKey(String(keyString), passphrase)), isOutputString)
        : keyString;
}
exports.readPrivateKey = readPrivateKey;
/**
 * @desc Inline syntax sugar
 */
function convertToString(input, isOutputString) {
    return Boolean(isOutputString) ? String(input) : input;
}
/**
 * @desc Check if the input is an array with non-zero size
 */
function isNonEmptyArray(a) {
    return Array.isArray(a) && a.length > 0;
}
exports.isNonEmptyArray = isNonEmptyArray;
function notEmpty(value) {
    return value !== null && value !== undefined;
}
exports.notEmpty = notEmpty;
var utility = {
    isString: isString,
    base64Encode: base64Encode,
    base64Decode: base64Decode,
    deflateString: deflateString,
    inflateString: inflateString,
    normalizeCerString: normalizeCerString,
    normalizePemString: normalizePemString,
    getFullURL: getFullURL,
    parseString: parseString,
    applyDefault: applyDefault,
    getPublicKeyPemFromCertificate: getPublicKeyPemFromCertificate,
    readPrivateKey: readPrivateKey,
    convertToString: convertToString,
    isNonEmptyArray: isNonEmptyArray,
};
exports.default = utility;
//# sourceMappingURL=utility.js.map