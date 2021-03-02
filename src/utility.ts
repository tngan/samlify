/**
 * @file utility.ts
 * @author tngan
 * @desc  Library for some common functions (e.g. de/inflation, en/decoding)
 */
import { asn1, pki, util } from 'node-forge';
import { deflate, inflate } from 'pako';

const BASE64_STR = 'base64';

/**
 * @desc Mimic lodash.zipObject
 * @param arr1 {string[]}
 * @param arr2 {[]}
 */
export function zipObject(arr1: string[], arr2: any[], skipDuplicated = true) {
	return arr1.reduce((res, l, i) => {
		if (skipDuplicated) {
			res[l] = arr2[i];
			return res;
		}
		// if key exists, aggregate with array in order to get rid of duplicate key
		if (res[l] !== undefined) {
			const arr: any[] = Array.isArray(res[l]) ? res[l] : [res[l]];
			res[l] = arr.concat(arr2[i]);
			return res;
		}
		res[l] = arr2[i];
		return res;
	}, {} as Record<string, any>);
}
/**
 * @desc Alternative to lodash.flattenDeep
 * @reference https://github.com/you-dont-need/You-Dont-Need-Lodash-Underscore#_flattendeep
 * @param input {[]}
 */
export function flattenDeep<T>(input: T | T[]): T[] {
	return Array.isArray(input) ? input.reduce((a, b) => a.concat(flattenDeep(b)), [] as T[]) : [input];
}
/**
 * @desc Alternative to lodash.last
 * @reference https://github.com/you-dont-need/You-Dont-Need-Lodash-Underscore#_last
 * @param input {[]}
 */
export function last<T>(input: T[]) {
	return input.slice(-1)[0];
}
/**
 * @desc Alternative to lodash.uniq
 * @reference https://github.com/you-dont-need/You-Dont-Need-Lodash-Underscore#_uniq
 * @param input {string[]}
 */
export function uniq(input: string[]) {
	const set = new Set(input);
	return [...set];
}
/**
 * @desc Check if the input is string
 * @param {any} input
 */
export function isString(input: any): input is string {
	return typeof input === 'string';
}
/**
 * @desc Check if the input is an array of arrays
 * @param {T[] | T[][]} input
 */
export function isArrayOfArrays<T>(arr: T[] | T[][]): arr is T[][] {
	return (arr as T[][]).every(Array.isArray);
}
/**
 * Create a buffer or return current buffer
 * @param {string|Buffer} buf
 */
export function bufferFromIfNeeded(buf: string | Buffer): Buffer {
	return Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
}
/**
 * @desc Encode string with base64 format
 * @param  {string} message                       plain-text message
 * @return {string} base64 encoded string
 */
export function base64Encode(message: string | number[]) {
	return Buffer.from(message as string).toString(BASE64_STR);
}
/**
 * @desc Decode string from base64 format
 * @param  {string} base64Message                 encoded string
 * @param  {boolean} isBytes                      determine the return value type (True: bytes False: string)
 * @return {bytes/string}  decoded bytes/string depends on isBytes, default is {string}
 */
export function base64Decode(base64Message: string, isBytes?: boolean): string | Buffer {
	const bytes = Buffer.from(base64Message, BASE64_STR);
	return isBytes ? bytes : bytes.toString();
}
/**
 * @desc Compress the string
 * @param  {string} message
 * @return {string} compressed string
 */
export function deflateString(message: string): number[] {
	const input = Array.prototype.map.call(message, (char: string) => char.charCodeAt(0)) as number[];
	return Array.from(deflate(input, { raw: true }));
}
/**
 * @desc Decompress the compressed string
 * @param  {string} compressedString
 * @return {string} decompressed string
 */
export function inflateString(compressedString: string): string {
	const inputBuffer = Buffer.from(compressedString, BASE64_STR);
	const input = Array.prototype.map.call(inputBuffer.toString('binary'), (char: string) =>
		char.charCodeAt(0)
	) as number[];
	return Array.from(inflate(input, { raw: true }))
		.map((byte) => String.fromCharCode(byte))
		.join('');
}
/**
 * @desc Abstract the normalizeCerString and normalizePemString
 * @param {buffer} File stream or string
 * @param {string} String for header and tail
 * @return {string} A formatted certificate string
 */
function _normalizeCerString(bin: string | Buffer, format: string) {
	return bin
		.toString()
		.replace(/\n/g, '')
		.replace(/\r/g, '')
		.replace(`-----BEGIN ${format}-----`, '')
		.replace(`-----END ${format}-----`, '')
		.replace(/ /g, '')
		.trim();
}
/**
 * @desc Parse the .cer to string format without line break, header and footer
 * @param  {string} certString     declares the certificate contents
 * @return {string} certificiate in string format
 */
export function normalizeCerString(certString: string | Buffer) {
	return _normalizeCerString(certString, 'CERTIFICATE');
}
/**
 * @desc Normalize the string in .pem format without line break, header and footer
 * @param  {string} pemString
 * @return {string} private key in string format
 */
export function normalizePemString(pemString: string | Buffer) {
	return _normalizeCerString(pemString.toString(), 'RSA PRIVATE KEY');
}
/**
 * @desc Get public key in pem format from the certificate included in the metadata
 * @param {string | Buffer} x509 certificate
 * @return {string} public key fetched from the certificate
 */
export function getPublicKeyPemFromCertificate(x509Certificate: string | Buffer) {
	const certDerBytes = util.decode64(x509Certificate.toString());
	const obj = asn1.fromDer(certDerBytes);
	const cert = pki.certificateFromAsn1(obj);
	return pki.publicKeyToPem(cert.publicKey);
}
/**
 * @desc Inline syntax sugar
 */
function toStringMaybe<T>(input: T, yesOrNo: boolean): string | T {
	return yesOrNo ? String(input) : input;
}
/**
 * @desc Read private key from pem-formatted string
 * @param {string | Buffer} keyString pem-formattted string
 * @param {string} protected passphrase of the key
 * @return {string} string in pem format
 * If passphrase is used to protect the .pem content (recommend)
 */
export function readPrivateKey(keyString: string | Buffer, passphrase: string | undefined, returnString = false) {
	return isString(passphrase)
		? toStringMaybe(pki.privateKeyToPem(pki.decryptRsaPrivateKey(keyString.toString(), passphrase)), returnString)
		: keyString;
}
/**
 * @desc Check if the input is an array with non-zero size
 */
export function isNonEmptyArray<T>(a?: T | null): a is T {
	return Array.isArray(a) && a.length > 0;
}

export function notEmpty<TValue>(value: TValue | null | undefined): value is TValue {
	return value !== null && value !== undefined;
}
