/**
 * @file utility.ts
 * @author tngan
 * @desc Common helpers (encoding, compression, certificate / key handling).
 */
import { X509Certificate, createPrivateKey } from 'crypto';
import { deflateRawSync, inflateRawSync } from 'zlib';

const BASE64_STR = 'base64';

/**
 * Build an object by zipping two parallel arrays of keys and values.
 * When `skipDuplicated` is false, colliding keys are aggregated into arrays
 * so duplicate keys do not clobber earlier values.
 *
 * @param arr1 key array
 * @param arr2 value array (same index as keys)
 * @param skipDuplicated when true (default) later writes overwrite earlier ones
 * @returns object composed from key/value pairs
 */
export function zipObject<T>(
  arr1: string[],
  arr2: T[],
  skipDuplicated = true,
): Record<string, T | T[]> {
  return arr1.reduce<Record<string, T | T[]>>((res, l, i) => {
    if (skipDuplicated) {
      res[l] = arr2[i];
      return res;
    }
    if (res[l] !== undefined) {
      res[l] = Array.isArray(res[l])
        ? (res[l] as T[]).concat(arr2[i])
        : [res[l] as T].concat(arr2[i]);
      return res;
    }
    res[l] = arr2[i];
    return res;
  }, {});
}

/**
 * Recursively flatten a nested array into a single-level array.
 *
 * @param input nested array input
 * @returns flattened array
 */
export function flattenDeep<T>(input: T | T[]): T[] {
  return Array.isArray(input)
    ? input.reduce<T[]>((a, b) => a.concat(flattenDeep(b)), [])
    : [input];
}

/**
 * Return the last element of an array.
 *
 * @param input source array
 * @returns the final element, or undefined when the array is empty
 */
export function last<T>(input: T[]): T {
  return input.slice(-1)[0];
}

/**
 * Return a copy of a string array with duplicates removed.
 *
 * @param input array with possible duplicates
 * @returns array in original order without duplicates
 */
export function uniq(input: string[]): string[] {
  const set = new Set(input);
  return [...set];
}

/**
 * Safely read a dotted path from an object, returning `defaultValue` when
 * any segment is missing.
 *
 * @param obj source object
 * @param path dotted path expression (e.g. "a.b.c")
 * @param defaultValue fallback when the path does not resolve
 * @returns resolved value or the default
 */
export function get<T = unknown>(
  obj: Record<string, unknown> | null | undefined,
  path: string,
  defaultValue: T | null = null,
): T | null {
  return path
    .split('.')
    .reduce<unknown>((a, c) => {
      if (a && typeof a === 'object' && c in (a as Record<string, unknown>)) {
        const next = (a as Record<string, unknown>)[c];
        return next ?? defaultValue;
      }
      return defaultValue;
    }, obj) as T | null;
}

/**
 * Type guard for strings.
 *
 * @param input value to test
 * @returns true when the input is a string primitive
 */
export function isString(input: unknown): input is string {
  return typeof input === 'string';
}

/**
 * Encode a string or byte array as base64.
 *
 * @param message plain text or raw bytes
 * @returns base64 encoded string
 */
function base64Encode(message: string | number[]): string {
  return Buffer.from(message as string).toString(BASE64_STR);
}

/**
 * Decode a base64 message. Returns either the decoded string or the raw
 * Buffer depending on `isBytes`.
 *
 * @param base64Message base64 encoded payload
 * @param isBytes when true, return a Buffer instead of a string
 * @returns decoded string or Buffer
 */
export function base64Decode(base64Message: string, isBytes?: boolean): string | Buffer {
  const bytes = Buffer.from(base64Message, BASE64_STR);
  return Boolean(isBytes) ? bytes : bytes.toString();
}

/**
 * Raw-deflate a UTF-8 string and return the compressed bytes.
 *
 * @param message plain text
 * @returns compressed bytes as a number array
 */
function deflateString(message: string): number[] {
  const input = Buffer.from(message, 'utf8');
  return Array.from(deflateRawSync(input));
}

/**
 * Raw-inflate a base64 string that was produced by {@link deflateString}.
 *
 * @param compressedString base64-encoded raw-deflate payload
 * @returns decompressed UTF-8 string
 */
export function inflateString(compressedString: string): string {
  const inputBuffer = Buffer.from(compressedString, BASE64_STR);
  return inflateRawSync(inputBuffer).toString('utf8');
}

/**
 * Strip PEM header/footer, whitespace and newlines from a PEM payload.
 */
function _normalizeCerString(bin: string | Buffer, format: string): string {
  return bin
    .toString()
    .replace(/\n/g, '')
    .replace(/\r/g, '')
    .replace(`-----BEGIN ${format}-----`, '')
    .replace(`-----END ${format}-----`, '')
    .replace(/ /g, '')
    .replace(/\t/g, '');
}

/**
 * Normalise a PEM certificate string to its base64 body.
 *
 * @param certString PEM-encoded X.509 certificate
 * @returns certificate body without headers/whitespace
 */
function normalizeCerString(certString: string | Buffer): string {
  return _normalizeCerString(certString, 'CERTIFICATE');
}

/**
 * Normalise a PEM RSA private key string to its base64 body.
 *
 * @param pemString PEM-encoded RSA private key
 * @returns key body without headers/whitespace
 */
function normalizePemString(pemString: string | Buffer): string {
  return _normalizeCerString(pemString.toString(), 'RSA PRIVATE KEY');
}

/**
 * Reconstruct the full URL (protocol + host + path) from an Express-style
 * HTTP request.
 *
 * @param req Express-compatible request object
 * @returns absolute URL string
 */
function getFullURL(req: {
  protocol: string;
  get: (name: string) => string | undefined;
  originalUrl: string;
}): string {
  return `${req.protocol}://${req.get('host')}${req.originalUrl}`;
}

/**
 * Return `str` when it is truthy, otherwise the provided default.
 */
function parseString(str: string | undefined | null, defaultValue = ''): string {
  return str || defaultValue;
}

/**
 * Shallow-merge `obj2` on top of `obj1`, returning a new object.
 */
function applyDefault<A extends object, B extends object>(obj1: A, obj2: B): A & B {
  return Object.assign({}, obj1, obj2) as A & B;
}

/**
 * Extract the SPKI PEM public key from a base64 X.509 certificate body.
 *
 * @param x509Certificate normalised certificate body (no PEM wrappers)
 * @returns PEM-encoded public key
 */
function getPublicKeyPemFromCertificate(x509Certificate: string): string | Buffer {
  const der = Buffer.from(x509Certificate, 'base64');
  const cert = new X509Certificate(der);
  return cert.publicKey.export({ type: 'spki', format: 'pem' });
}

/**
 * Read a PEM private key, optionally decrypting it with a passphrase.
 *
 * @param keyString PEM key contents
 * @param passphrase optional passphrase protecting the key
 * @param isOutputString when true, always return a string
 * @returns PEM key as string or Buffer
 */
export function readPrivateKey(
  keyString: string | Buffer,
  passphrase: string | undefined,
  isOutputString?: boolean,
): string | Buffer {
  if (isString(passphrase)) {
    const key = createPrivateKey({ key: keyString, format: 'pem', passphrase });
    const pem = key.export({ type: 'pkcs1', format: 'pem' });
    return convertToString(pem, isOutputString);
  }
  return keyString;
}

/**
 * Coerce a value to a string when `isOutputString` is true, otherwise pass
 * it through untouched.
 */
function convertToString(input: string | Buffer, isOutputString?: boolean): string | Buffer {
  return Boolean(isOutputString) ? String(input) : input;
}

/**
 * Check that the input is an array with at least one element.
 *
 * @param a candidate value
 * @returns true when the argument is a non-empty array
 */
export function isNonEmptyArray<T>(a: unknown): a is T[] {
  return Array.isArray(a) && a.length > 0;
}

/**
 * Wrap a single value in an array, or return the array unchanged.
 * An undefined input returns an empty array.
 *
 * @param a scalar, array, or undefined
 * @returns array form of the input
 */
export function castArrayOpt<T>(a?: T | T[]): T[] {
  if (a === undefined) return [];
  return Array.isArray(a) ? a : [a];
}

/**
 * Type guard removing `null` and `undefined` from a union.
 *
 * @param value value to narrow
 * @returns true when the value is neither null nor undefined
 */
export function notEmpty<TValue>(value: TValue | null | undefined): value is TValue {
  return value !== null && value !== undefined;
}

/**
 * Escape a string for safe use inside an XPath single-quoted string literal.
 * Prevents XPath injection by splitting on single quotes and using concat().
 *
 * @param value raw string that may contain quotes
 * @returns XPath-safe string expression
 */
export function escapeXPathValue(value: string): string {
  if (!value.includes("'")) {
    return "'" + value + "'";
  }
  const parts = value.split("'").map(part => "'" + part + "'");
  return 'concat(' + parts.join(`,"'",`) + ')';
}

/**
 * Convert a string to camelCase, splitting on whitespace, `-`, `_`, `.`,
 * and inferred case boundaries.
 *
 * @param input source string
 * @returns camelCased output
 */
export function camelCase(input: string): string {
  const words = input
    .replace(/([a-z\d])([A-Z])/g, '$1\0$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1\0$2')
    .split(/[\0\s\-_\.]+/)
    .filter(w => w.length > 0);

  return words
    .map((word, i) => {
      const lower = word.toLocaleLowerCase('en-US');
      return i === 0 ? lower : lower.charAt(0).toLocaleUpperCase('en-US') + lower.slice(1);
    })
    .join('');
}

const utility = {
  isString,
  base64Encode,
  base64Decode,
  deflateString,
  inflateString,
  normalizeCerString,
  normalizePemString,
  getFullURL,
  parseString,
  applyDefault,
  getPublicKeyPemFromCertificate,
  readPrivateKey,
  convertToString,
  isNonEmptyArray,
};

export default utility;
