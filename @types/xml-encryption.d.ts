declare module "xml-encryption" {
  export interface EncryptOptions {
    rsa_pub: string | Buffer;
    pem: string | Buffer;
    encryptionAlgorithm: string;
    keyEncryptionAlgorithm: string;
    input_encoding?: string;
  }
  export interface DecryptOptions {
    key: string | Buffer;
  }
  export interface Callback {
    (err:Error, result): void;
  }
  export function encrypt(content: string, options: EncryptOptions, callback: Callback): string;
  export function encryptKeyInfo(symmetricKey: string, options: EncryptOptions, callback: Callback): string;
  export function decrypt(xml: string | Document, options: DecryptOptions, callback: Callback): string;
  export function decryptKeyInfo(doc: string | Document, options: DecryptOptions): string;
	const _default: { decrypt, encrypt, decryptKeyInfo, encryptKeyInfo };
  export default _default;
}
