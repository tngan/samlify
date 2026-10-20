# Encrypted Assertion

The SAML specification leaves encryption up to the deployment. When the assertion carries sensitive information, the identity provider may encrypt it. Enable encryption on the IdP as follows:

```javascript
const idp = IdentityProvider({
  isAssertionEncrypted: true,
  metadata: fs.readFileSync('./metadata_idp.xml'),
  dataEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
  keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
});
```

As with request signing, the SP configuration supplies `privateKey` and `privateKeyPass`. **Important:** when samlify is used as the identity provider, do not reuse the same key pair for both signing and encryption.

The SP metadata must include an encryption certificate so that the IdP can encrypt the assertion. Certificates in metadata must be plain base64 (whitespace and line breaks are allowed); metadata with any other content in `X509Certificate` is rejected with `ERR_INVALID_CERTIFICATE`, because the certificate is copied into the encrypted assertion:

```xml
<KeyDescriptor use="encryption">
    <KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
            <X509Certificate>MIID6TCCAtGg...</X509Certificate>
        </X509Data>
    </KeyInfo>
</KeyDescriptor>
```

Parsing and verifying the encrypted response uses the same `sp.parseLoginResponse` helper — decryption is transparent to the caller:

```javascript
router.post('/acs', (req, res) => {
  sp.parseLoginResponse(idp, 'post', req)
    .then(parseResult => {
      // Use parseResult to run your business logic.
    })
    .catch(console.error);
});
```

Supported algorithms:

**Data encryption algorithms**

- `http://www.w3.org/2001/04/xmlenc#tripledes-cbc` *(insecure)*
- `http://www.w3.org/2001/04/xmlenc#aes128-cbc`
- `http://www.w3.org/2001/04/xmlenc#aes256-cbc`
- `http://www.w3.org/2009/xmlenc11#aes128-gcm`

**Key encryption algorithms**

- `http://www.w3.org/2001/04/xmlenc#rsa-1_5` *(insecure)*
- `http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p`

The SP refuses to decrypt an assertion that uses an insecure algorithm and rejects it with `ERR_INSECURE_ENCRYPTION_ALGORITHM`. The algorithms are named in the incoming XML, so the SP cannot otherwise stop an attacker from choosing them. RSA-1.5 key transport is open to padding-oracle attacks (see [XML Encryption 1.1 §5.4.1](https://www.w3.org/TR/xmlenc-core1/#rsav15note)), and TripleDES is deprecated by NIST. If an IdP you cannot reconfigure still uses them, set `allowInsecureDecryptionAlgorithms: true` on the SP. Even then, Node.js refuses RSA-1.5 private decryption on OpenSSL builds without implicit rejection (CVE-2023-46809), so RSA-1.5 may fail regardless of this setting.

XML encryption is provided by [auth0/node-xml-encryption](https://github.com/auth0/node-xml-encryption).
