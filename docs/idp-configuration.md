# IdP configuration

samlify can be used as an identity provider for testing or production, and it can also be integrated with an existing IdP deployment.

## Required parameters

::: tip
The identity provider can be constructed either from an existing metadata document plus optional parameters, or entirely from a configuration object.
:::

### From a metadata document

- **`metadata: string`** — IdP-issued metadata describing the structure and scope of the entity. It serves as the contract between the SP and IdP for SSO/SLO.

```js
const idp = new IdentityProvider({
  // Required.
  metadata: readFileSync('./test/misc/idpmeta.xml'),
  // Optional.
  privateKey: readFileSync('./test/key/idp/privkey.pem'),
  privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  encPrivateKey: readFileSync('./test/key/idp/encryptKey.pem'),
  encPrivateKeyPass: 'g7hGcRmp8PxT5QeP2q9Ehf1bWe9zTALN',
  isAssertionEncrypted: true,
});
```

### From a configuration object

- **`entityID: string`** — Entity identifier. Used to identify the IdP and to match values in each SAML request or response.

- **`signingCert: string`** *(optional)* — The certificate used for signing when the IdP is constructed without metadata.

- **`encryptCert: string`** *(optional)* — The certificate used for encryption when the IdP is constructed without metadata.

- **`singleSignOnService: SignOnService[]`** *(optional)* — Single Sign-On endpoints when the IdP is constructed without metadata.

- **`singleLogoutService: SignLogoutService[]`** *(optional)* — Single Logout endpoints when the IdP is constructed without metadata.

- **`nameIDFormat: NameIDFormat[]`** *(optional)* — NameID formats supported when the IdP is constructed without metadata.

```js
const idp = new IdentityProvider({
  // Required.
  entityID: 'http://hello-saml-idp.com/metadata',
  // Optional parameters listed below.
});
```

## Optional parameters

- **`wantAuthnRequestsSigned: boolean`** — Whether the IdP requires signed AuthnRequest messages from the SP. Maps to `WantAuthnRequestsSigned` in the IdP metadata. Defaults to `false`.

- **`tagPrefix: { [key: TagPrefixKey]: string }`** — XML tag prefix overrides. `TagPrefixKey` currently supports `encryptedAssertion` only. See [#220](https://github.com/tngan/samlify/issues/220).

- **`loginResponseTemplate: { context: string, attributes: Attributes, additionalTemplates: LoginResponseAdditionalTemplates }`** — Custom login response template, reusable from the callback function for runtime interpolation. See [Templates](/template).

- **`wantLogoutResponseSigned: boolean`** — Whether the IdP requires the SP's logout response to be signed.

- **`messageSigningOrder: SigningOrder`** — Message signing order. Either `sign-then-encrypt` (default) or `encrypt-then-sign`.

- **`relayState: string`** — RelayState for outgoing requests.

  ::: warning Deprecated
  Entity-level RelayState is unsafe under concurrent requests because RelayState is request-scoped per [`saml-bindings §3.4.3 / §3.5.3`](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf). Pass it via the per-request options bag instead — see the [SP configuration page](/sp-configuration) for examples. This option will be removed in v3.
  :::

- **`isAssertionEncrypted: boolean`** — Whether the IdP encrypts the assertion in the response.

  ::: warning Deprecation
  This option will be removed in a future release. samlify will detect encryption automatically.
  :::

- **`requestSignatureAlgorithm: SigningAlgorithm`** — Signature algorithm used for requests. Defaults to `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`. Also supported: `http://www.w3.org/2000/09/xmldsig#rsa-sha1` (not recommended) and `http://www.w3.org/2001/04/xmldsig-more#rsa-sha512`.

- **`dataEncryptionAlgorithm: EncryptionAlgorithm`** — Data encryption algorithm used in responses. Defaults to `http://www.w3.org/2001/04/xmlenc#aes256-cbc`. Also supported: `http://www.w3.org/2001/04/xmlenc#tripledes-cbc` (3DES), `http://www.w3.org/2001/04/xmlenc#aes128-cbc` (AES-128 CBC), and `http://www.w3.org/2009/xmlenc11#aes128-gcm` (AES-128 GCM).

- **`keyEncryptionAlgorithm: KeyEncryptionAlgorithm`** — Key encryption algorithm. Defaults to `http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p`. Also supported: `http://www.w3.org/2001/04/xmlenc#rsa-1_5`.

- **`generateID: () => string`** — A function that generates the root-element identifier of each SAML document. Defaults to `_${UUID_V4}`.
