# SP configuration

## Required parameters

::: tip
The service provider can be constructed either from an existing metadata document plus optional parameters, or entirely from a configuration object.
:::

### From a metadata document

- **`metadata: string`** — SP-issued metadata describing the structure and scope of the entity. It serves as the contract between the SP and IdP for SSO/SLO.

```js
const sp = new ServiceProvider({
  // Required.
  metadata: readFileSync('./test/misc/spmeta.xml'),
  // Optional.
  privateKey: readFileSync('./test/key/sp/privkey.pem'),
  privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  encPrivateKey: readFileSync('./test/key/sp/encryptKey.pem'),
  encPrivateKeyPass: 'g7hGcRmp8PxT5QeP2q9Ehf1bWe9zTALN'
});
```

### From a configuration object

- **`entityID: string`** — Entity identifier. Used to identify the SP and to match values in each SAML request or response.

- **`authnRequestsSigned: boolean`** *(optional)* — Whether the SP signs its AuthnRequest. Maps to `AuthnRequestsSigned` in the SP metadata. Defaults to `false`.

- **`wantAssertionsSigned: boolean`** *(optional)* — Whether the SP requires signed assertions. Maps to `WantAssertionsSigned` in the SP metadata. Defaults to `false`.

- **`wantMessageSigned: boolean`** *(optional)* — Whether the SP requires signed SAML messages. Defaults to `false`.

- **`signingCert: string`** *(optional)* — The certificate used for signing when the SP is constructed without metadata.

- **`encryptCert: string`** *(optional)* — The certificate used for encryption when the SP is constructed without metadata.

- **`elementsOrder: string[]`** *(optional)* — DOM element ordering for the generated metadata. Defaults to `['KeyDescriptor', 'NameIDFormat', 'SingleLogoutService', 'AssertionConsumerService']`. See [#89](https://github.com/tngan/samlify/issues/89).

- **`nameIDFormat: NameIDFormat[]`** *(optional)* — NameID formats supported when the SP is constructed without metadata. When multiple values are specified, the first entry is used in outbound requests.

- **`singleLogoutService: Service[]`** *(optional)* — Single Logout endpoints when the SP is constructed without metadata.

- **`assertionConsumerService: Service[]`** *(optional)* — Assertion Consumer Service endpoints when the SP is constructed without metadata. These are the endpoints to which the IdP posts SAML responses.

- **`signatureConfig: SignatureConfig`** *(optional)* — Signature placement and layout options. See [Signed SAML Response](/signed-saml-response).

```js
const sp = new ServiceProvider({
  // Required.
  entityID: 'http://hello-saml-sp.com/metadata',
  // Optional parameters listed below.
});
```

## Optional parameters

- **`allowCreate: boolean`** — Whether the IdP may create a new identifier for the principal while fulfilling the request. Defaults to `false`.

- **`loginRequestTemplate: { context: string, attributes: Attributes }`** — Custom login request template, reusable from the callback function for runtime interpolation. See [Templates](/template).

- **`wantLogoutRequestSigned: boolean`** — Whether the SP requires the IdP's logout request to be signed.

- **`relayState: string`** — RelayState for outgoing requests.

  ::: warning Deprecated
  Entity-level RelayState is unsafe under concurrent requests because RelayState is request-scoped per [`saml-bindings §3.4.3 / §3.5.3`](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf). Pass it via the per-request options bag instead:

  ```javascript
  sp.createLoginRequest(idp, 'redirect', { relayState: '/deep/link' });
  idp.createLogoutRequest(sp, 'redirect', user, { relayState: '/return' });
  idp.createLogoutResponse(sp, requestInfo, 'redirect', { relayState: '/return' });
  idp.createLoginResponse(sp, requestInfo, 'redirect', user, { relayState: '/deep/link' });
  ```

  This option will be removed in v3.
  :::

- **`generateID: () => string`** — A function that generates the root-element identifier of each SAML document. Defaults to `_${UUID_V4}`.

- **`clockDrifts: [number, number]`** — Tolerance for clock drift on the SAML validity window, in milliseconds. The first element applies to `notBefore`; the second applies to `notOnOrAfter`. Both default to `0`. Either value may be negative or positive.

  For example, `[-5000, 3000]` extends the valid window by 5 seconds before `notBefore` and 3 seconds after `notOnOrAfter`:

  ```console
  # Tolerated timeline
  notBefore - 5s >>>>>>> notBefore >>>>>>> notOnOrAfter ---- notOnOrAfter + 3s

  # Effective valid range
  notBefore - 5s >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> notOnOrAfter + 3s
  ```

  With the default `[0, 0]`, the valid range is exactly the declared window:

  ```console
  # Valid range
  notBefore >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> notOnOrAfter
  ```

  ::: tip
  The check is skipped entirely when both `notBefore` and `notOnOrAfter` are absent.
  :::

  See [SAML Core §2.5.1.2](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf) for details.
