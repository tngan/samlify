# Configuration

The simplest way to configure both SP and IdP is to import an existing metadata document.

```js
// Service provider.
const sp = saml.ServiceProvider({
  metadata: fs.readFileSync('./metadata/sp.xml')
});

// Identity provider.
const idp = saml.IdentityProvider({
  metadata: fs.readFileSync('./metadata/idp.xml')
});
```

When no metadata document is available, the entity can be configured programmatically. The library will generate the metadata from the supplied parameters.

```js
// Service provider.
const sp = saml.ServiceProvider({
  privateKey: readFileSync('./test/key/sp/privkey.pem'),
  privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  isAssertionEncrypted: false,
  encPrivateKey: readFileSync('./test/key/sp/encryptKey.pem'),
  encPrivateKeyPass: 'g7hGcRmp8PxT5QeP2q9Ehf1bWe9zTALN',
  // ...
});

// Identity provider.
const idp = saml.IdentityProvider({
  privateKey: readFileSync('./test/key/idp/privkey.pem'),
  privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  isAssertionEncrypted: false,
  encPrivateKey: readFileSync('./test/key/idp/encryptKey.pem'),
  encPrivateKeyPass: 'g7hGcRmp8PxT5QeP2q9Ehf1bWe9zTALN',
  // ...
});
```

The generated metadata can be retrieved with `getMetadata()`; see [Metadata distribution](/metadata-distribution) for details.

```js
sp.getMetadata();
idp.getMetadata();

// Or expose it publicly (Express example):
router.get('/metadata', (req, res) => {
  const metadata = sp.getMetadata();
  return res.header('Content-Type', 'text/xml').send(metadata);
});
```

## References

- [Metadata for the OASIS Security Assertion Markup Language](https://www.oasis-open.org/committees/download.php/35391/sstc-saml-metadata-errata-2.0-wd-04-diff.pdf)
- [SAML specification](http://saml.xml.org/saml-specifications)
