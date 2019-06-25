# Configuration

The easiest way to get SP and iDP ready is to import the metadata file directly. 

```js
// service provider
const sp = saml.ServiceProvider({
  metadata: fs.readFileSync('./metadata/sp.xml')
});

// identity provider
const idp = saml.IdentityProvider({
  metadata: fs.readFileSync('./metadata/idp.xml')
});
```

Without importing a defined metadata, we provide an advanced way to configure the entities. The metadata can be created according to the parameters later on.

```js
// service provider
const sp = saml.ServiceProvider({
  privateKey: readFileSync('./test/key/sp/privkey.pem'),
  privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  isAssertionEncrypted: false,
  encPrivateKey: readFileSync('./test/key/sp/encryptKey.pem'),
  encPrivateKeyPass: 'g7hGcRmp8PxT5QeP2q9Ehf1bWe9zTALN',
  // ....
});

// identity provider
const idp = saml.ServiceProvider({
  privateKey: readFileSync('./test/key/idp/privkey.pem'),
  privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  isAssertionEncrypted: false,
  encPrivateKey: readFileSync('./test/key/idp/encryptKey.pem'),
  encPrivateKeyPass: 'g7hGcRmp8PxT5QeP2q9Ehf1bWe9zTALN',
  // ....
});
```

We will also generate the metadata for you if you use this advanced method to create your entity. See more [here](/metadata-distribution).

```js
sp.getMetadata();
idp.getMetadata();

// or expose it to public (e.g. express.js)
router.get('/metadata', (req, res) => {
  const metadata = sp.getMetadata();
  return res.header('Content-Type','text/xml').send(metadata);
});
```

## References

+ [Metadata for the OASIS Security Assertion Markup Language](https://www.oasis-open.org/committees/download.php/35391/sstc-saml-metadata-errata-2.0-wd-04-diff.pdf)
+ [SAML specification](http://saml.xml.org/saml-specifications)
