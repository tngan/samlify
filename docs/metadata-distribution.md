# Metadata Distribution

::: tip
Metadata is the contract used to exchange SSO configuration between identity and service providers. There are two common distribution patterns.
:::

## Publishing publicly

Expose the metadata document at a stable URL so that any party can retrieve it. samlify provides a helper that returns the current metadata for a configured entity.

```javascript
const saml = require('samlify');
const sp = saml.ServiceProvider({
  metadata: fs.readFileSync('./metadata_sp.xml')
});
router.get('/metadata', (req, res) => {
  res.header('Content-Type', 'text/xml').send(sp.getMetadata());
});
```

The same pattern applies when samlify serves as the identity provider:

```javascript
const idp = saml.IdentityProvider({
  metadata: fs.readFileSync('./metadata_idp.xml')
});
router.get('/metadata', (req, res) => {
  res.header('Content-Type', 'text/xml').send(idp.getMetadata());
});
```

## Exporting for private distribution

When an organization does not wish to publish metadata publicly, and when the IdP or SP has been configured programmatically, the generated metadata can be written to disk and shared through a private channel.

```javascript
// Configure the entities without a metadata document.
const sp = saml.ServiceProvider(spSetting);
const idp = saml.IdentityProvider(idpSetting);

// Export the auto-generated metadata to files.
sp.exportMetadata('./distributed_sp_md.xml');
idp.exportMetadata('./distributed_idp_md.xml');
```
