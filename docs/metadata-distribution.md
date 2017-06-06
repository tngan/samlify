# Metadata distribution

?> Metadata is used to exchange information between Identity Provider and Service Provider. Simply there are two major ways to exchange Metadata.

**Release in public **

Display the Metadata in a specific URL. Everyone has the URL can watch the Metadata. Therefore, the Metadata is distributed publicly. We provide an API to do it once you've configure your SP.

```javascript
const saml = require('samlify');
const sp = saml.ServiceProvider({
  metadata: fs.readFileSync('./metadata_sp.xml')
});
router.get('/metadata', (req, res) => {
  res.header('Content-Type', 'text/xml').send(sp.getMetadata());
});
```

If you use our IdP solution, you can also release the Metadata same as above.

```javascript
const idp = saml.IdentityProvider({
  metadata: fs.readFileSync('./metadata_idp.xml')
});
router.get('/metadata', (req, res) => {
  res.header('Content-Type', 'text/xml').send(idp.getMetadata());
});
```

**Export and distribute it privately**

Some properties may not want their metadata to release publicly. If IdP or SP is configured explicitly, a helper method is provided to export the auto-generated metadata.

```javascript
// Configure the entities without metadata
const sp = saml.ServiceProvider(spSetting);
const idp = saml.IdentityProvider(idpSetting);
// Export the auto-generated Metadata to a specific file
sp.exportMetadata('./distributed_sp_md.xml');
idp.exportMetadata('./distributed_idp_md.xml');
```


