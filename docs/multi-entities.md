# Multiple entities

For those applications with many clients, each client may have its own Identity Provider. Developers just need to configure multiple IdPs. Different configuration of SP is required for different IdP, therefore multiple SPs are allowed.

**Multiple IdPs - Single SP**

```javascript
// define SP
const sp = saml.ServiceProvider({
  metadata: fs.readFileSync('./metadata_sp.xml')
});
// define multiple IdPs
const defaultIdP = saml.IdentityProvider({
  metadata: fs.readFileSync('./metadata_idp_default.xml')
});
const oneloginIdP = saml.IdentityProvider({
  metadata: fs.readFileSync('./metadata_onelogin.xml')
});
// URL routing for SP-initiated SSO 
router.get('/spinitsso-post/:idp', (req, res) => {
  let targetIdP = undefined;
  switch(req.params.idp) {
    case 'onelogin': {
      targetIdP = oneloginIdP;
      break;
    }
    default: {
      targetIdP = idp;
      break;
    }
  }
  return sp.createLoginRequest(targetIdP, 'post', (req, res) => res.render('actions', req));
});
```

Using the same SP configuration, it can apply to different IdPs. We've played a trick here, the initiated URL for SP-inititated SSO is controlled by a parameter. When user accesses `/spinitsso-post/onelogin`, the OneLogin IdP is used. When user accesses `/spinitsso-post/default`, the default IdP is then used for authentication.

**Multiple IdPs - Mutiple SPs**

Different IdPs may have different preference, so single SP configuration may not be suitable. For example, OneLogin IdP requires a request with signature but our default IdP does not. Here we come up with another solution which is very similar to the previous one.

```javascript
// define a default SP
const defaultSP = saml.ServiceProvider({
  metadata: fs.readFileSync('./metadata_sp.xml')
});
// define SP for OneLogin with different metadta
const oneloginSP = saml.ServiceProvider({
  metadata: fs.readFileSync('./metadata_sp_for_oneLogin.xml')
});
// define a default IdP
const defaultIdP = saml.IdentityProvider({
  metadata: fs.readFileSync('./metadata_idp_default.xml')
});
// define OneLogin IdP
const oneloginIdP = saml.IdentityProvider({
  metadata: fs.readFileSync('./metadata_idp_onelogin.xml')
});
// URL routing for SP-initiated SSO 
router.get('/spinitsso-post/:idp', function(req, res) {
  let targetIdP = undefined;
  let sourceSP = undefined;
  switch(req.params.idp || '') {
    case 'onelogin': {
      targetIdP = oneloginIdP;
      sourceSP = oneloginSP;
      break;
    }
    default: {
      targetIdP = idp;
      sourceSP = defaultSP;
      break;
    }
  }
  return sourceSP.createLoginRequest(targetIdP, 'post', (req, res) => res.render('actions', request));
});
```
