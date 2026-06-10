# Multiple Entities

An application with many clients may need to support multiple identity providers. Different IdPs often require different SP configurations, so multiple SP instances may also be needed.

## Multiple IdPs, single SP

```javascript
// Define the SP.
const sp = saml.ServiceProvider({
  metadata: fs.readFileSync('./metadata_sp.xml')
});

// Define multiple IdPs.
const defaultIdP = saml.IdentityProvider({
  metadata: fs.readFileSync('./metadata_idp_default.xml')
});
const oneloginIdP = saml.IdentityProvider({
  metadata: fs.readFileSync('./metadata_onelogin.xml')
});

// SP-initiated SSO route, parameterised by IdP name.
router.get('/spinitsso-post/:idp', (req, res) => {
  let targetIdP;
  switch (req.params.idp) {
    case 'onelogin':
      targetIdP = oneloginIdP;
      break;
    default:
      targetIdP = defaultIdP;
      break;
  }
  return sp.createLoginRequest(targetIdP, 'post', (req, res) => res.render('actions', req));
});
```

With a single SP configuration, the request can be routed to different IdPs based on a path parameter. `/spinitsso-post/onelogin` authenticates against OneLogin; `/spinitsso-post/default` (or any unknown value) falls back to the default IdP.

## Multiple IdPs, multiple SPs

Different IdPs may require different SP configurations — for example, OneLogin may require signed requests while the default IdP does not. The pattern below uses one SP instance per IdP.

```javascript
// Define the default SP.
const defaultSP = saml.ServiceProvider({
  metadata: fs.readFileSync('./metadata_sp.xml')
});

// Define an SP specifically configured for OneLogin.
const oneloginSP = saml.ServiceProvider({
  metadata: fs.readFileSync('./metadata_sp_for_oneLogin.xml')
});

// Define the default IdP.
const defaultIdP = saml.IdentityProvider({
  metadata: fs.readFileSync('./metadata_idp_default.xml')
});

// Define the OneLogin IdP.
const oneloginIdP = saml.IdentityProvider({
  metadata: fs.readFileSync('./metadata_idp_onelogin.xml')
});

// SP-initiated SSO route, parameterised by IdP name.
router.get('/spinitsso-post/:idp', (req, res) => {
  let targetIdP;
  let sourceSP;
  switch (req.params.idp || '') {
    case 'onelogin':
      targetIdP = oneloginIdP;
      sourceSP = oneloginSP;
      break;
    default:
      targetIdP = defaultIdP;
      sourceSP = defaultSP;
      break;
  }
  return sourceSP.createLoginRequest(targetIdP, 'post', (req, res) => res.render('actions', req));
});
```
