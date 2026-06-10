# OneLogin integration

::: tip
This chapter walks through a sample application that supports both IdP-initiated and SP-initiated SSO with OneLogin.
:::

Express.js is used in the example. Any other Node.js web framework (Koa, Sails.js, Kraken.js, etc.) works as well.

## 1. Create an Express application

See the official Express guide: <http://expressjs.com/starter/installing.html>.

## 2. Prepare the IdP and SP metadata

This is the metadata published by OneLogin:

```xml
<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://app.onelogin.com/saml/metadata/487043">
  <IDPSSODescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIEFzCCAv+gAwIBAgIUGn44ShzpiI8UDq2qKb7RPuULLgAwDQYJKoZIhvcNAQEFBQAwWDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCEJhc2ggTGFiMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgNzA2MDkwHhcNMTUxMDIyMDE0MTUxWhcNMjAxMDIzMDE0MTUxWjBYMQswCQYDVQQGEwJVUzERMA8GA1UECgwIQmFzaCBMYWIxFTATBgNVBAsMDE9uZUxvZ2luIElkUDEfMB0GA1UEAwwWT25lTG9naW4gQWNjb3VudCA3MDYwOTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOS0Ced6VucP8FGDzcMSwOgi1u98MtTrBOuYDDlIT7QJ2okwu1qx0D1/XUpVDZCrvblie85H/HZIDO8TgJ3roXy0VNlAwuJ95TaADinc6hZGYLAfMcz35ihg5MZIoDXxB/29GMgTrF5xozdndKJdcYf5HmyLjL2uULQ22ldXOxm9uA8K17LRnDApOIfT73EEG+Zjch9EuvUh7CqR9HrmUXLsYHcijKt7KfruA1UgKRT251i7bm5dWuj/Eq87O2qH2fTDTb8VVWro5yuQXrs3KP27IYHYukkhVBbAq8dhfpUt7Fuv/Ia0oZTvps0b6VDiB3mvYKrquQPEA61YrnVlT2MCAwEAAaOB2DCB1TAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQ0uWb6LdIG00ptY49iAP/ydNaGZDCBlQYDVR0jBIGNMIGKgBQ0uWb6LdIG00ptY49iAP/ydNaGZKFcpFowWDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCEJhc2ggTGFiMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxHzAdBgNVBAMMFk9uZUxvZ2luIEFjY291bnQgNzA2MDmCFBp+OEoc6YiPFA6tqim+0T7lCy4AMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEATa7tS0aG4o+GW0fBTKt2NboI7O0S9msDM1PRUeYV69pM0UZzDph/fymoLo31BHu/FqwVQDTOxXw+Tq536I5hRSFhcS3Z8x6xXUwSCJ8JXYw8MbTzbf3lrIUccZl19fmAklrOF9c8Z7ZSrVa2N6xgmS03xD/FcznC053bvqH8nQ4v+H39mXsAbK+sfp5hMM5zD9fd332zwFm8Zc52mp+G+bv6+WI8IKOOk/5LlA6JexUbZdF4ZqSCzzKMrnNWn/GSUdgqtSwqXa9hCY4m86e4cqEZZ8+JB5/7Nx4FPU3uSzVa7Ird4xbkxahpws42MwyWMRPg56fjVHzN1e1l00Qfbw==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://esaml2.onelogin.com/trust/saml2/http-post/sso/487043"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://esaml2.onelogin.com/trust/saml2/http-post/sso/487043"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://esaml2.onelogin.com/trust/saml2/soap/sso/487043"/>
  </IDPSSODescriptor>
  <ContactPerson contactType="technical">
    <SurName>Support</SurName>
    <EmailAddress>support@onelogin.com</EmailAddress>
  </ContactPerson>
</EntityDescriptor>
```

This is the application's SP metadata:

```xml
<EntityDescriptor
 xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
 xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
 entityID="http://localhost:3000/sso/metadata">
    <SPSSODescriptor WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
        <AssertionConsumerService isDefault="true" index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:3000/sso/acs"/>
    </SPSSODescriptor>
</EntityDescriptor>
```

Save both metadata files in the same directory as `sso.js`.

## 3. Add an SSO route

Install dependencies:

```console
$ yarn
```

Create `routes/sso.js`:

```javascript
// routes/sso.js
const saml = require('samlify');
const express = require('express');
const router = express.Router();
const ServiceProvider = saml.ServiceProvider;
const IdentityProvider = saml.IdentityProvider;

// Configure the endpoint for IdP-initiated and SP-initiated SSO.
const sp = ServiceProvider({
  metadata: fs.readFileSync('../metadata_sp.xml')
});
const idp = IdentityProvider({
  metadata: fs.readFileSync('../onelogin_metadata_487043.xml')
});

// Publish the SP metadata.
router.get('/metadata', (req, res) =>
  res.header('Content-Type', 'text/xml').send(sp.getMetadata())
);

// SP-initiated SSO entry point.
router.get('/spinitsso-redirect', (req, res) => {
  const { id, context } = sp.createLoginRequest(idp, 'redirect');
  return res.redirect(context);
});

// Assertion Consumer Service endpoint. Required for both IdP-initiated
// and SP-initiated flows.
router.post('/acs', (req, res) => {
  sp.parseLoginResponse(idp, 'post', req)
    .then(parseResult => {
      // ...
    })
    .catch(console.error);
});
```

The route above starts SP-initiated SSO via `/spinitsso-redirect` using the HTTP-Redirect binding. Users can also start from the OneLogin dashboard to trigger IdP-initiated SSO.

## 4. Mount the routes under `/sso`

```javascript
// app.js
const routes = require('./routes/index');
const sso = require('./routes/sso');
// ...
app.use('/', routes);
app.use('/sso', sso);
```

## 5. Start the server

```console
$ npm start
```

Either visit <http://localhost:3000/spinitsso-redirect>, or sign in to [OneLogin](https://esaml2.onelogin.com/login) and launch the `esaml2-example-3000` app.

Test credentials for OneLogin:

- **Account Name:** `user@esaml2.com`
- **Password:** `Tk2eQc%9`

A successful SP-initiated sign-in displays *"Validate the SAML Response successfully!"*. Alternatively, launch the `esaml2-example-3000` app from the OneLogin dashboard after signing in.
