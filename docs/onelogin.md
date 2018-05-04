# Work with OneLogin

?> In this chapter, we will make an sample application that implements IdP-initiated and SP-initiated SSO.

Express.js is our default web framework in development. In fact, you can use other web framworks (e.g. koa, Sails.js, Kraken.js ... etc) if you don't care the prefix of module is`express-`.

**1. Generate your express application**

See the official documentation [here](http://expressjs.com/starter/installing.html)

**2. Prepare the metadata from OneLogin and the self one**

This is the metadata published by OneLogin
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
This is our application metadata:
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
The above two metadata files are saved in the same directory as `sso.js`.

**3. Add a route for SSO implementation**

Make sure all dependencies are installed first:
```console
$ yarn
```

Add a file `sso.js` under `/routes` folder
```javascript
// This is /routes/sso.js
const saml = require('samlify');
const express = require('express');
const router = express.Router();
const ServiceProvider = saml.ServiceProvider;
const IdentityProvider = saml.IdentityProvider;

// Configure your endpoint for IdP-initiated / SP-initiated SSO
const sp = ServiceProvider({
  metadata: fs.readFileSync('../metadata_sp.xml')
});
const idp = IdentityProvider({
  metadata: fs.readFileSync('../onelogin_metadata_487043.xml')
});

// Release the metadata publicly
router.get('/metadata', (req, res) => res.header('Content-Type','text/xml').send(sp.getMetadata()));

// Access URL for implementing SP-init SSO
router.get('/spinitsso-redirect', (req, res) => {
	const { id, context } = sp.createLoginRequest(idp, 'redirect');
	return res.redirect(context);
});

// If your application only supports IdP-initiated SSO, just make this route is enough
// This is the assertion service url where SAML Response is sent to
router.post('/acs', (req, res) => {
	sp.parseLoginResponse(idp, 'post', req)
  .then(parseResult => {
    // ...
	})
  .catch(console.error);
});
```
By applying the above defined route,
users access **/spinitsso-redirect** to start SSO in SP side. The initiation uses Redirect-binding. Users can also login OneLogin first and start SSO in IdP side.

**4. Modify the app.js to include the path `/sso/*`**

```javascript
// This is app.js
// ...
const routes = require('./routes/index');
const sso = require('./routes/sso');
// ...
app.use('/', routes);
app.use('/sso', sso);
// ...
```

**5. Start the server**
```console
$ npm start
```
and also access http://localhost:3000/spinitsso-redirect or login [OneLogin](https://esaml2.onelogin.com/login) first and click the app `esaml2-example-3000`.

The credential for OneLogin testing is:

Account Name: **user@esaml2.com**<br/>
Password: **Tk2eQc%9**

You will see the message `Validate the SAML Response successfully !` when you are successfully log-in OneLogin app through SP-initiated SSO. 

OR

You click the app icon of `esaml2-example-3000` after you have logged into OneLogin.

