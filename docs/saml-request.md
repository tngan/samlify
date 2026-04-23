# SAML Request

Under SP-initiated SSO, the service provider sends a SAML request to the identity provider.

A SAML request is an XML document that asks the IdP to authenticate a user. Below is an example AuthnRequest without a signature:

```xml
<samlp:AuthnRequest
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="_809707f0030a5d00620c9d9df97f627afe9dcc24"
        Version="2.0" ProviderName="SP test"
        IssueInstant="2014-07-16T23:52:45Z"
        Destination="http://idp.example.com/SSOService.php"
        ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        AssertionConsumerServiceURL="https://sp.example.org/sp/sso">
    <saml:Issuer>https://sp.example.org/metadata</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
    <samlp:RequestedAuthnContext Comparison="exact">
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>
```

Two bindings are supported for the outbound request: HTTP-Redirect and HTTP-POST.

## HTTP-Redirect binding

The XML is encoded into a query parameter that redirects the user to the IdP's SSO endpoint. Because browsers impose varying URL length limits, the request must be deflated before encoding.

```javascript
const saml = require('samlify');
const sp = saml.ServiceProvider({
  metadata: fs.readFileSync('./metadata_sp.xml')
});
const idp = saml.IdentityProvider({
  metadata: fs.readFileSync('./metadata_idp.xml')
});
```

The IdP's SSO endpoint is declared in its metadata, for example:

```xml
<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.org/sso/SingleSignOnService"/>
<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.org/sso/SingleSignOnService"/>
```

An IdP may declare multiple endpoints to support different bindings. Using the entity-level API, the SP's initiation route can be implemented as follows:

```javascript
router.get('/spinitsso-redirect', (req, res) => {
  const { id, context } = sp.createLoginRequest(idp, 'redirect');
  return res.redirect(context);
});
```

`sp.createLoginRequest` resolves the SP and IdP preferences and returns a URL of the following shape:

```
https://idp.example.org/sso/SingleSignOnService?SAMLRequest=www&SigAlg=xxx&RelayState=yyy&Signature=zzz
```

The `SigAlg` and `Signature` parameters are included only when the IdP requires a signed request. `RelayState` is optional and is typically used to preserve a deep link across the authentication round-trip.

All parameter values are URL-encoded. `Signature` is base64-encoded, and the deflated `SAMLRequest` is also base64-encoded.

## HTTP-POST binding

The request XML is delivered via an auto-submitting HTML form instead of URL parameters. The same helper is used, with `'post'` as the binding:

```javascript
router.get('/spinitsso-redirect', (req, res) => {
  res.render('actions', sp.createLoginRequest(idp, 'post'));
});
```

The callback returns an object that can be rendered with a generic form-post template:

```html
<form id="saml-form" method="post" action="{{entityEndpoint}}" autocomplete="off">
    <input type="hidden" name="{{type}}" value="{{context}}" />
    {{#if relayState}}
        <input type="hidden" name="RelayState" value="{{relayState}}" />
    {{/if}}
</form>
<script type="text/javascript">
    // Auto-submit the form.
    (function () {
        document.forms[0].submit();
    })();
</script>
```

This example uses the Handlebars view engine. Configure your preferred engine in `app.js`:

```javascript
app.engine('handlebars', exphbs({ defaultLayout: 'main' }));
app.set('view engine', 'handlebars');
```

Once the template is rendered with the supplied values, the form auto-submits to the IdP.

::: tip What happens next?
The IdP parses the SP's request and returns a SAML response containing the authentication result. On success, the SP creates a session for the authenticated user.
:::
