# SAML Request

When we apply SP-initiated SSO, our Service Provider have to send a SAML Request to Identity Provider.

SAML Request is in XML format, asking if identity provider can authenticate this user. The following is a sample request without signature.

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

Different bindings can be used to send this request, we support Redirect-Binding and Post-Binding. 

**Redirect-Binding**

It means that the XML is embedded as an URL parameter and redirect to the SSO endpoint of IdP. Because of different length limitation in different browsers, it's required to deflate Request.

```javascript
const saml = require('express-saml2');
const sp = saml.ServiceProvider({
  metadata: fs.readFileSync('./metadata_sp.xml')
});
const idp = saml.IdentityProvider({
  metadata: fs.readFileSync('./metadata_idp.xml')
});
```

The SSO endpoint of IdP is specified in their metadata. For example:

```xml
<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.org/sso/SingleSignOnService"/>
<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.org/sso/SingleSignOnService"/>
```

There may be more than one SSO endpoint, to support different bindings. By using our entity level API, you can just write your initiation point in any route you want as follow:

```javascript
router.get('/spinitsso-redirect', (req, res) => {
	res.redirect(sp.createLoginRequest(idp, 'redirect'));
});
```
By applying the preference of SP and IdP, `sp.createLoginRequest`returns an URL which is in following general format:

https://idp.example.org/sso/SingleSignOnService?SAMLRequest=www&SigAlg=xxx&RelayState=yyy&Signature=zzz

The parameters **SigAlg** and **Signature** is optional in case IdP requests your SAML Request should be signed. **relayState** is also optional if the application needs a deep link to access.

All the corresponding values are URL-encoded. **Signature** is already Base64-encoded and the deflated **SAMLRequest** should be Base64-encoded.

**Post-Binding**

The Request XML is sent via a form post instead of embedding in URL parameters. By using the same method as in Redirect-Binding:

```javascript
router.get('/spinitsso-redirect', (req, res) => {
  res.render('actions', sp.createLoginRequest(idp, 'post'));
});
```

You can simply change the second argument from 'redirect' to 'post'. This time the callback function returns an object instead of a string. It is then fed to a generic form post template as follow:

```html
<form id="saml-form" method="post" action="{{entityEndpoint}}" autocomplete="off">
    <input type="hidden" name="{{type}}" value="{{context}}" />
    {{#if relayState}}
        <input type="hidden" name="RelayState" value="{{relayState}}" />
    {{/if}}
</form>
<script type="text/javascript">
    // Automatic form submission
    (function(){
        document.forms[0].submit();
    })();
</script>
```

Handlebar view engine is used in this example, you may choose your own and configure in your `app.js`.

```javascript
app.engine('handlebars', exphbs({defaultLayout: 'main'}));
app.set('view engine', 'handlebars');
```

After those values are filled into the tags, the form will be automatically submit.

?> **What's the next ?** <br/><br/>
Identity Provider parses SP's request, then a SAML Response is sent back to SP. The response includes the authentication result. SP can then take action to create session for authenticated user if the result is successful.
