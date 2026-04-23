# Attributes in the response

::: tip
Starting from v2, a shortcut is provided for declaring the `<AttributeStatement>` section instead of hand-coding attribute markup inside the template string.
:::

```javascript
const idp = require('samlify').IdentityProvider({
  // ...
  loginResponseTemplate: {
    context: '<samlp:Response ...>',
    attributes: [
      { name: 'mail', valueTag: 'user.email', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', valueXsiType: 'xs:string' },
      { name: 'name', valueTag: 'user.name',  nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', valueXsiType: 'xs:string' }
    ]
  }
});
```

The library renders the attributes into the template as:

```xml
<saml:AttributeStatement>
  <saml:Attribute
    Name="mail"
    NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
    <saml:AttributeValue xsi:type="xs:string">
      {attrUserEmail}
    </saml:AttributeValue>
  </saml:Attribute>
  <saml:Attribute
    Name="name"
    NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
    <saml:AttributeValue xsi:type="xs:string">
      {attrUserName}
    </saml:AttributeValue>
  </saml:Attribute>
</saml:AttributeStatement>
```

The placeholder name is generated automatically with the prefix `attr` and the camel-cased `valueTag` from the configuration.

# Custom templates

The login and logout request/response templates can be customised via configuration. Each entity factory accepts optional template parameters.

```javascript
const saml = require('samlify');

// The template is loaded once and reused for every outbound request.
const sp = saml.ServiceProvider({
  // ...
  loginRequestTemplate: {
    context: readFileSync('./loginRequestTemplate.xml')
  }
});
```

In SP configuration, `loginRequestTemplate` is the AuthnRequest template. It can be provided as either a file path or an XML string. The built-in default is:

```xml
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{ID}"
    Version="2.0"
    IssueInstant="{IssueInstant}"
    Destination="{Destination}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    AssertionConsumerServiceURL="{AssertionConsumerServiceURL}">

    <saml:Issuer>{Issuer}</saml:Issuer>
    <samlp:NameIDPolicy
        Format="{NameIDFormat}"
        AllowCreate="{AllowCreate}"/>

</samlp:AuthnRequest>
```

When supplying a custom template, pass a callback that performs tag replacement at runtime. `replaceTagFromTemplate` below is illustrative — the actual function name is up to the caller.

```javascript
router.get('/spinitsso-redirect', (req, res) => {
  const { id, context } = sp.createLoginRequest(idp, 'redirect', loginRequestTemplate => {
    // Callback for custom template substitution.
    // The input is the value of `loginRequestTemplate` for the current action.
    //
    //   sp.createLoginRequest    -> loginRequestTemplate
    //   sp.createLogoutResponse  -> logoutResponseTemplate
    //   idp.createLoginResponse  -> loginResponseTemplate
    //   idp.createLogoutRequest  -> logoutRequestTemplate
    //
    // `replaceTagFromTemplate` should perform the actual substitution.
    return replaceTagFromTemplate(loginRequestTemplate);
  });

  return res.redirect(context);
});
```

::: warning
The callback must return an object with `id` (the SAML message ID) and `context` (the resulting XML string).
:::
