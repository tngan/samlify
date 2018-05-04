# Attributes in response

?> **Starting from v2, we provide a shortcut for user to construct the attributes section efficiently instead of hard code the attribute information in template string.**

```javascript
const idp = require('samlify').IdentityProvider({
  // ...
  loginResponseTemplate: {
    context: '<samlp:Response ...'>,
    attributes: [
      { name: "mail", valueTag: "user.email", nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", valueXsiType: "xs:string" },
      { name: "name", valueTag: "user.name", nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", valueXsiType: "xs:string" }
    ]
  }
});
```

then the attributes part will be included in the template string:

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

the tag name is auto-generated with prefix `attr` and the suffix is formatted as camel case of `valueTag` specified in the config.

# Custom templates

Developer can design their own request and response template for log-in and log-out respectively. There are optional parameters in setting object.

```javascript
const saml = require('samlify');

// load the template every time before each request/response is sent
const sp = saml.ServiceProvider({
  //...
  loginRequestTemplate: {
    context: readFileSync('./loginResponseTemplate.xml'),
  }
});
```

In SP configuration, `loginRequestTemplate` is the template of SAML Request, it can be either file name or XML string. This is the default template we've used in our module.

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

When you apply your own template, remember to do custom tag replacement when you send out the request. `replaceTagFromTemplate` is just the name here to illustrate but it's not fixed.

```javascript
router.get('/spinitsso-redirect', (req, res) => {
  
  const { id, context } = sp.createLoginRequest(idp, 'redirect', loginRequestTemplate => {
    // Here is the callback function for custom template
    // the input parameter is the value of loginRequestTemplate
    // The following is the input parameter of rcallback in different actions
    // sp.createLoginRequest -> loginRequestTemplate
    // sp.createLogoutResponse -> logoutResponseTemplate
    // idp.createLoginResponse -> loginResponseTemplate
    // idp.createLogoutRequest -> logoutRequestTemplate
    // replaceTagFromTemplate is a function to do dynamically substitution of tags
    return replaceTagFromTemplate(loginRequestTemplate);
  });

  return res.redirect(context);
  
});
```

!> `replaceTagFromTemplate` must return the object containing `id` (response id) and `context` (string)
