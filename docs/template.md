# Custom templates

Developer can design their own request and response template for log-in and log-out respectively. There are optional parameters in setting object.

```javascript
const saml = require('express-saml2');

// Load the template every time before each request/response is sent
const sp = saml.ServiceProvider({
  //...
  loginRequestTemplate: fs.readFileSync('./loginResponseTemplate.xml'),
  metadata: fs.readFileSync('./metadata_sp.xml') 
});

// or hardcoded it in memory
const sp = saml.ServiceProvider({
  //...
  loginRequestTemplate: '<saml:...>',
  metadata: fs.readFileSync('./metadata_sp.xml') 
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
  sp.sendLoginRequest(idp, 'redirect', url => {
    res.redirect(url);
  }, loginRequestTemplate => {
    // Here is the callback function for custom template
    // the input parameter is the value of loginRequestTemplate
    // The following is the input parameter of rcallback in different actions
    // sp.sendLoginRequest -> loginRequestTemplate
    // sp.sendLogoutResponse -> logoutResponseTemplate
    // idp.sendLoginResponse -> loginResponseTemplate
    // idp.sendLogoutRequest -> logoutRequestTemplate
    // replaceTagFromTemplate is a function to do dynamically substitution of tags
    return replaceTagFromTemplate(loginRequestTemplate);
  });
});
```
Developers may want to use our default tag replacement `saml.SamlLib.replaceTagsByValue` instead of writing their own `replaceTagFromTemplate`. It replaces all defined tags in the input XML string. This method is supported with version >= 1.1.6.

```javascript
const saml = require('express-saml2');
const lib = saml.SamlLib;
const requestTags = saml.Constants.tags.request;
// ...
router.get('/spinitsso-redirect', function(req, res) {
  sp.sendLoginRequest(idp, 'redirect', url => {
    // ...
    return lib.replaceTagFromTemplate(loginRequestTemplate, requestTags);
  });
});
```

The default tag list includes:
```javascript
module.exports.tags = {
  request: {
    AllowCreate: '{AllowCreate}',
    AssertionConsumerServiceURL: '{AssertionConsumerServiceURL}',
    AuthnContextClassRef: '{AuthnContextClassRef}',
    AssertionID: '{AssertionID}',
    Audience: '{Audience}',
    AuthnStatement: '{AuthnStatement}',
    AttributeStatement: '{AttributeStatement}',
    ConditionsNotBefore: '{ConditionsNotBefore}',
    ConditionsNotOnOrAfter: '{ConditionsNotOnOrAfter}',
    Destination: '{Destination}',
    EntityID: '{EntityID}',
    ID: '{ID}',
    Issuer: '{Issuer}',
    IssueInstant: '{IssueInstant}',
    InResponseTo: '{InResponseTo}',
    NameID: '{NameID}',
    NameIDFormat: '{NameIDFormat}',
    ProtocolBinding: '{ProtocolBinding}',
    SessionIndex: '{SessionIndex}',
    SubjectRecipient: '{SubjectRecipient}',
    SubjectConfirmationDataNotOnOrAfter: '{SubjectConfirmationDataNotOnOrAfter}',
    StatusCode: '{StatusCode}'
  },
  // ...
};
```
