# express-saml2

[![Join the chat at https://gitter.im/tngan/express-saml2](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/tngan/express-saml2?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

High-level API for Single Sign On (SAML 2.0)

##Description

This module provides high-level API for scalable Single Sign On (SSO) implementation. Developers can easily configure the Service Providers and Identity Providers by importing the corresponding metadata. SAML2.0 provides a standard guide but leaves a lot of options, so we provide a simple interface that's highly configurable.

##Glossary

Metadata: A public XML document specifies the entity's preference<br/>
Identity Provider: An entity authenticates the users<br/>
Service Provider: An entity provides services/resources

##Get Started

```bash
$ git clone https://github.com/tngan/express-saml2.git
```

##Branches

Currently we are working on v1.1, it will be noticed if we are ready to release the alpha version. In terms of long term development and integration, for those who love coding with ES6, we are happy to announce that we will embrace ES6 later on, and compile with [Babel](https://babeljs.io/).

##API Reference
```javascript
var saml = require('express-saml2');
```
###Entity-Level API
This type of API defines the actions taken by the entity, is designed to be called directly in the routing files.

####Entity
The following methods can be used in `IdentityProvider` and `ServiceProvider`:
```
methods:
	+ getEntityID()
        Get the entity ID specifies in metadata<br/>
	+ getEntitySetting()
        Get the entity Setting
	+ parseMetadata()
        Get the essential elements from metadata
	+ getMetadata()
        Get the metadata in XML format
	+ exportMetadata(exportFile)
        parameter:
        | exportFile <string> - file path (e.g. ./path/mymetadata.xml)
        Export the metadata to a file
	+ entityMeta
        Get the Metadata object
```

####IdentityProvider
#####Construct a new Identity Provider
```
methods:
	+ saml.IdentityProvider(setting,metadata)
		Construct it by both metadata and setting
	+ saml.IdentityProvider(metadata)
		Construct it by importing metadata, use unless you confirm that the idp follows our default setting
	+ saml.IdentityProvider(setting)
		(Advanced) Construct it by custom setting, a new metadata will be also generated

parameters:

  + metadata <string> - path of the metadata (e.g. ./path/mymetadata.xml)
  + setting <object> - declares the perference of identity provider

  symbol representation
    o: optional
    m: must set if metadata is not imported

  {
    requestSignatureAlgorithm <string|o>  Default is 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
    loginResponseTemplate <string|o>      Login response template (#1)
    logoutRequestTemplate <string|o>      Logout request template (#1)
    generateID <function|o>               Function to generate the ID of request/response
    entityID <string>                     Define the entity ID, a.k.a issuer
    privateKeyFile <string|o>             File path of .pem file
    privateKeyFilePass <string|o>         Set if your .pem file has protected passpharse (recommend)
    signingCertFile <string|m>            File path of .cer file which is your X.509 certificate (#2)
    nameIDFormat <[string]|o>             Define the support name ID format
    singleSignOnService <[object]|m>      Define binding and location of each single sign on service
    singleLogoutService <[object]|o>      Define binding and location of each single logout service (#3)
    wantAuthnRequestsSigned <boolean|o>   Define whether login request need signature (Default is false) (#4)
    wantLogoutResponseSigned <boolean|o>  Define whether logout response need signature (Default is false) (#5)
  }

remarks:

  #1: Need to set up another callback function in order to dynamically replace the tag in template
  #2: We recommend to have signature so this field should be specified when metadata is not imported
  #3: Optional depends on whether you provide logout service in your user case
  #4: Service Provider signs login request if set to true
  #5: Service Provider signs logout response if set to true
```
#####Example
```javascript
// Sample of IDP setting used to construct an identity provider
var idpSetting = {
    entityID:'https://idp.example.org/metadata',
    nameIDFormat:['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
    privateKeyFile: './privateKey.pem',
    privateKeyFilePass: 'myPassword',
    signingCertFile: './certificate.cer',
    singleSignOnService:[{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        Location: 'https://idp.example.org/sso/SingleSignOnService'
    },{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        Location: 'https://idp.example.org/sso/SingleSignOnService'
    }],
    singleLogoutService:[{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        Location: 'https://idp.example.org/sso/SingleLogoutService'
    },{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        Location: 'https://idp.example.org/sso/SingleSignOnService'
    }]
};

// Example 1: Construct Identity Provider manually
var idp = saml.IdentityProvider(idpSetting);

// Example 2: Construct Identity Provider with metadata and without signing key
var idp = saml.IdentityProvider('./metadata_idp.xml');

//  Example 3: Construct Identity Provider with metadata and include signing key
var idp = saml.IdentityProvider({
    privateKeyFile: './privateKey.pem',
    privateKeyFilePass: 'myPassword'
},'./metadata_idp.xml');
```
#####Actions taken by Identity Provider
```
methods:

	+ idp.sendLoginResponse(sp,requestInfo,binding,user,callback,rcallback)

        parameters:
        | sp <ServiceProvider>   Declare the target entity
		| requestInfo <object>   Callback parameter from parseLoginRequest (set null when idp-initiated)
        | binding <string>       Define the binding used to send login response, only support 'post'
        | user <object>          User information in your session (e.g. req.user)
        | callback <function>    Function with parameters rendered in a form post
        | rcallback <function|o> Function with loginResponseTemplate defined in setting object (#1)

        Generates the login response and callback to developers to design their own method

	+ idp.parseLoginRequest(sp,binding,req,callback)

        parameters:
        | sp <ServiceProvider>   Declare the source entity
        | binding <string>       Define the binding of login request is received, 'post' or 'redirect'
        | req <object>           req object in express
        | callback <function>    Function with parameter

        Validation and callback parsed the URL parameters (#2)

	+ idp.sendLogoutRequest(sp,binding,user,relayState,callback,rcallback)

        parameters:
        | sp <ServiceProvider>   Declare the target entity
        | binding <string>       Define the binding used to send logout request, 'post' or 'redirect'
        | user <object>          User information in your session (e.g. req.user)
        | relayState <string>    URL to which to redirect the user when logout is complete
        | req <object>           req object in express
        | callback <function>    Function with parameter
          - callback(url)        url is the logout request redirect URL (Redirect binding)
          - callback(obj)        parameters rendered in a form post (Post binding)
        | rcallback <function|o> Function with logoutRequestTemplate defined in setting object (#1)

        Generates the logout request and callback to developers to design their own method

	+ idp.parseLogoutResponse(sp,binding,req,callback)

        parameters:
        | sp <ServiceProvider>   Declare the source entity
        | binding <string>       Define the binding of logout response is received, 'post' or 'redirect'
        | req <object>           req object in express
        | callback <function>    Function with parameters

        Validation and callback parsed the URL parameters

remarks:

  #1: User can replace the tags in their custom logout request template in this rCallback
  #2: We provide basic checking, user can continue their checking in callback function
```

####ServiceProvider
#####Construct a new Service Provider
```
methods:
	+ saml.ServiceProvider(setting,metadata)
		Construct it by both metadata and setting
	+ saml.ServiceProvider(metadata)
		Construct it by importing metadata, use unless you confirm that the idp follows our default setting
	+ saml.ServiceProvider(setting)
		(Advanced) Construct it by custom setting, a new metadata will be also generated

parameters:

  + metadata <string> - path of the metadata (e.g. ./path/mymetadata.xml)
  + setting <object> - declares the perference of service provider

  symbol representation
    o: optional
    m: must set if metadata is not imported

  {
    requestSignatureAlgorithm <string|o>  Default is 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
    loginRequestTemplate <string|o>       Login request template (#1)
    logoutResponseTemplate <string|o>     Logout response template (#1)
    generateID <function|o>               Function to generate the ID of request/response
    entityID <string>                     Define the entity ID, a.k.a issuer
    privateKeyFile <string|o>             File path of .pem file
    privateKeyFilePass <string|o>         Set if your .pem file has protected passpharse (recommend)
    signingCertFile <string|m>            File path of .cer file which is your X.509 certificate (#2)
    nameIDFormat <[string]|o>             Define the support name ID format
    assertionConsumerService <[object]|m> Define binding and location of each single assertion consumer service
    singleLogoutService <[object]|o>      Define binding and location of each single logout service (#3)
    wantAssertionsSigned <boolean|o>      Define whether assertion need signature (Default is false) (#4)
    wantLogoutRequestSigned <boolean|o>   Define whether logout request need signature (Default is false) (#5)
  }

remarks:

  #1: Need to set up another callback function in order to dynamically replace the tag in template
  #2: We recommend to have signature so this field should be specified when metadata is not imported
  #3: Optional depends on whether you provide logout service in your user case
  #4: Identity Provider signs login assertion (response) if set to true
  #5: Identity Provider signs logout request if set to true
```
#####Example
```javascript
// Sample of IDP setting used to construct an service provider
var spSetting = {
    entityID:'https://sp.example.org/metadata',
    nameIDFormat:['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
    privateKeyFile: './privateKey.pem',
    privateKeyFilePass: 'myPassword',
    signingCertFile: './certificate.cer',
    assertionConsumerService:[{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        Location: 'https://sp.example.org/sso/acs'
    },{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        Location: 'https://sp.example.org/sso/acs'
    }],
    singleLogoutService:[{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        Location: 'https://sp.example.org/sso/slo'
    },{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        Location: 'https://sp.example.org/sso/slo'
    }]
};

// Example 1: Construct Service Provider manually
var sp = saml.ServiceProvider(spSetting);

// Example 2: Construct Service Provider with metadata and without signing key
var sp = saml.ServiceProvider('./metadata_sp.xml');

//  Example 3: Construct Service Provider with metadata and include signing key
var sp = saml.ServiceProvider({
    privateKeyFile: './privateKey.pem',
    privateKeyFilePass: 'myPassword'
},'./metadata_sp.xml');
```
#####Actions taken by Service Provider
```
methods:

	+ sp.sendLoginRequest(idp,requestInfo,binding,callback,rcallback)

        parameters:
        | idp <IdentityProvider>  Declare the target entity
        | binding <string>        Define the binding used to send login request, 'post' or 'redirect'
        | callback <function>     Function with parameters rendered in a form post
          - callback(url)         url is the logout request redirect URL (Redirect binding)
          - callback(obj)         parameters rendered in a form post (Post binding)
        | rcallback <function|o>  Function with loginRequestTemplate defined in setting object (#1)

        Generates the login request and callback to developers to design their own method

	+ sp.parseLoginResponse(idp,binding,req,callback)

        parameters:
        | idp <IdentityProvider>  Declare the target entity
        | binding <string>        Define the binding used to send login response, only support 'post'
        | req <object>            req object in express
        | callback <function>     Function with parameter

        Validation and callback parsed the URL parameters (#2)

	+ sp.sendLogoutResponse(idp,requestInfo,binding,user,relayState,callback,rcallback)

        parameters:
        | idp <IdentityProvider>  Declare the target entity
		| requestInfo <object>    Callback parameter from parseLogoutRequest
        | binding <string>        Define the binding used to send logout response, 'post' or 'redirect'
        | user <object>           User information in your session (e.g. req.user)
        | relayState <string>     URL to which to redirect the user when logout is complete
        | req <object>            req object in express
        | callback <function>     Function with parameter
          - callback(url)         url is the logout response redirect URL (Redirect binding)
          - callback(obj)         parameters rendered in a form post (Post binding)
		| rcallback <function|o>  Function with logoutResponseTemplate defined in setting object (#1)

        Generates the logout response and callback to developers to design their own method

	+ sp.parseLogoutRequest(idp,binding,req,callback)

        parameters:
        | idp <IdentityProvider>  Declare the target entity
        | binding <string>        Define the binding of logout request is received, 'post' or 'redirect'
        | req <object>            req object in express
        | callback <function>     Function with parameters

        Validation and callback parsed the URL parameters

remarks:

  #1: User can replace the tags in their custom logout response template in this rCallback
  #2: We provide basic checking, user can continue their checking in callback function
```

##Use cases & knowledge base
For those who may be interested, there are three express application simulating one identity provider and service provider.

Please install all dependencies before start those three servers:
```bash
$ cd example/
$ npm install
$ nodemon app
```

* localhost:3001 idp
* localhost:4002 sp1
* localhost:4003 sp2

###Implementation 1 - Basic login
Access the above three homepage, you are able to login all three portals without using any single-sign-on strategies, the login credentials are as follow:
```
username: admin@idp.com (idp)/ admin@sp1.com (sp1)/ admin@sp2.com (sp2)
password: admin123
```
###Implementation 2 - IdP-initiated Single Sign On (SSO)
1. Login `http://localhost:3001` first which is our `idp`.
2. Under the list of services, select one of those services and click login. (e.g. localhost:4002)
3. A SAML response message w/o signature will send back to the assertion consumer service in `sp1`.
4. `sp1` will validate and parse the response message to confirm the user is authenticated.
5. Login to sp1 and redirect to the main page of sp1.
6. Login user with email `admin@sp1.com` is shown on screen.
7. Steps (1-6) can be repeated to login `sp2`

####Backend code:
In our basic solution, email is assumed to be an unique field and used to identify each user. There is a one-to-many user email mapping in identity provider. When SAML response message is sent, the associated email is included in <saml:NameID> field. In our example, we hard coded the association but better use database to do it in practical.
```javascript
/*
  example/idp/routes/sso.js
*/
  var epn = {
      'admin@idp.com' : {
          assoHash: '$2a$10$/0lqAmz.r6trTurxW3qMJuFHyicUWsV3GKF94KcgN42eVR8y5c25S',
          app: {
              '369550': {
                  assoSpEmail: 'admin@sp1.com'
              },
              '369551': {
                  assoSpEmail: 'admin@sp2.com'
              }
          }
      }
  };
```
###Implementation 3 - SP-initiated Single Sign On (SSO) (Redirect binding)
1. Access `http://localhost/4002/login` which is the login page of `sp1`.
2. Click the login link next to "SP-initiated Single Sign On (Redirect binding)".
3. `sp1` issues a request w/o signature embeded in URL (GET), to `idp` endpoint of single sign on service.
4. If you don't have security context in our `idp`, it will redirect to the login portal of `idp`.
5. If user credentials are correct, `idp` validates request sends a SAML response with associated email to `sp1`.
6. `sp1` will validate and parse the response message to confirm the user is authenticated.
7. Login user with email `admin@sp1.com` is shown on screen.
8. Steps (1-7) can be repeated to login `sp2`

####Backend code:
We implement Redirect binding using URL redirect. The redirect URL has the format  `http://localhost:3001/sso/SingleSignOnService?SAMLRequest=@SAMLRequest&SigAlg=@SigAlg&RelayState=@RelayState&Signature=@Signature`. Notice that `RelayState`, `SigAlg` and `Signature` are optional depending on the perference of `idp`. `SigAlg` and `Signature` will be issued only when `WantAuthnRequestsSigned` is set to true in idp metadata.
```javascript
/*
    sp1/routes/sso.js
    /sso/spinitsso-redirect is the link to initiate redirect-binding sso from sp
*/
router.get('/spinitsso-redirect',function(req,res){
    sp.sendLoginRequest(idp,'redirect',function(url){
        // url is a string, e.g. http://localhost:3001/sso/SingleSignOnService?SAMLRequest=...
        res.redirect(url);
    });
});
```
###Implementation 4 - SP-initiated Single Sign On (SSO) (POST binding)
1. Access `http://localhost/4002/login` which is the login page of `sp1`.
2. Click the login link next to "SP-initiated Single Sign On (Post binding)".
3. `sp1` issues a SAML request w/o signature in a form post to `idp` endpoint of single sign on service (POST).
4. If you don't have security context in our `idp`, it will redirect to the login portal of `idp`.
5. If user credentials are correct, `idp` validates request sends a SAML response with associated email to `sp1`.
6. `sp1` will validate and parse the response message to confirm the user is authenticated.
7. Login user with email `admin@sp1.com` is shown on screen.
8. Steps (1-7) can be repeated to login `sp2`

####Backend code:
We implement POST binding using an automatic form submit. Once the `idp` validates and parses the SAML request from `sp1` succcessfully, it will render the parse result to a new page defined in `views/actions.handlebars` as follow:
```javascript
/*
    idp/routes/sso.js
*/
router.post('/SingleSignOnService/:id',function(req,res){
    // ...
    assoIdp.parseLoginRequest(targetSP,'post',req,function(parseResult){
        // ...
        assoIdp.sendLoginResponse(targetSP,parseResult,'post',req.user,function(response){
            res.render('actions',response);
        });
    });
});
/*
  parseResult is an object with parameters as follow:

  + entityEndpoint:   endpoint of the form
  + actionType:       declares the type of actions (SAMLRequest/SAMLResponse/LogoutRequest/LogoutResponse)
  + actionValue:      base64 encoded value
  + relayState:       used for deeper link
*/
```
```html
<form id="saml-form" method="post" action="{{entityEndpoint}}">
    <input type="hidden" name="{{actionType}}" id="{{actionType}}" value="{{actionValue}}" />
    {{#if relayState}}
        <input type="hidden" name="RelayState" id="relayState" value="{{relayState}}" />
    {{/if}}
</form>
<script type="text/javascript">
    (function(){
        document.forms[0].submit();
    })();
</script>
```

###Implementation 5 - Basic Logout
Access the above three homepage after login, you are able to logout all three portals independently without using any single-sign-on strategies.

###Implementation 6 - IdP-initiated Single Logout (SLO)
1. Login `sp1` and `sp2`.
2. Login `idp` and access its management console. http://localhost:3001.
3. Under the list of services, click the login next to `Logout all services`.
4. `idp` issues a logout request w/o signature to the `sp1`.
5. `sp1` validates the logout request and logout the user.
6. `sp1` sends a logout response w/o signature to the `idp`.
7. There exists a field called `relayState` which is used to specified the redirect destination after user logout.
8. `idp` issues another logout request w/o signature to the `sp2`.
9. `sp2` validates the logout request and logout the user.
10. `sp2` sends a logout response w/o signature to the `idp`.
11. Since no more participating service providers, therefore user is also logged out from `idp`.
12. Redirect to the `idp` login portal http://localhost:3001/login.
13. When accessing `sp1` and `sp2`, the browser will redirect you to the corresponding login page.

####Backend code:
We have set `relayState` to go through all participating service providers. When user is logged out from `idp`, also indicated that logged out from `sp1` and `sp2` in our example.

## Customization
### Custom template for login/logout
Developer can design their own request and response template for login and logout respectively. There are optional parameters in entity setting. For example, add `loginResponseTemplate`, `logoutRequestTemplate` in the setting object when `idp` is constructed, and `loginRequestTemplate`, `logoutResponseTemplate` in the setting object when `
```javascript
// Load the template every time before each request/response is sent
var idp = saml.IdentityProvider({
    //...
    loginResponseTemplate: './loginResponseTemplate.xml',
    logoutRequestTemplate: './logoutRequestTemplate.xml'
    //...
},'./metadata_idp.xml');
// or load the template once the application is cached
var idp = saml.IdentityProvider({
    //...
    loginResponseTemplate: '<saml:...>',
    logoutRequestTemplate: '<saml:...>'
    //...
},'./metadata_idp.xml');
```
There is a callback function `rcallback` in each sending action. It will only be called before sending the request/response when custom template is specified. Otherwise, it uses the default template specfied in `SamlLib.js`. The following section is an example using the custom template.
```javascript
// Access http://localhost:4002/sso/spinitsso-redirect to initiate single sign on service
router.get('/spinitsso-redirect',function(req,res){
    sp.sendLoginRequest(idp,'redirect',function(url){
        res.redirect(url);
    },function(loginRequestTemplate){
        // Here is the callback function for custom template
        // the input parameter is the value of loginRequestTemplate
        // The following is the input parameter of rcallback in different actions
        // sp.sendLoginRequest -> loginRequestTemplate
        // sp.sendLogoutResponse -> logoutResponseTemplate
        // idp.sendLoginResponse -> loginResponseTemplate
        // idp.sendLogoutRequest -> logoutRequestTemplate
        return replaceTagFromTemplate(loginRequestTemplate);
        // replaceTagFromTemplate is a function to do dynamically substitution of tags
    });
});
```
Developers may want to use our default tag replacement `SamlLib.replaceTagsByValue(rawXML,tagValues)` instead of writing their own `replaceTagFromTemplate`. It replaces all defined tags in the input xml string.
```javascript
var requestTags = require('./urn').tags.request;
/**
  * @desc Repalce the tag (e.g. {tag}) inside the raw XML
  * @param  {string} rawXML      raw XML string used to do keyword replacement
  * @param  {array} tagValues    tag values
  * @return {string}
  */
replaceTagsByValue: function replaceTagsByValue(rawXML,tagValues){
    Object.keys(requestTags).forEach(function(t){
        rawXML = rawXML.replace(new RegExp(requestTags[t],'g'),tagValues[t]);
    });
    return rawXML;
}
```
###Release metadata in public
Developer can decide to release the entity metadata publicly.
```javascript
router.get('/metadata',function(req, res, next){
    res.header('Content-Type','text/xml').send(idp.getMetadata());
});
```
###Additional validation
There is a callback function in each sending action. It only checks the signature (if any), the issuer name and timestamp, but developers may want to validate the request/response more than that. Here is the example:
```javascript
/*
* sp1/routes/sso.js
* http://localhost:4002/sso/acs is the endpoint of assertion consumer service in sp1
*/
router.post('/acs',function(req,res,next){
    sp.parseLoginResponse(idp,'post',req,function(parseResult){
        // Your code will be here
        // parseResult is an object consists of
        // + samlContent <string>   plain-text version of request
        // + extract <object>       object including values of NameID, Audience, Attributes
    });
});
```

## More developers and Todo

There is plenty of room for improvement and more features will be added. Please feel free to contribute. Some features and supports are planning to be added in the next release as follow:

+ More test cases !
+ Embrace ES6 !
+ UI improvement of the express applications
+ A GUI for SAML tools
+ Encryption in SAML messages
+ Example of SP-initiated Single Logout Service
+ Example of using MongoDB to handle accounts
+ Asynchronous single logout strategy
+ Support for Artifact Binding
+ Support for rsa-sha256 signing algorithm
+ Support for more certificate format

## License

[MIT](LICENSE)

## Copyright

Copyright (C) 2015 Tony Ngan, released under the MIT License.
