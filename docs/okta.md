## Work with Okta (Credit to [@fas3r](https://github.com/fas3r))

?> In this chapter, we will make an sample application that implements SP-initiated SSO.

### Pre-requirement:

samlify, express (or other), body-parser.

### Step-by-step tutorial:

1. Create a new web app with SAML2.0 in okta :

![](https://user-images.githubusercontent.com/11342586/54870114-a3396880-4da2-11e9-9e79-3debd7f6c93f.png)


2. Configure SAML_integration:

  - General setting:

    ![](https://user-images.githubusercontent.com/11342586/54870126-b8ae9280-4da2-11e9-9154-39a697e0a69a.png)
    
  - Configure SAML :

    !> Never upload your private key online

    ![](https://user-images.githubusercontent.com/11342586/54870230-f7911800-4da3-11e9-920e-66c22fca8b14.png)

    * "Single Sign on URL": the uri where to "POST" the auth request 
    * "Audience URI": The uri where the metadata are accessible. This is not mandatory if you don't want to share the metadata file. See [here](https://samlify.js.org/#/metadata-distribution)
    * "Assertion Encryption": We set to "Encrypted". Indicates whether the SAML assertion is encrypted.
    * "Encryption Certificate" : Upload the path to the certificate `*.cer` to use to encrypt the assertion.
    
    ![](https://user-images.githubusercontent.com/11342586/54870264-9289f200-4da4-11e9-8ce4-560aaa8e99d7.png)

    * and the attributes statement/groups to return in the assertion section

  -  Feedback:

    ![](https://user-images.githubusercontent.com/11342586/54870275-b1888400-4da4-11e9-96ec-d09a61cf00a5.png)

    * Choose your desired one.

3. Next you will see in the "Sign On" tab the following :

  ![](https://user-images.githubusercontent.com/11342586/54870311-18a63880-4da5-11e9-815f-f73ab237e954.png)

 - Red Arrow: The SAML 2.0 Certificate
 - Green Arrow: Get the idp XML file of your application with all the information
 - Blue Arrow: Direct link to the metadata file of the application.
 - In the "General" tab you should see something like :

  ![](https://user-images.githubusercontent.com/11342586/54870350-a2ee9c80-4da5-11e9-8c32-c05eaae3d7c9.png)


4. Example code snippet

```js
const express = require('express');
const fs = require('fs');
const saml = require('samlify');
const axios = require('axios');
const bodyParser = require("body-parser");
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(serveStatic(path.resolve(__dirname, 'public')));

// URL to the okta metadata
const uri_okta_metadata = 'https://dev-xxxxxxx.oktapreview.com/app/APP_ID/sso/saml/metadata';

axios.get(uri_okta_metadata)
.then(response => {

  const idp = saml.IdentityProvider({
    metadata: response.data,
    isAssertionEncrypted: true,
    messageSigningOrder: 'encrypt-then-sign',
    wantLogoutRequestSigned: true
  });

  const sp = saml.ServiceProvider({
    entityID: 'http://localhost:8080/sp/metadata?encrypted=true',
    authnRequestsSigned: false,
    wantAssertionsSigned: true,
    wantMessageSigned: true,
    wantLogoutResponseSigned: true,
    wantLogoutRequestSigned: true,
    // the private key (.pem) use to sign the assertion; 
    privateKey: fs.readFileSync(__dirname + '/ssl/sign/privkey.pem'),       
    // the private key pass;
    privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',                     
    // the private key (.pem) use to encrypt the assertion;
    encPrivateKey: fs.readFileSync(__dirname + '/ssl/encrypt/privkey.pem'),             
    isAssertionEncrypted: true,
    assertionConsumerService: [{
      Binding: saml.Constants.namespace.binding.post,
      Location: 'http://localhost:8080/sp/acs?encrypted=true',
    }]
  });

  app.post('/sp/acs', async (req, res) => {
    try {
      const { extract } = await sp.parseLoginResponse(idp, 'post', req);
      console.log(extract.attributes);
      /**
      *
      * Implement your logic here. 
      * extract.attributes, should contains : firstName, lastName, email, uid, groups 
      *           
      **/
    } catch (e) {
      console.error('[FATAL] when parsing login response sent from okta', e);
      return res.redirect('/');
    }
  });

  app.get('/login', async (req, res) => {
        const { id, context } = await sp.createLoginRequest(idp, 'redirect');
        console.log(context);
        return res.redirect(context);
      });

  app.get('/sp/metadata', (req, res) => {
    console.log("here");
    res.header('Content-Type', 'text/xml').send(idp.getMetadata());
  });

});
```
