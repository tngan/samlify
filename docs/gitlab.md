# Work with Gitlab (samlify as idp)

In this tutorial, we will walk through step by step to configure self-hosted and dockerized Gitlab CE, also integrates with samlify.

### Setup postgresql

```
docker run --name gitlab-postgresql -d \
    --env 'DB_NAME=gitlabhq_production' \
    --env 'DB_USER=gitlab' --env 'DB_PASS=password' \
    --env 'DB_EXTENSION=pg_trgm' \
    --volume /esaml2/postgresql:/var/lib/postgresql \
    sameersbn/postgresql:9.6-2
```
!> Remember to configure file sharing when work with volume mount

### Setup redis

```
docker run --name gitlab-redis -d \
    --volume /esaml2/redis:/var/lib/redis \
    sameersbn/redis:latest
```

### Running gitlab in container

```
docker run --name gitlab -d \
    --link gitlab-postgresql:postgresql --link gitlab-redis:redisio \
    --publish 10022:22 --publish 10080:80 \
    --env 'GITLAB_PORT=10080' --env 'GITLAB_SSH_PORT=10022' \
    --env 'GITLAB_SECRETS_DB_KEY_BASE=long-and-random-alpha-numeric-string' \
    --env 'GITLAB_SECRETS_SECRET_KEY_BASE=long-and-random-alpha-numeric-string' \
    --env 'GITLAB_SECRETS_OTP_KEY_BASE=long-and-random-alpha-numeric-string' \
    --env 'OAUTH_SAML_ASSERTION_CONSUMER_SERVICE_URL=http://localhost:10080/users/auth/saml/callback' \
    --env 'OAUTH_SAML_IDP_CERT_FINGERPRINT=77:36:12:0B:32:9A:6D:61:29:E1:0D:13:C0:FF:63:1A:B9:22:FC:3C' \
    --env 'OAUTH_SAML_IDP_SSO_TARGET_URL=http://localhost:3001/sso/SingleSignOnService/gitlab' \
    --env 'OAUTH_SAML_ISSUER=https://gitlab' \
    --env 'OAUTH_SAML_NAME_IDENTIFIER_FORMAT=urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' \
    --volume /esaml2/gitlab:/home/git/data \
    sameersbn/gitlab:9.1.2
```

### Get fingerprint (This is another way I found)

```console
$ openssl x509 -in ./key/idp/cert.cer -sha1 -noout -fingerprint
```

### Get metadata from gitlab

`http://localhost:10080/users/auth/saml/metadata`

remember to modify the acs endpoint to http://localhost:10080/users/auth/saml/callback

### The step-by-step configuration of IDP with samlify

After setting up the gitlab, we need to set up the IDP with samlify. Beside, the identity provider is an experimental feature in this module.

Since there are some required attributes are required and specified in the Gitlab metadata, so we need to add attributes to the response, so we need to customize response template when we construct the Identity provider.

`email`, `name`, `first_name` and `last_name` (default email and name are `admin@example.com` and `Administrator` in docker-gitlab)

And we need to change our metadata by setting `WantAuthnRequestsSigned` to false since the request from SP is not signed.

Signed response is highly RECOMMENDED (compulsory in Gitlab's implementation), including assertion signature or/and entire message signature, so a new property `signatureConfig` is introduced into constructor of identity provider to specify the location, prefix of messsage signature, this configuration is exactly the same as [xml-crypto](https://github.com/yaronn/xml-crypto#examples).

```javascript
const idp = require('samlify').IdentityProvider({
  metadata: readFileSync('./misc/metadata_idp1.xml'),
  privateKey: './misc/privkey.pem',
  isAssertionEncrypted: false,
  privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  loginResponseTemplate: {
    context: '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status><saml:Assertion ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><AuthnStatement AuthnInstant="{IssueInstant}"> <AuthnContext><AuthnContextClassRef>AuthnContextClassRef</AuthnContextClassRef></AuthnContext></AuthnStatement></samlp:Response>',
    attributes: [
      { name: "mail", valueTag: "user.email", nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", valueXsiType: "xs:string" },
      { name: "name", valueTag: "user.name", nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", valueXsiType: "xs:string" },
      { name: "first_name", valueTag: "user.first", nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", valueXsiType: "xs:string" },
      { name: "last_name", valueTag: "user.last", nameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", valueXsiType: "xs:string" },
    ]
  },
  signatureConfig: {
    prefix: 'ds',
    location: { reference: "/*[local-name(.)='Response']/*[local-name(.)='Issuer']", action: 'after' }
  }
});
```

### The step-by-step configuration of SP with samlify

```javascript
const sp = require('samlify').ServiceProvider({
  metadata: readFileSync('./misc/metadata_sp1.xml')
});
```

the metadata is obtained from `http://localhost:10080/users/auth/saml/metadata`
