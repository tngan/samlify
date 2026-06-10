# GitLab integration (samlify as IdP)

This chapter walks through the configuration of a self-hosted, Dockerized GitLab CE instance that integrates with samlify as the identity provider.

## 1. Set up PostgreSQL

```console
docker run --name gitlab-postgresql -d \
    --env 'DB_NAME=gitlabhq_production' \
    --env 'DB_USER=gitlab' --env 'DB_PASS=password' \
    --env 'DB_EXTENSION=pg_trgm' \
    --volume /esaml2/postgresql:/var/lib/postgresql \
    sameersbn/postgresql:9.6-2
```

::: warning
Remember to configure file sharing when using volume mounts.
:::

## 2. Set up Redis

```console
docker run --name gitlab-redis -d \
    --volume /esaml2/redis:/var/lib/redis \
    sameersbn/redis:latest
```

## 3. Run GitLab in a container

```console
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

## 4. Retrieve the certificate fingerprint

```console
$ openssl x509 -in ./key/idp/cert.cer -sha1 -noout -fingerprint
```

## 5. Retrieve the GitLab metadata

Fetch the metadata from:

```
http://localhost:10080/users/auth/saml/metadata
```

Update the ACS endpoint in the metadata to `http://localhost:10080/users/auth/saml/callback`.

## 6. Configure the IdP with samlify

The IdP in samlify is an experimental feature. GitLab's metadata declares several required attributes, so the response template must be customised to include them:

- `email`
- `name`
- `first_name`
- `last_name`

The default values used by the `docker-gitlab` image are `admin@example.com` for `email` and `Administrator` for `name`.

Set `WantAuthnRequestsSigned` to `false` in the IdP metadata because the request from this SP is not signed.

A signed response is strongly recommended (it is mandatory in GitLab's implementation), either at the assertion level, the message level, or both. Use `signatureConfig` to control the location and prefix of the message signature; the options match those of [xml-crypto](https://github.com/yaronn/xml-crypto#examples).

```javascript
const idp = require('samlify').IdentityProvider({
  metadata: readFileSync('./misc/metadata_idp1.xml'),
  privateKey: './misc/privkey.pem',
  isAssertionEncrypted: false,
  privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  loginResponseTemplate: {
    context: '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status><saml:Assertion ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><AuthnStatement AuthnInstant="{IssueInstant}"> <AuthnContext><AuthnContextClassRef>AuthnContextClassRef</AuthnContextClassRef></AuthnContext></AuthnStatement></samlp:Response>',
    attributes: [
      { name: 'mail',       valueTag: 'user.email', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', valueXsiType: 'xs:string' },
      { name: 'name',       valueTag: 'user.name',  nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', valueXsiType: 'xs:string' },
      { name: 'first_name', valueTag: 'user.first', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', valueXsiType: 'xs:string' },
      { name: 'last_name',  valueTag: 'user.last',  nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', valueXsiType: 'xs:string' },
    ]
  },
  signatureConfig: {
    prefix: 'ds',
    location: { reference: "/*[local-name(.)='Response']/*[local-name(.)='Issuer']", action: 'after' }
  }
});
```

## 7. Configure the SP with samlify

```javascript
const sp = require('samlify').ServiceProvider({
  metadata: readFileSync('./misc/metadata_sp1.xml')
});
```

The SP metadata is obtained from `http://localhost:10080/users/auth/saml/metadata`.
