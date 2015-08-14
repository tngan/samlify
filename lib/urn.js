/**
 * @file urn.js
 * @author Tony Ngan
 * @desc  Includes all keywords need in express-saml2
 */
module.exports.namespace = {
    binding: {
        redirect: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        post: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        arifact: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-ARIFACT'
    },
    names: {
        protocol: 'urn:oasis:names:tc:SAML:2.0:protocol',
        assertion: 'urn:oasis:names:tc:SAML:2.0:assertion',
        metadata: 'urn:oasis:names:tc:SAML:2.0:metadata',
        userLogout: 'urn:oasis:names:tc:SAML:2.0:logout:user',
        adminLogout: 'urn:oasis:names:tc:SAML:2.0:logout:admin'
    },
    authnContextClassRef: {
        password: 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password',
        passwordProtectedTransport: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
    },
    format: {
        emailAddress: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        persistent: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
        transient: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        entity: 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
        unspecified: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        kerberos: 'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos',
        windowsDomainQualifiedName: 'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName',
        x509SubjectName: 'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName'
    },
    statusCode:{
        // permissible top-level status codes
        success: 'urn:oasis:names:tc:SAML:2.0:status:Success',
        requester: 'urn:oasis:names:tc:SAML:2.0:status:Requester',
        responder: 'urn:oasis:names:tc:SAML:2.0:status:Responder',
        versionMismatch: 'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch',
        // second-level status codes
        authFailed: 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed',
        invalidAttrNameOrValue: 'urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue',
        invalidNameIDPolicy: 'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy',
        noAuthnContext:'urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext',
        noAvailableIDP:'urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP',
        noPassive:'urn:oasis:names:tc:SAML:2.0:status:NoPassive',
        noSupportedIDP:'urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP',
        partialLogout:'urn:oasis:names:tc:SAML:2.0:status:PartialLogout',
        proxyCountExceeded:'urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded',
        requestDenied:'urn:oasis:names:tc:SAML:2.0:status:RequestDenied',
        requestUnsupported:'urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported',
        requestVersionDeprecated:'urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated',
        requestVersionTooHigh:'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh',
        requestVersionTooLow:'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow',
        resourceNotRecognized:'urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized',
        tooManyResponses:'urn:oasis:names:tc:SAML:2.0:status:TooManyResponses',
        unknownAttrProfile:'urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile',
        unknownPrincipal:'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal',
        unsupportedBinding:'urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding'
    }
};

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
    xmlTag: {
        loginRequest: 'AuthnRequest',
        logoutRequest: 'LogoutRequest',
        loginResponse: 'Response',
        logoutResponse: 'LogoutResponse'
    }
};

module.exports.wording = {
    algorithms: {
        RSA_SHA1: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
        RSA_SHA256: 'http://www.w3.org/2000/09/xmldsig#rsa-sha256'
    },
    urlParams: {
        samlRequest: 'SAMLRequest',
        logoutRequest: 'LogoutRequest',
        logoutResponse: 'LogoutResponse',
        sigAlg: 'SigAlg',
        signature: 'Signature',
        relayState: 'RelayState'
    },
    binding: {
        redirect: 'redirect',
        post: 'post',
        arifact: 'arifact'
    },
    certUse: {
        signing: 'signing',
        encrypt: 'encrypt'
    },
    metadata: {
        sp: 'SPMetadata',
        idp: 'IdPMetadata'
    }
};
