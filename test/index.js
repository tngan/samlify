/**
* @file index.js
* @author Tony Ngan
* @desc mocha test for Utility and SamlLib module
*/
// Package
var entry = require('../build/index');
var Utility = entry.Utility;
var should = require('should');
var fs = require('fs');
var SamlLib = entry.SamlLib;
var xpath = require('xpath');
var dom = require('xmldom').DOMParser;
var wording = require('../build/src/urn').wording;
var binding = entry.Constants.namespace.binding;
var select = require('xml-crypto').xpath;
var algorithms = entry.Constants.algorithms;
var signatureAlgorithms = algorithms.signature;

// Define of metadata
var _spKeyFolder = './test/key/sp/';
var _spPrivPem = _spKeyFolder + 'privkey.pem';
var _spPrivKey = _spKeyFolder + 'nocrypt.pem';
var _spPrivKeyPass = 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px';

// Define an identity provider
var idp = entry.IdentityProvider({
  privateKeyFile: './test/key/idp/privkey.pem',
  privateKeyFilePass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  isAssertionEncrypted: true,
  encPrivateKeyFile: './test/key/idp/encryptKey.pem',
  encPrivateKeyFilePass: 'g7hGcRmp8PxT5QeP2q9Ehf1bWe9zTALN',
  metadata: './test/metadata/IDPMetadata.xml'
});

var sp = entry.ServiceProvider({
  privateKeyFile: './test/key/sp/privkey.pem',
  privateKeyFilePass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
  isAssertionEncrypted: true, // for logout purpose
  encPrivateKeyFile: './test/key/sp/encryptKey.pem',
  encPrivateKeyFilePass: 'BXFNKpxrsjrCkGA8cAu5wUVHOSpci1RU',
  metadata: './test/metadata/SPMetadata.xml'
});

// Define metadata
var IdPMetadata = entry.IdPMetadata('./test/metadata/IDPMetadata.xml');
var SPMetadata = entry.SPMetadata('./test/metadata/SPMetadata.xml');
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
var sampleSignedResponse = fs.readFileSync('./test/metadata/SignSAMLResponse.xml').toString();
var wrongResponse = fs.readFileSync('./test/metadata/wrongResponse.xml').toString();
var spCertKnownGood = fs.readFileSync('./test/key/sp/knownGoodCert.cer').toString().trim();
var spPemKnownGood = fs.readFileSync('./test/key/sp/knownGoodEncryptKey.pem').toString().trim();

///*
function writer(str) {
  fs.writeFileSync('test.txt', str);
}

//*/
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
describe('1. Utility.js', function () {
  it('1.1 Base64 Encoding should return encoded string', function (done) {
    (Utility.base64Encode('Hello World')).should.be.equal('SGVsbG8gV29ybGQ=');
    done();
  });
  it('1.2 Base64 Decoding should return desendLoginResponsecoded string', function (done) {
    (Utility.base64Decode('SGVsbG8gV29ybGQ=')).should.be.equal('Hello World');
    done();
  });
  it('1.3 SAML Encoded (Deflate + Base64 Encoded)', function (done) {
    (Utility.base64Encode(Utility.deflateString('Hello World'))).should.be.equal('80jNyclXCM8vykkBAA==');
    done();
  });
  it('1.4 SAML Decoded (Base64 Decoded + Inflate)', function (done) {
    (Utility.inflateString('80jNyclXCM8vykkBAA==')).should.be.equal('Hello World');
    done();
  });
  it('1.5 Parse Certificate should return clean certificate', function (done) {
    (Utility.parseCerFile('./test/key/sp/cert.cer').should.be.equal((spCertKnownGood)));
    done();
  });
  it('1.6 Normalize Pem should return clean string', function (done) {
    (Utility.normalizePemString(fs.readFileSync('./test/key/sp/encryptKey.pem').toString()).should.be.equal((spPemKnownGood)));
    done();
  });
});

describe('2. SamlLib.js', function () {
  var _originRequest = fs.readFileSync('./test/metadata/SAMLRequest.xml').toString();
  var _originResponse = fs.readFileSync('./test/metadata/SAMLResponse.xml').toString();

  var _decodedResponse = fs.readFileSync('./test/metadata/SignSAMLResponse.xml').toString();
  var _decodedResponseDoc = new dom().parseFromString(_decodedResponse);
  var _decodedResponseSignature = select(_decodedResponseDoc, "/*/*[local-name(.)='Signature']")[0];

  var _decodedRequestSHA256 = fs.readFileSync('./test/metadata/SignSAMLRequestSHA256.xml').toString();
  var _decodedRequestDocSHA256 = new dom().parseFromString(_decodedRequestSHA256);
  var _decodedRequestSignatureSHA256 = select(_decodedRequestDocSHA256, "/*/*[local-name(.)='Signature']")[0];

  var _decodedRequestSHA512 = fs.readFileSync('./test/metadata/SignSAMLRequestSHA512.xml').toString();
  var _decodedRequestDocSHA512 = new dom().parseFromString(_decodedRequestSHA512);
  var _decodedRequestSignatureSHA512 = select(_decodedRequestDocSHA512, "/*/*[local-name(.)='Signature']")[0];

  var octetString = 'SAMLRequest=fVNdj9MwEHxH4j9Yfm%2Fi5PpBrLaotEJUOrioKTzwgoy9oZZiO9ibu%2FLvcXLtKUhHnyzZM7Mzu+tlEKZp+abDkz3A7w4CkrNpbODDw4p23nIngg7cCgOBo+TV5vM9zxPGW+%2FQSdfQEeU2Q4QAHrWzlOx3K%2FrjHSsWbFEzdsfETDE2z5ksVKHqYlHP84WooVBS5lNKvoEPkbeiUYaS0rtHrcB%2FiRVWtCoJRuNRM4QO9jagsBiRLJtO2GKSzY%2F5HZ%2FlfDr7TskuIrUVOIidEFueplq1CZyFaRtIpDNpVT1U4B+1hKQ9tUO5IegHbZW2v25n%2FPkMCvzT8VhOyofqSMnmmnvrbOgM+Iv818P9i4nwrwcFxmVp1IJzb+K9kIGu374hZNm3mQ9R%2Ffp1rgEUSqBYpmPsC7nlfd%2F2u9I1Wv4hH503Av8fKkuy4UarST1AORihm41SHkKI4ZrGPW09CIyzQN8BTce1LmsFaliy2ACEM5KtM63wOvRTiNYlPoe7xhtjt01cmwPU65ubJbnscfG6jMeT8+qS%2FlWpwV96w2BEXN%2FHn2P9Fw%3D%3D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1';
  var octetStringSHA256 = 'SAMLRequest=fZJbTwIxEIX%2Fyqbvy3Yv3BogQYiRBJWw6INvY3eAJt0WO10v%2F966YIKJkPRpek7nfDMdEdT6IKaN35s1vjVIPvqstSHRXoxZ44ywQIqEgRpJeCnK6f1SZB0uDs56K61mZ5brDiBC55U1LFrMx2wrB8P%2BIB%2FGeQHbuOgVwxigB3EqewXfDjDPZJ9Fz%2BgoWMYsvBB8RA0uDHkwPpR42o1THvNswzMRTtHtpEX2wqJ5QFEGfOvce38QSaKtBL235EXOeZoQ2aRUZqexVDvzaEp070pikveG3W5otTrx3ShTBdl1tNejiMTdZrOKV4%2FlhkXTX9yZNdTU6E4dntbLfzIVnGdtJpDEJqOfaYqW1k0ua2v0UIGHUXKuHx3X%2BhBSLuYrq5X8im6tq8Ffhkg7aVtRVbxtpQJrUHpaVQ6JAozW9mPmEDyGzYEmZMnk2PbvB5p8Aw%3D%3D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256';
  var octetStringSHA512 = 'SAMLRequest=fZJfT8IwFMW%2FytL3sY5tCA0jQYiRBIUw9MG3a3cnTboWezv%2FfHvr0AQT9fX2nJ7zu%2B2UoNVHMe%2F8wezwuUPy0VurDYn%2BoGSdM8ICKRIGWiThpajmN2sxHHBxdNZbaTU7s%2FzvACJ0XlnDotWyZFBkDcAE47wZjeNcXqTxGAsZy0lR1EUzAiwaFt2jo2ApWbgh%2BIg6XBnyYHwY8bSIUx7z4Z4PRZaLbDLg4%2FyBRcuAogz43nnw%2FiiSRFsJ%2BmDJi4zzNCGySaXMk8ZKPZmNqdC9KIlJNgr5IWr7xXepTB1k%2F6M9nkQkrvf7bbzdVHsWzb9xF9ZQ16L7SrjbrX%2FplHM%2B7DuBJDabfm5T9LRu9re2RQ81eJgm5%2Frp6VlvQ8vVcmu1ku%2FRlXUt%2BL8h0kHaT1QdN71UYAtKz%2BvaIVGA0dq%2BLhyCx5I1oAlZMjvF%2FvxAsw8%3D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha512';

  var signatureB64SHA512 = 'rLIExCcCVXup1szC1vh1Q+JZyRu5gXcAI3NuU3Wkws2uqBpgCjiKU0etFWTmakJHvomMlHkzjVgPJbZAnJYPGfY3PYenJmTrrYORcZ1O73Io0enQsMyF/fholtcFcHSM2dN1rBuMaImEUON+nrtcf0v4b73kVizLXLCejGPgXEoASLs6tk9nzDCNLRJECwkgmFRWwWoo4e57SyH5aWPUR0Vz7VV/UJ4TJgUpdWMOM65QVDBQDckpkttIcMssOl9WzOqJGXdSTTn5K7UlljK8mVh5V0zKSZnQld4qXicW+Dm+P1QCiwfcxf0IklYFoU6bd0LCuxyAW7pmwI8PYpA76Q==';
  var signatureB64SHA256 = 'iC7RXfHuIu4gBLGABv0qtt96XFvyC7QSX8cDyLjJj+WNOTRMO5J/AYKelVhuc2AZuyGcf/sfeeVmcW7wyKTBHiGS+AWUCljmG43mPWERPfsa7og+GxrsHDSFh5nD70mQF44bXvpo/oVOxHx/lPiDG5LZg2KBccNXqJxMVUhnyU6xeGBctYY5ZQ4y7MGOx7hWTWjHyv+wyFd44Bcq0kpunTls91z03GkYo/Oxd4KllbfR5D2v6awjrc79wMYL1CcZiKZ941ter6tHOHCwtZRhTqV3Dl42zOKUOCyGcjJnVzJre1QBA7hrn3WB5/fu5kE6/E9ENRWp8ZRJLbU8C2Oogg==';
  var signatureB64SHA1 = 'UKPzYQivZOavFV3QjOH/B9AwKls9n5hZIzOL+V93Yi7lJ7siNkAA9WZgErtFVpDTN6ngSwvlfP/hXZcS33RcCGBWi1SX+xuwuk2U7bZgdkkw4tIH8zcgiRy8bK0IpMoXmLbApU2QsiNwRDMZq3iQdlaMhlsJh85VI+90SQk7fewseiw5Ui6BIpFSH96gLYjWMDPpwk+0GkhkkVaP5vo+I6mBQryD9YPFRu7JfCrnw2T6gldXlGu0IN326+qajKheAGmPSLWBmeFYhquJ5ipgfQGU/KCNIEUr6hkW8NU0+6EVaZl/A9Fyfs1+8KCQ6HxZ7FGyewQjJIx3a8XvBM5vDg==';
  var dummySignRequest = 'PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iXzgwOTcwN2YwMDMwYTVkMDA2MjBjOWQ5ZGY5N2Y2MjdhZmU5ZGNjMjQiIFZlcnNpb249IjIuMCIgUHJvdmlkZXJOYW1lPSJTUCB0ZXN0IiBJc3N1ZUluc3RhbnQ9IjIwMTQtMDctMTZUMjM6NTI6NDVaIiBEZXN0aW5hdGlvbj0iaHR0cDovL2lkcC5leGFtcGxlLmNvbS9TU09TZXJ2aWNlLnBocCIgUHJvdG9jb2xCaW5kaW5nPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YmluZGluZ3M6SFRUUC1QT1NUIiBBc3NlcnRpb25Db25zdW1lclNlcnZpY2VVUkw9Imh0dHBzOi8vc3AuZXhhbXBsZS5vcmcvc3Avc3NvIj48c2FtbDpJc3N1ZXIgSWQ9Il8wIj5odHRwczovL3NwLmV4YW1wbGUub3JnL21ldGFkYXRhPC9zYW1sOklzc3Vlcj48c2FtbHA6TmFtZUlEUG9saWN5IEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIiBBbGxvd0NyZWF0ZT0idHJ1ZSIvPjxzYW1scDpSZXF1ZXN0ZWRBdXRobkNvbnRleHQgQ29tcGFyaXNvbj0iZXhhY3QiPjxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbHA6UmVxdWVzdGVkQXV0aG5Db250ZXh0PjxTaWduYXR1cmUgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxTaWduZWRJbmZvPjxDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PFNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPjxSZWZlcmVuY2UgVVJJPSIjXzAiPjxUcmFuc2Zvcm1zPjxUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L1RyYW5zZm9ybXM+PERpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+PERpZ2VzdFZhbHVlPnRRRGlzQlhLVFErOU9YSk81cjdLdUpnYStLST08L0RpZ2VzdFZhbHVlPjwvUmVmZXJlbmNlPjwvU2lnbmVkSW5mbz48U2lnbmF0dXJlVmFsdWU+b3hSa3ZhdTdVdllnRkVaN1lOQVVOZjMwNjdWN1RuNUM5WFNJaWV0MWFadzJGWWV2Tlc1YlV5LzBteHAzYWo2QXZmRmpubXB6QWI4OEJqZHdBejJCRXJEVG9tUmN1WkI3TGIwZllUZjMxTjJvWk9YME1pUGlRT0g1NEk2M3FKVzRYbzNWcWRGN0dCdUZaWkh5bGxmU0J2N2dmQ3RqSkR3RlNDeldLNzBCOXIzY0ZNUkpaTGhDSjlvUGVuKzRVOXNjU1lPNmcrc3pCWkxsNkFpSjA2UEhjOGp6RUtHd2ZRcmNaazhrREtVbHZOZkpNVUx5cThkcHgyVnZVQXg0cDVld2ZNT3dCOVczSGwzUFBhMGRPNzd6WmlmM0NnbHBjTjA2ZittNlVZRy93bm9UUUV5S1c5aE9lKzJ2R004MFc3N2VXdTBkbWlhUHVxVDFvazhMWFB1cTFBPT08L1NpZ25hdHVyZVZhbHVlPjxLZXlJbmZvPjxYNTA5RGF0YT48WDUwOUNlcnRpZmljYXRlPk1JSURvekNDQW91Z0F3SUJBZ0lKQUtOc21MOFFiZnB3TUEwR0NTcUdTSWIzRFFFQkN3VUFNR2d4Q3pBSkJnTlZCQVlUQWtoTE1SSXdFQVlEVlFRSURBbEliMjVuSUV0dmJtY3hDekFKQmdOVkJBY01Ba2hMTVJNd0VRWURWUVFLREFwdWIyUmxMWE5oYld3eU1TTXdJUVlKS29aSWh2Y05BUWtCRmhSdWIyUmxMbk5oYld3eVFHZHRZV2xzTG1OdmJUQWVGdzB4TlRBM01EVXhOelUyTkRkYUZ3MHhPREEzTURReE56VTJORGRhTUdneEN6QUpCZ05WQkFZVEFraExNUkl3RUFZRFZRUUlEQWxJYjI1bklFdHZibWN4Q3pBSkJnTlZCQWNNQWtoTE1STXdFUVlEVlFRS0RBcHViMlJsTFhOaGJXd3lNU013SVFZSktvWklodmNOQVFrQkZoUnViMlJsTG5OaGJXd3lRR2R0WVdsc0xtTnZiVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFNUUpBQjhKcnNMUWJVdUphOGFrekxxTzFFWnFDbFMwdFFwK3crNXdndWZwMDdXd0duL3NobWE4ZGNRTmoxZGJqc3pJNUhCZVZGak9LSXhsZmptTkI5b3ZoUVBzdEJqUC9VUFFZcDFJcDJJb0hDWVg5SERnTXozeHlYS2JIdGhVelphRUN6K3ArN1d0Z3doY3pSa0JMRE9tMmsxNXFoUFlHUHcwdkgyemJWUkdXVUJTOWR5Mk1wM3RxbFZiUDB4WjlDRE5raENKa1Y5U01OZm9DVlcvVllQcUsyUUJvN2tpNG9ibTV4NWl4RlFTU0hzS2JWQVJWenlRSDVpTmpGZTFUZEFwM3JEd3JFNUxjMU5RbFFheFI1R25iMk5aQXBET1JSWklWbE52MldVZGk5UXZNMHlDempROTBqUDBPQW9nSGhSWWF4ZzAvdmdORXllNDZoK1BpWTBDQXdFQUFhTlFNRTR3SFFZRFZSME9CQllFRkVWa2pjTEFJVG5ka3kwOTBBeTc0UXFDbVFLSU1COEdBMVVkSXdRWU1CYUFGRVZramNMQUlUbmRreTA5MEF5NzRRcUNtUUtJTUF3R0ExVWRFd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBRzRsWVgzS1FYZW5lejRMcERuWmhjRkJFWmk5WXN0VUtQRjVFS2QrV3BscFZiY1RRYzFBMy9aK3VIUm15VjhoK3BRemVGNkxpb2IzN0c4N1lwYWNQcGxKSTY2Y2YyUmo3ajhoU0JOYmRyKzY2RTJxcGNFaEFGMWlKbXpCTnloYi95ZGxFdVZwbjgvRXNvUCtIdkJlaURsNWdvbjM1NjJNelpJZ1YvcExkVGZ4SHlXNmh6QVFoakdxMlVoY3ZSK2dYTlZKdkhQMmVTNGpsSG5Ka0I5YmZvMGt2Zjg3UStENlhLWDNxNWMzbU84dHFXNlVwcUhTQyt1TEVwelppTkxldUZhNFRVSWhnQmdqRGpsUnJOREt1OG5kYW5jU24zeUJIWW5xSjJ0OWNSK2NvRm5uallBQlFwTnJ2azRtdG1YWThTWG9CellHOVkrbHFlQXVuNiswWXlFPTwvWDUwOUNlcnRpZmljYXRlPjwvWDUwOURhdGE+PC9LZXlJbmZvPjwvU2lnbmF0dXJlPjwvc2FtbHA6QXV0aG5SZXF1ZXN0Pg==';
  var dummySignRequestSHA256 = 'PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iXzgwOTcwN2YwMDMwYTVkMDA2MjBjOWQ5ZGY5N2Y2MjdhZmU5ZGNjMjQiIFZlcnNpb249IjIuMCIgUHJvdmlkZXJOYW1lPSJTUCB0ZXN0IiBJc3N1ZUluc3RhbnQ9IjIwMTQtMDctMTZUMjM6NTI6NDVaIiBEZXN0aW5hdGlvbj0iaHR0cDovL2lkcC5leGFtcGxlLmNvbS9TU09TZXJ2aWNlLnBocCIgUHJvdG9jb2xCaW5kaW5nPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YmluZGluZ3M6SFRUUC1QT1NUIiBBc3NlcnRpb25Db25zdW1lclNlcnZpY2VVUkw9Imh0dHBzOi8vc3AuZXhhbXBsZS5vcmcvc3Avc3NvIj48c2FtbDpJc3N1ZXIgSWQ9Il8wIj5odHRwczovL3NwLmV4YW1wbGUub3JnL21ldGFkYXRhPC9zYW1sOklzc3Vlcj48c2FtbHA6TmFtZUlEUG9saWN5IEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIiBBbGxvd0NyZWF0ZT0idHJ1ZSIvPjxzYW1scDpSZXF1ZXN0ZWRBdXRobkNvbnRleHQgQ29tcGFyaXNvbj0iZXhhY3QiPjxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbHA6UmVxdWVzdGVkQXV0aG5Db250ZXh0PjxTaWduYXR1cmUgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxTaWduZWRJbmZvPjxDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PFNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz48UmVmZXJlbmNlIFVSST0iI18wIj48VHJhbnNmb3Jtcz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9UcmFuc2Zvcm1zPjxEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz48RGlnZXN0VmFsdWU+d3VKWlJSdWlGb0FQZVZXVllReXhOWXpjbUpJdXB0dTZmaE10MVZuQVZQbz08L0RpZ2VzdFZhbHVlPjwvUmVmZXJlbmNlPjwvU2lnbmVkSW5mbz48U2lnbmF0dXJlVmFsdWU+V0VUTUtaL1pzTm5pbDVjVCtHeTFKbmJWMVVscUN2N205SlppZ1NLTXFhbFlOL1ZDclMxelpFMkVOekxFSjhCN1ZaVkMyRVJBT2pHL1lHbWJ4Si95K2Z6YVR1bGh0blhrYUZncytmNEdJZDBISDY0MldKRnRBeUg2RS81SUVVWUVXYUk0TzA5MWgvd2EvM2EyNEJZK3R5L0ExSmIxLzM5NXpXVi84NUZETXFNemdVRDdRYkQ4TG5mcThkS1hJZDdQWmdnVnpQTFpvRHo0YXpaL3V4VG9aUkxwKy9XVjZHQy91Y2lLMmVmR1hMb09NMm1wcElDc05qVk9mT1NEM2pXS3BjQk11bDBRMjJZMGFoaXlKWDlFcnZkSEcwV0RMcXI0RXc5TGFqVVNydFovaGNqR1ZIemhZZCs1YklYSXp6ZWlmbUF6Snp4WFM4cmhjNGVoV25OYTJ3PT08L1NpZ25hdHVyZVZhbHVlPjxLZXlJbmZvPjxYNTA5RGF0YT48WDUwOUNlcnRpZmljYXRlPk1JSURvekNDQW91Z0F3SUJBZ0lKQUtOc21MOFFiZnB3TUEwR0NTcUdTSWIzRFFFQkN3VUFNR2d4Q3pBSkJnTlZCQVlUQWtoTE1SSXdFQVlEVlFRSURBbEliMjVuSUV0dmJtY3hDekFKQmdOVkJBY01Ba2hMTVJNd0VRWURWUVFLREFwdWIyUmxMWE5oYld3eU1TTXdJUVlKS29aSWh2Y05BUWtCRmhSdWIyUmxMbk5oYld3eVFHZHRZV2xzTG1OdmJUQWVGdzB4TlRBM01EVXhOelUyTkRkYUZ3MHhPREEzTURReE56VTJORGRhTUdneEN6QUpCZ05WQkFZVEFraExNUkl3RUFZRFZRUUlEQWxJYjI1bklFdHZibWN4Q3pBSkJnTlZCQWNNQWtoTE1STXdFUVlEVlFRS0RBcHViMlJsTFhOaGJXd3lNU013SVFZSktvWklodmNOQVFrQkZoUnViMlJsTG5OaGJXd3lRR2R0WVdsc0xtTnZiVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFNUUpBQjhKcnNMUWJVdUphOGFrekxxTzFFWnFDbFMwdFFwK3crNXdndWZwMDdXd0duL3NobWE4ZGNRTmoxZGJqc3pJNUhCZVZGak9LSXhsZmptTkI5b3ZoUVBzdEJqUC9VUFFZcDFJcDJJb0hDWVg5SERnTXozeHlYS2JIdGhVelphRUN6K3ArN1d0Z3doY3pSa0JMRE9tMmsxNXFoUFlHUHcwdkgyemJWUkdXVUJTOWR5Mk1wM3RxbFZiUDB4WjlDRE5raENKa1Y5U01OZm9DVlcvVllQcUsyUUJvN2tpNG9ibTV4NWl4RlFTU0hzS2JWQVJWenlRSDVpTmpGZTFUZEFwM3JEd3JFNUxjMU5RbFFheFI1R25iMk5aQXBET1JSWklWbE52MldVZGk5UXZNMHlDempROTBqUDBPQW9nSGhSWWF4ZzAvdmdORXllNDZoK1BpWTBDQXdFQUFhTlFNRTR3SFFZRFZSME9CQllFRkVWa2pjTEFJVG5ka3kwOTBBeTc0UXFDbVFLSU1COEdBMVVkSXdRWU1CYUFGRVZramNMQUlUbmRreTA5MEF5NzRRcUNtUUtJTUF3R0ExVWRFd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBRzRsWVgzS1FYZW5lejRMcERuWmhjRkJFWmk5WXN0VUtQRjVFS2QrV3BscFZiY1RRYzFBMy9aK3VIUm15VjhoK3BRemVGNkxpb2IzN0c4N1lwYWNQcGxKSTY2Y2YyUmo3ajhoU0JOYmRyKzY2RTJxcGNFaEFGMWlKbXpCTnloYi95ZGxFdVZwbjgvRXNvUCtIdkJlaURsNWdvbjM1NjJNelpJZ1YvcExkVGZ4SHlXNmh6QVFoakdxMlVoY3ZSK2dYTlZKdkhQMmVTNGpsSG5Ka0I5YmZvMGt2Zjg3UStENlhLWDNxNWMzbU84dHFXNlVwcUhTQyt1TEVwelppTkxldUZhNFRVSWhnQmdqRGpsUnJOREt1OG5kYW5jU24zeUJIWW5xSjJ0OWNSK2NvRm5uallBQlFwTnJ2azRtdG1YWThTWG9CellHOVkrbHFlQXVuNiswWXlFPTwvWDUwOUNlcnRpZmljYXRlPjwvWDUwOURhdGE+PC9LZXlJbmZvPjwvU2lnbmF0dXJlPjwvc2FtbHA6QXV0aG5SZXF1ZXN0Pg==';
  var dummySignRequestSHA512 = 'PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iXzgwOTcwN2YwMDMwYTVkMDA2MjBjOWQ5ZGY5N2Y2MjdhZmU5ZGNjMjQiIFZlcnNpb249IjIuMCIgUHJvdmlkZXJOYW1lPSJTUCB0ZXN0IiBJc3N1ZUluc3RhbnQ9IjIwMTQtMDctMTZUMjM6NTI6NDVaIiBEZXN0aW5hdGlvbj0iaHR0cDovL2lkcC5leGFtcGxlLmNvbS9TU09TZXJ2aWNlLnBocCIgUHJvdG9jb2xCaW5kaW5nPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YmluZGluZ3M6SFRUUC1QT1NUIiBBc3NlcnRpb25Db25zdW1lclNlcnZpY2VVUkw9Imh0dHBzOi8vc3AuZXhhbXBsZS5vcmcvc3Avc3NvIj48c2FtbDpJc3N1ZXIgSWQ9Il8wIj5odHRwczovL3NwLmV4YW1wbGUub3JnL21ldGFkYXRhPC9zYW1sOklzc3Vlcj48c2FtbHA6TmFtZUlEUG9saWN5IEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIiBBbGxvd0NyZWF0ZT0idHJ1ZSIvPjxzYW1scDpSZXF1ZXN0ZWRBdXRobkNvbnRleHQgQ29tcGFyaXNvbj0iZXhhY3QiPjxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbHA6UmVxdWVzdGVkQXV0aG5Db250ZXh0PjxTaWduYXR1cmUgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxTaWduZWRJbmZvPjxDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PFNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGE1MTIiLz48UmVmZXJlbmNlIFVSST0iI18wIj48VHJhbnNmb3Jtcz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9UcmFuc2Zvcm1zPjxEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGE1MTIiLz48RGlnZXN0VmFsdWU+RWN3emlpSzZmazFNK2RETkpHNVlFeWpGY3Fjc0dzRmZNNGFDUkJKcENWTlltVWs4NWJxQk8rblRFN3RmRnd5Uk1yOUZBODBpSnN3MlFwM3R4QTE1Q2c9PTwvRGlnZXN0VmFsdWU+PC9SZWZlcmVuY2U+PC9TaWduZWRJbmZvPjxTaWduYXR1cmVWYWx1ZT5MVmFYajQ3MlZEalBvQU1hZ1BNcEswdGwvckV1c2llVXc4SXZrVVJmVVJDKzl1YXNqRXgxZjR4S1dkYUJLa09zQUhIZ1RMVlpxUnBNY1RBVnJTWDM5SnN1TmRDZnlycXBZTWlBY0w0RXhTM3dOSXdBenFCY1RiUlgxdEY2Nzk5cENYVXVOTE84NVdyN3FwZG5RTnFkTWc1L0E5a0xzUjFSc2dOeFhtandPM1dKUDhucFJ5dXYrVjJvNXhvN01FOVYyaVE4ODRhWVhnNUJodWQ5S1huSU5TZWw5YjN2NnV6T3V2VlFSM1ZCTlFWUXhRaGNUNlFpZ1BkR1hqZDl0cEU4TXV0UG5ZS1NNbHJKc1Ird2wzV2ZacmhwQ2E4U2JGS0RjNnBja1lmVUJYV3pRVVFJVkpXRm5icXBlemJsSUk2NmtlNlRvSzVseVpiajRSajFEcytjMHc9PTwvU2lnbmF0dXJlVmFsdWU+PEtleUluZm8+PFg1MDlEYXRhPjxYNTA5Q2VydGlmaWNhdGU+TUlJRG96Q0NBb3VnQXdJQkFnSUpBS05zbUw4UWJmcHdNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1HZ3hDekFKQmdOVkJBWVRBa2hMTVJJd0VBWURWUVFJREFsSWIyNW5JRXR2Ym1jeEN6QUpCZ05WQkFjTUFraExNUk13RVFZRFZRUUtEQXB1YjJSbExYTmhiV3d5TVNNd0lRWUpLb1pJaHZjTkFRa0JGaFJ1YjJSbExuTmhiV3d5UUdkdFlXbHNMbU52YlRBZUZ3MHhOVEEzTURVeE56VTJORGRhRncweE9EQTNNRFF4TnpVMk5EZGFNR2d4Q3pBSkJnTlZCQVlUQWtoTE1SSXdFQVlEVlFRSURBbEliMjVuSUV0dmJtY3hDekFKQmdOVkJBY01Ba2hMTVJNd0VRWURWUVFLREFwdWIyUmxMWE5oYld3eU1TTXdJUVlKS29aSWh2Y05BUWtCRmhSdWIyUmxMbk5oYld3eVFHZHRZV2xzTG1OdmJUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU1RSkFCOEpyc0xRYlV1SmE4YWt6THFPMUVacUNsUzB0UXArdys1d2d1ZnAwN1d3R24vc2htYThkY1FOajFkYmpzekk1SEJlVkZqT0tJeGxmam1OQjlvdmhRUHN0QmpQL1VQUVlwMUlwMklvSENZWDlIRGdNejN4eVhLYkh0aFV6WmFFQ3orcCs3V3Rnd2hjelJrQkxET20yazE1cWhQWUdQdzB2SDJ6YlZSR1dVQlM5ZHkyTXAzdHFsVmJQMHhaOUNETmtoQ0prVjlTTU5mb0NWVy9WWVBxSzJRQm83a2k0b2JtNXg1aXhGUVNTSHNLYlZBUlZ6eVFINWlOakZlMVRkQXAzckR3ckU1TGMxTlFsUWF4UjVHbmIyTlpBcERPUlJaSVZsTnYyV1VkaTlRdk0weUN6alE5MGpQME9Bb2dIaFJZYXhnMC92Z05FeWU0NmgrUGlZMENBd0VBQWFOUU1FNHdIUVlEVlIwT0JCWUVGRVZramNMQUlUbmRreTA5MEF5NzRRcUNtUUtJTUI4R0ExVWRJd1FZTUJhQUZFVmtqY0xBSVRuZGt5MDkwQXk3NFFxQ21RS0lNQXdHQTFVZEV3UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFHNGxZWDNLUVhlbmV6NExwRG5aaGNGQkVaaTlZc3RVS1BGNUVLZCtXcGxwVmJjVFFjMUEzL1ordUhSbXlWOGgrcFF6ZUY2TGlvYjM3Rzg3WXBhY1BwbEpJNjZjZjJSajdqOGhTQk5iZHIrNjZFMnFwY0VoQUYxaUptekJOeWhiL3lkbEV1VnBuOC9Fc29QK0h2QmVpRGw1Z29uMzU2Mk16WklnVi9wTGRUZnhIeVc2aHpBUWhqR3EyVWhjdlIrZ1hOVkp2SFAyZVM0amxIbkprQjliZm8wa3ZmODdRK0Q2WEtYM3E1YzNtTzh0cVc2VXBxSFNDK3VMRXB6WmlOTGV1RmE0VFVJaGdCZ2pEamxSck5ES3U4bmRhbmNTbjN5QkhZbnFKMnQ5Y1IrY29Gbm5qWUFCUXBOcnZrNG10bVhZOFNYb0J6WUc5WStscWVBdW42KzBZeUU9PC9YNTA5Q2VydGlmaWNhdGU+PC9YNTA5RGF0YT48L0tleUluZm8+PC9TaWduYXR1cmU+PC9zYW1scDpBdXRoblJlcXVlc3Q+';

  describe('2.1 construct a SAML message signature', function () {
    it('RSA-SHA1', function (done) {
      (SamlLib.constructMessageSignature(octetString, _spPrivPem, _spPrivKeyPass).toString('base64')).should.be.equal(signatureB64SHA1);
      done();
    });
    it('RSA-SHA256', function (done) {
      (SamlLib.constructMessageSignature(octetStringSHA256, _spPrivPem, _spPrivKeyPass, null, signatureAlgorithms.RSA_SHA256).toString('base64')).should.be.equal(signatureB64SHA256);
      done();
    });
    it('RSA-SHA512', function (done) {
      (SamlLib.constructMessageSignature(octetStringSHA512, _spPrivPem, _spPrivKeyPass, null, signatureAlgorithms.RSA_SHA256).toString('base64')).should.be.equal(signatureB64SHA512);
      done();
    });
  });
  describe('2.2 verify a SAML message signature (binary)', function () {
    it('RSA-SHA1', function (done) {
      var signature = SamlLib.constructMessageSignature(octetString, _spPrivPem, _spPrivKeyPass, false);
      (SamlLib.verifyMessageSignature(SPMetadata, octetString, signature)).should.be.equal(true);
      done();
    });
    it('RSA-SHA256', function (done) {
      var signature = SamlLib.constructMessageSignature(octetStringSHA256, _spPrivPem, _spPrivKeyPass, false, signatureAlgorithms.RSA_SHA256);
      (SamlLib.verifyMessageSignature(SPMetadata, octetStringSHA256, signature, signatureAlgorithms.RSA_SHA256)).should.be.equal(true);
      done();
    });
    it('RSA-SHA512', function (done) {
      var signature = SamlLib.constructMessageSignature(octetStringSHA512, _spPrivPem, _spPrivKeyPass, false, signatureAlgorithms.RSA_SHA512);
      (SamlLib.verifyMessageSignature(SPMetadata, octetStringSHA512, signature, signatureAlgorithms.RSA_SHA512)).should.be.equal(true);
      done();
    });
  });
  describe('2.3 verify a SAML message signature (string)', function () {
    it('RSA-SHA1', function (done) {
      var signature = SamlLib.constructMessageSignature(octetString, _spPrivPem, _spPrivKeyPass);
      (SamlLib.verifyMessageSignature(SPMetadata, octetString, new Buffer(signature, 'base64'))).should.be.equal(true);
      done();
    });
    it('RSA-SHA256', function (done) {
      var signature = SamlLib.constructMessageSignature(octetStringSHA256, _spPrivPem, _spPrivKeyPass);
      (SamlLib.verifyMessageSignature(SPMetadata, octetStringSHA256, new Buffer(signature, 'base64'))).should.be.equal(true);
      done();
    });
    it('RSA-SHA512', function (done) {
      var signature = SamlLib.constructMessageSignature(octetStringSHA512, _spPrivPem, _spPrivKeyPass);
      (SamlLib.verifyMessageSignature(SPMetadata, octetStringSHA512, new Buffer(signature, 'base64'))).should.be.equal(true);
      done();
    });
  });
  describe('2.4 construct a SAML signature successfully', function () {
    it('RSA-SHA1', function (done) {
      //fs.writeFileSync('test.txt',SamlLib.constructSAMLSignature(_originRequest,SamlLib.createXPath('Issuer'),SPMetadata.getX509Certificate('signing'),_spPrivPem,_spPrivKeyPass,signatureAlgorithms.RSA_SHA256));
      (SamlLib.constructSAMLSignature(_originRequest, SamlLib.createXPath('Issuer'), SPMetadata.getX509Certificate('signing'), _spPrivPem, _spPrivKeyPass, signatureAlgorithms.RSA_SHA1)).should.be.equal(dummySignRequest);
      done();
    });
    it('RSA-SHA256', function (done) {
      //fs.writeFileSync('test.txt',SamlLib.constructSAMLSignature(_originResponse,SamlLib.createXPath('Assertion'),SPMetadata.getX509Certificate('signing'),_spPrivPem,_spPrivKeyPass,signatureAlgorithms.RSA_SHA256));
      (SamlLib.constructSAMLSignature(_originRequest, SamlLib.createXPath('Issuer'), SPMetadata.getX509Certificate('signing'), _spPrivPem, _spPrivKeyPass, signatureAlgorithms.RSA_SHA256)).should.be.equal(dummySignRequestSHA256);
      done();
    });
    it('RSA-SHA512', function (done) {
      //fs.writeFileSync('test.txt',SamlLib.constructSAMLSignature(_originRequest,SamlLib.createXPath('Issuer'),SPMetadata.getX509Certificate('signing'),_spPrivPem,_spPrivKeyPass,signatureAlgorithms.RSA_SHA512));
      (SamlLib.constructSAMLSignature(_originRequest, SamlLib.createXPath('Issuer'), SPMetadata.getX509Certificate('signing'), _spPrivPem, _spPrivKeyPass, signatureAlgorithms.RSA_SHA512)).should.be.equal(dummySignRequestSHA512);
      done();
    });
  });
  describe('2.5 verify a XML signature from sample using metadata', function () {
    it('RSA-SHA1', function (done) {
      (SamlLib.verifySignature(_decodedResponse, _decodedResponseSignature, {
        cert: IdPMetadata
      })).should.be.equal(true);
      done();
    });
    it('RSA-SHA256', function (done) {
      (SamlLib.verifySignature(_decodedRequestSHA256, _decodedRequestSignatureSHA256, {
        cert: SPMetadata,
        signatureAlgorithm: signatureAlgorithms.RSA_SHA256
      })).should.be.equal(true);
      done();
    });
    it('RSA-SHA512', function (done) {
      (SamlLib.verifySignature(_decodedRequestSHA512, _decodedRequestSignatureSHA512, {
        cert: SPMetadata,
        signatureAlgorithm: signatureAlgorithms.RSA_SHA512
      })).should.be.equal(true);
      done();
    });
  });
  describe('2.6 verify a XML signature from sample using keyFile (.cer)', function () {
    it('RSA-SHA1', function (done) {
      var xml = fs.readFileSync("./test/metadata/SignSAMLRequest.xml").toString();
      var _decodedResponseDoc = new dom().parseFromString(xml);
      var signature = select(_decodedResponseDoc, "/*/*[local-name(.)='Signature']")[0];
      (SamlLib.verifySignature(xml, signature, {
        keyFile: './test/key/sp/cert.cer'
      })).should.be.equal(true);
      done();
    });
    it('RSA-SHA256', function (done) {
      var xml = fs.readFileSync("./test/metadata/SignSAMLRequestSHA256.xml").toString();
      var _decodedResponseDoc = new dom().parseFromString(xml);
      var signature = select(_decodedResponseDoc, "/*/*[local-name(.)='Signature']")[0];
      (SamlLib.verifySignature(xml, signature, {
        keyFile: './test/key/sp/cert.cer'
      })).should.be.equal(true);
      done();
    });
    it('RSA-SHA512', function (done) {
      var xml = fs.readFileSync("./test/metadata/SignSAMLRequestSHA512.xml").toString();
      var _decodedResponseDoc = new dom().parseFromString(xml);
      var signature = select(_decodedResponseDoc, "/*/*[local-name(.)='Signature']")[0];
      (SamlLib.verifySignature(xml, signature, {
        keyFile: './test/key/sp/cert.cer'
      })).should.be.equal(true);
      done();
    });
  });
  describe('2.7 High-level extractor', function () {
    describe('2.7.1 get innerText', function () {
      it('should return a value', function (done) {
        (SamlLib.extractor(_decodedResponse, ['NameID']).nameid).should.be.equal('_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7');
        done();
      });
      it('should return undefined', function (done) {
        (SamlLib.extractor(_decodedResponse, ['notexist']).notexist === undefined).should.equal(true);
        done();
      });
      it('should return an array of values', function (done) {
        (JSON.stringify(SamlLib.extractor(_decodedResponse, ['AttributeValue']))).should.equal(JSON.stringify({
          attributevalue: ["test", "test@example.com", "users", "examplerole1"]
        }));
        done();
      });
      it('using custom key', function (done) {
        (SamlLib.extractor(_decodedResponse, [{
          localName: 'NameID',
          customKey: 'nid'
        }]).nid).should.equal('_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7');
        done();
      });
    });
    describe('2.7.2 get attributes', function () {
      it('should return an Object', function (done) {
        (JSON.stringify(SamlLib.extractor(_decodedResponse, [{
          localName: 'Conditions',
          attributes: ['NotBefore', 'NotOnOrAfter']
        }]))).should.be.equal(JSON.stringify({
          conditions: {
            notbefore: "2014-07-17T01:01:18Z",
            notonorafter: "2024-01-18T06:21:48Z"
          }
        }));
        done();
      });
      it('should return an array of Objects', function (done) {
        (JSON.stringify(SamlLib.extractor(_decodedResponse, [{
          localName: 'Attribute',
          attributes: ['Name', 'NameFormat']
        }]).attribute)).should.be.equal(JSON.stringify([{
          name: "uid",
          nameformat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
        }, {
          name: "mail",
          nameformat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
        }, {
          name: "eduPersonAffiliation",
          nameformat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
        }]));
        done();
      });
      it('non-exist attribute should return undefined', function (done) {
        (SamlLib.extractor(_decodedResponse, [{
          localName: 'Conditions',
          attributes: ['notexist']
        }]).conditions.notexist === undefined).should.be.equal(true);
        done();
      });
      it('non-exist localName should return undefined', function (done) {
        (SamlLib.extractor(_decodedResponse, [{
          localName: 'Condition',
          attributes: ['notexist']
        }]).condition === undefined).should.be.equal(true);
        done();
      });
      it('using custom key', function (done) {
        (SamlLib.extractor(_decodedResponse, [{
          localName: 'Conditions',
          attributes: ['notexist'],
          customKey: 'cd'
        }]).cd.notexist === undefined).should.be.equal(true);
        done();
      });
    });
    describe('2.7.3 get entire text', function () {
      it('should return a XML string', function (done) {
        (JSON.stringify(SamlLib.extractor(_decodedResponse, [{
          localName: 'Signature',
          extractEntireBody: true
        }]).signature)).should.be.equal(JSON.stringify("<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"#_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>upUaQyNo8KYfaugAsM9I6e/HYNQ=</DigestValue></Reference></SignedInfo><SignatureValue>T3eM5SxwxP8wH+w1jxH/YezcsC03xU0N19uEggWbL//adCbdvPEWqnYDRlRi6HqdfLTAxqt0LqXzy4Sx2Sj/G3dKA1fTu8qZueqg1oTdKIHEO7BKQlWj+vhsxP4RJwOaooZ195Ez0DsqBjIYM8O+hrmGCpKoJNz7ZaASDhnBBqg4UyilA/VXwP2Wq/LwXdQQ+SfgbtmqxfrcqRQtN87aL3YdPFoS4oR6Q8d97g+YiSbsSvTrxfU5vDEo1tRKxvAQXDDxRBral9kELhqcd3Aumcr9zPF00KxkYIAKtyWd5RsWgOcfbiEQpCit0vh74Y1HplLhzeLhPI/RrLB5gSI4DA==</SignatureValue></Signature>"));
        done();
      });
      it('should return undefined', function (done) {
        (SamlLib.extractor(_decodedResponse, [{
          localName: 'Not Exist',
          extractEntireBody: true
        }]).signature === undefined).should.be.equal(true);
        done();
      });
      it('using custom key', function (done) {
        (JSON.stringify(SamlLib.extractor(_decodedResponse, [{
          localName: 'Signature',
          extractEntireBody: true,
          customKey: 'cd'
        }]).cd)).should.be.equal(JSON.stringify("<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"#_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>upUaQyNo8KYfaugAsM9I6e/HYNQ=</DigestValue></Reference></SignedInfo><SignatureValue>T3eM5SxwxP8wH+w1jxH/YezcsC03xU0N19uEggWbL//adCbdvPEWqnYDRlRi6HqdfLTAxqt0LqXzy4Sx2Sj/G3dKA1fTu8qZueqg1oTdKIHEO7BKQlWj+vhsxP4RJwOaooZ195Ez0DsqBjIYM8O+hrmGCpKoJNz7ZaASDhnBBqg4UyilA/VXwP2Wq/LwXdQQ+SfgbtmqxfrcqRQtN87aL3YdPFoS4oR6Q8d97g+YiSbsSvTrxfU5vDEo1tRKxvAQXDDxRBral9kELhqcd3Aumcr9zPF00KxkYIAKtyWd5RsWgOcfbiEQpCit0vh74Y1HplLhzeLhPI/RrLB5gSI4DA==</SignatureValue></Signature>"));
        done();
      });
    });
    describe('2.7.4 get key-value pair, attribute value as key, innerText as value', function () {
      it('single value should return string', function (done) {
        (JSON.stringify(SamlLib.extractor(SPMetadata.xmlString, [{
          localName: {
            tag: 'KeyDescriptor',
            key: 'use'
          },
          valueTag: 'X509Certificate'
        }]))).should.be.equal('{"keydescriptor":{"signing":"MIIDozCCAougAwIBAgIJAKNsmL8QbfpwMA0GCSqGSIb3DQEBCwUAMGgxCzAJBgNVBAYTAkhLMRIwEAYDVQQIDAlIb25nIEtvbmcxCzAJBgNVBAcMAkhLMRMwEQYDVQQKDApub2RlLXNhbWwyMSMwIQYJKoZIhvcNAQkBFhRub2RlLnNhbWwyQGdtYWlsLmNvbTAeFw0xNTA3MDUxNzU2NDdaFw0xODA3MDQxNzU2NDdaMGgxCzAJBgNVBAYTAkhLMRIwEAYDVQQIDAlIb25nIEtvbmcxCzAJBgNVBAcMAkhLMRMwEQYDVQQKDApub2RlLXNhbWwyMSMwIQYJKoZIhvcNAQkBFhRub2RlLnNhbWwyQGdtYWlsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQJAB8JrsLQbUuJa8akzLqO1EZqClS0tQp+w+5wgufp07WwGn/shma8dcQNj1dbjszI5HBeVFjOKIxlfjmNB9ovhQPstBjP/UPQYp1Ip2IoHCYX9HDgMz3xyXKbHthUzZaECz+p+7WtgwhczRkBLDOm2k15qhPYGPw0vH2zbVRGWUBS9dy2Mp3tqlVbP0xZ9CDNkhCJkV9SMNfoCVW/VYPqK2QBo7ki4obm5x5ixFQSSHsKbVARVzyQH5iNjFe1TdAp3rDwrE5Lc1NQlQaxR5Gnb2NZApDORRZIVlNv2WUdi9QvM0yCzjQ90jP0OAogHhRYaxg0/vgNEye46h+PiY0CAwEAAaNQME4wHQYDVR0OBBYEFEVkjcLAITndky090Ay74QqCmQKIMB8GA1UdIwQYMBaAFEVkjcLAITndky090Ay74QqCmQKIMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAG4lYX3KQXenez4LpDnZhcFBEZi9YstUKPF5EKd+WplpVbcTQc1A3/Z+uHRmyV8h+pQzeF6Liob37G87YpacPplJI66cf2Rj7j8hSBNbdr+66E2qpcEhAF1iJmzBNyhb/ydlEuVpn8/EsoP+HvBeiDl5gon3562MzZIgV/pLdTfxHyW6hzAQhjGq2UhcvR+gXNVJvHP2eS4jlHnJkB9bfo0kvf87Q+D6XKX3q5c3mO8tqW6UpqHSC+uLEpzZiNLeuFa4TUIhgBgjDjlRrNDKu8ndancSn3yBHYnqJ2t9cR+coFnnjYABQpNrvk4mtmXY8SXoBzYG9Y+lqeAun6+0YyE=","encryption":"MIID7TCCAtWgAwIBAgIJANSq1uUtXl4DMA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNVBAYTAkhLMRIwEAYDVQQIEwlIb25nIEtvbmcxFjAUBgNVBAoTDWV4cHJlc3Mtc2FtbDIxDDAKBgNVBAsTA2RldjEOMAwGA1UEAxMFZXNhbWwwHhcNMTUxMDAzMDM0ODA2WhcNMTgxMDAyMDM0ODA2WjBXMQswCQYDVQQGEwJISzESMBAGA1UECBMJSG9uZyBLb25nMRYwFAYDVQQKEw1leHByZXNzLXNhbWwyMQwwCgYDVQQLEwNkZXYxDjAMBgNVBAMTBWVzYW1sMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyx/yIgvJwfOCwMTNjL4Fslr21ky4O/uzxp0Y8wpHk9jk8Afcj3plQCr5X8dPKG2Rz4EIh//nQQL9tq2InaUdRwJkS9SeuuAcJG7DN/KDUtfrh4+cO2lZ4h7cQIdjpbBgpGEMhGy1wwpwHJsadoBuX0PKyT4O4oHkj1gwWO14qYnK4biviNBqmjGjmN+py+lUcACsQt22abA4s8Xjm/tlvnkgNRE3H44ICvSr8m5MVhyYGoAUe7Qprn2BcsMXd9mrlZ5hEdalNUDRbKb+W7mrKEkKFCbE3wi/Ns2bc4fbNXvwcZoF3/TPzl936u2eivTQESjCLsymIqdYHwRiVLifWQIDAQABo4G7MIG4MB0GA1UdDgQWBBSdBiMAVhKrjzd72sncR13imevq/DCBiAYDVR0jBIGAMH6AFJ0GIwBWEquPN3vaydxHXeKZ6+r8oVukWTBXMQswCQYDVQQGEwJISzESMBAGA1UECBMJSG9uZyBLb25nMRYwFAYDVQQKEw1leHByZXNzLXNhbWwyMQwwCgYDVQQLEwNkZXYxDjAMBgNVBAMTBWVzYW1sggkA1KrW5S1eXgMwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEARi25PJOR+x0ytYCmfXwG5LSXKNHx5BD6G+nBgXm1/DMMJ9ZY34FYMF3gDUu+NmQoVegqARTxetQcCICpAPdKnK0yQb6MXdj3VfQnEA+4hVGFmqnHTK90g0BudEmp1fWKBjJYpLd0oncVwJQJDK5OfS7fMUftN6/Kg6/fDuJMCNIECfKRE8tiXz2Ht924MjedKlH0+qoV1F2Fy5as+QRbj/QfrPTrZrfqhP04mavTPL2bdW6+ykeQWN3zMQtJA8kt2LI0y0CIGhFjLbqAceq+gDkp4drj7/Yw8qaqmxl6GP8w3GbfLu6mXCjCLCGgsATktvWq9dRfBuapaIpNDrv0NA=="}}');
        done();
      });
      it('multiple values should return array consists of multiple string', function (done) {
        (JSON.stringify(SamlLib.extractor(_decodedResponse, [{
          localName: {
            tag: 'Attribute',
            key: 'Name'
          },
          valueTag: 'AttributeValue'
        }]))).should.be.equal('{"attribute":{"uid":"test","mail":"test@example.com","eduPersonAffiliation":["users","examplerole1"]}}');
        done();
      });
      it('non-exist key should return undefined', function (done) {
        (JSON.stringify(SamlLib.extractor(SPMetadata.xmlString, [{
          localName: {
            tag: 'KeyDescriptor',
            key: 'used'
          },
          valueTag: 'X509Certificate'
        }])).keydescriptor === undefined).should.be.equal(true);
        done();
      });
      it('non-exist value should return undefined', function (done) {
        (JSON.stringify(SamlLib.extractor(SPMetadata.xmlString, [{
          localName: {
            tag: 'KeyDescriptor',
            key: 'use'
          },
          valueTag: 'X123Certificate'
        }])).keydescriptor === undefined).should.be.equal(true);
        done();
      });
      it('non-exist tag should return undefined', function (done) {
        (JSON.stringify(SamlLib.extractor(SPMetadata.xmlString, [{
          localName: {
            tag: 'KeyDescription',
            key: 'encrypt'
          },
          valueTag: 'X509Certificate'
        }])).keydescriptor === undefined).should.be.equal(true);
        done();
      });
      it('using custom key', function (done) {
        (JSON.stringify(SamlLib.extractor(_decodedResponse, [{
          localName: {
            tag: 'Attribute',
            key: 'Name'
          },
          valueTag: 'AttributeValue',
          customKey: 'kd'
        }]).kd)).should.be.equal('{"uid":"test","mail":"test@example.com","eduPersonAffiliation":["users","examplerole1"]}');
        done();
      });
    });
    describe('2.7.5 get key-value pair, attribute as key, attribute as value', function () {
      it('single value should return array consists of one object', function (done) {
        (JSON.stringify(SamlLib.extractor(SPMetadata.xmlString, [{
          localName: {
            tag: 'AssertionConsumerService',
            key: 'isDefault'
          },
          attributeTag: 'index'
        }]).assertionconsumerservice)).should.be.equal('[{"true":"0"}]');
        done();
      });
      it('multiple values should return array consists of multiple objects', function (done) {
        (JSON.stringify(SamlLib.extractor(SPMetadata.xmlString, [{
          localName: {
            tag: 'SingleLogoutService',
            key: 'Binding'
          },
          attributeTag: 'Location'
        }]).singlelogoutservice)).should.be.equal('[{"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect":"https://sp.example.org/sp/slo"},{"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":"https://sp.example.org/sp/slo"}]');
        done();
      });
      it('non-exist tag should return undefined', function (done) {
        (JSON.stringify(SamlLib.extractor(SPMetadata.xmlString, [{
          localName: {
            tag: 'SingleLogoutServices',
            key: 'Binding'
          },
          attributeTag: 'Location'
        }])).singlelogoutservice === undefined).should.be.equal(true);
        done();
      });
      it('non-exist key should return undefined', function (done) {
        (JSON.stringify(SamlLib.extractor(SPMetadata.xmlString, [{
          localName: {
            tag: 'SingleLogoutService',
            key: 'Winding'
          },
          attributeTag: 'Location'
        }])).singlelogoutservice === undefined).should.be.equal(true);
        done();
      });
      it('non-exist attributeTag should return undefined', function (done) {
        (JSON.stringify(SamlLib.extractor(SPMetadata.xmlString, [{
          localName: {
            tag: 'SingleLogoutService',
            key: 'Binding'
          },
          attributeTag: 'NoSuchLocation'
        }])).singlelogoutservice === undefined).should.be.equal(true);
        done();
      });
      it('using custom key', function (done) {
        (JSON.stringify(SamlLib.extractor(SPMetadata.xmlString, [{
          localName: {
            tag: 'SingleLogoutService',
            key: 'Binding'
          },
          attributeTag: 'Location',
          customKey: 'slo'
        }]).slo)).should.be.equal('[{"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect":"https://sp.example.org/sp/slo"},{"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":"https://sp.example.org/sp/slo"}]');
        done();
      });
    });
  });
  describe('2.8 encrypt assertion', function () {
    it('simple test should be passed', function (done) {
      SamlLib.encryptAssertion(idp, sp, sampleSignedResponse, function (res) {
        done();
      });
    });
    it('response without assertion should return error', function (done) {
      try {
        SamlLib.encryptAssertion(idp, sp, wrongResponse, function (res) {
          throw new Error('False-Positive')
        });
      } catch (err) {
        (err.message.toString()).should.be.equal('Undefined assertion or invalid syntax');
        done();
      }
    });
    it('invalid xml syntax should return error', function (done) {
      try {
        SamlLib.encryptAssertion(idp, sp, 'This is not a xml format string', function (res) {
          throw new Error('False-Positive')
        });
      } catch (err) {
        (err.message.toString()).should.be.equal('Undefined assertion or invalid syntax');
        done();
      }
    });
    it('empty string should return error', function (done) {
      try {
        SamlLib.encryptAssertion(idp, sp, '', function (res) {
          throw new Error('False-Positive')
        });
      } catch (err) {
        (err.message.toString()).should.be.equal('Empty or undefined xml string');
        done();
      }
    });
    it('undefined string should return error', function (done) {
      try {
        SamlLib.encryptAssertion(idp, sp, undefined, function (res) {
          throw new Error('False-Positive')
        });
      } catch (err) {
        (err.message.toString()).should.be.equal('Empty or undefined xml string');
        done();
      }
    });
  });
  describe('2.9 decrpyt assertion', function () {
    var signEncryptSAMLResponse = fs.readFileSync('./test/metadata/SignEncryptSAMLResponse.xml').toString();
    it('simple test should be passed', function (done) {
      SamlLib.decryptAssertion('SAMLResponse', sp, idp, signEncryptSAMLResponse, function (res) {
        done();
      });
    });
  });
  describe('2.10 parse query parameter for sso/slo', function () {
    var getQueryParamByType = SamlLib.getQueryParamByType;
    it('should return SamlRequest', function (done) {
      getQueryParamByType('SAMLRequest').should.be.equal(wording.urlParams.samlRequest);
      getQueryParamByType('LogoutRequest').should.be.equal(wording.urlParams.samlRequest);
      done();
    });
    it('should return SamlResponse', function (done) {
      getQueryParamByType('SAMLResponse').should.be.equal(wording.urlParams.samlResponse);
      getQueryParamByType('LogoutResponse').should.be.equal(wording.urlParams.samlResponse);
      done();
    });
    it('should return error for undefined query parameter', function (done) {
      try {
        getQueryParamByType('samlRequest');
      } catch (e) {
        done();
      }
    });
  });
});

describe('3 Constant.js', function () {
  var entry = require('../build/index');
  var constants = entry.Constants;
  it('constants should be exported', function (done) {
    if (typeof constants === 'object') done();
  });
});

describe('4 ServiceProvider.js', function () {
  describe('4.1 SPMetadata.js', function () {
    it('getAssertionConsumerService with one binding', function (done) {
      var expectedPostLocation = 'https://sp.example.org/sp/sso/post';
      var sp = entry.ServiceProvider({
        privateKeyFile: './test/key/sp/privkey.pem',
        privateKeyFilePass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
        isAssertionEncrypted: true, // for logout purpose
        encPrivateKeyFile: './test/key/sp/encryptKey.pem',
        encPrivateKeyFilePass: 'BXFNKpxrsjrCkGA8cAu5wUVHOSpci1RU',
        assertionConsumerService: [{
          Binding: binding.post,
          Location: expectedPostLocation
        }],
        singleLogoutService: [{
          Binding: binding.redirect,
          Location: 'https://sp.example.org/sp/slo'
        }]
      });
      sp.entityMeta.getAssertionConsumerService(wording.binding.post).should.be.equal(expectedPostLocation);
      done();
    });
    it('getAssertionConsumerService with two bindings', function (done) {
      var expectedPostLocation = 'https://sp.example.org/sp/sso/post';
      var expectedArtifactLocation = 'https://sp.example.org/sp/sso/artifact';
      var sp = entry.ServiceProvider({
        privateKeyFile: './test/key/sp/privkey.pem',
        privateKeyFilePass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
        isAssertionEncrypted: true, // for logout purpose
        encPrivateKeyFile: './test/key/sp/encryptKey.pem',
        encPrivateKeyFilePass: 'BXFNKpxrsjrCkGA8cAu5wUVHOSpci1RU',
        assertionConsumerService: [{
          Binding: binding.post,
          Location: expectedPostLocation
        }, {
          Binding: binding.arifact,
          Location: expectedArtifactLocation
        }],
        singleLogoutService: [{
          Binding: binding.redirect,
          Location: 'https://sp.example.org/sp/slo'
        }, {
          Binding: binding.post,
          Location: 'https://sp.example.org/sp/slo'
        }]
      });
      sp.entityMeta.getAssertionConsumerService(wording.binding.post).should.be.equal(expectedPostLocation);
      sp.entityMeta.getAssertionConsumerService(wording.binding.arifact).should.be.equal(expectedArtifactLocation);
      done();
    });
  })
});
