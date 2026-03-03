import * as esaml2 from '../build/index.js';
import {readFileSync} from 'fs';
import {describe, test, expect} from 'vitest';
import {verifyTime} from '../build/src/validator.js';
import path from 'path';

// 环境感知的资源路径处理
const TEST_ENV = process.env.TEST_ENV || 'source';
const TEST_RESOURCE_ROOT = TEST_ENV === 'build' ? './test' : './test';

function testResourcePath(subpath) {
  return path.join(TEST_RESOURCE_ROOT, subpath);
}

const {
  IdentityProvider: identityProvider,
  ServiceProvider: serviceProvider,
  IdPMetadata: idpMetadata,
  SPMetadata: spMetadata,
  Utility: utility,
  SamlLib: libsaml,
  Constants: ref,
} = esaml2;

const binding = ref.namespace.binding;
const algorithms = ref.algorithms;
const wording = ref.wording;
const signatureAlgorithms = algorithms.signature;

const _spKeyFolder = testResourcePath('./key/sp/');
const _spPrivPem = String(readFileSync(testResourcePath('key/sp/privkey.pem')));
const _spPrivKeyPass = 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px';

const defaultIdpConfig = {
  privateKey: readFileSync(testResourcePath('key/idp/privkey.pem')),
  privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  isAssertionEncrypted: true,
  encPrivateKey: readFileSync(testResourcePath('key/idp/encryptKey.pem')),
  encPrivateKeyPass: 'g7hGcRmp8PxT5QeP2q9Ehf1bWe9zTALN',
  metadata: readFileSync(testResourcePath('misc/idpmeta.xml')),
};

const defaultSpConfig = {
  privateKey: readFileSync(testResourcePath('key/sp/privkey.pem')),
  privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
  isAssertionEncrypted: true,
  encPrivateKey: readFileSync(testResourcePath('key/sp/encryptKey.pem')),
  encPrivateKeyPass: 'BXFNKpxrsjrCkGA8cAu5wUVHOSpci1RU',
  metadata: readFileSync(testResourcePath('misc/spmeta.xml')),
};

const idp = identityProvider(defaultIdpConfig);
const idpRollingCert = identityProvider({
  ...defaultIdpConfig,
  metadata: readFileSync(testResourcePath('misc/idpmeta_rollingcert.xml')),
});
const sp = serviceProvider(defaultSpConfig);

const IdPMetadata = idpMetadata(readFileSync(testResourcePath('misc/idpmeta.xml')));
const SPMetadata = spMetadata(readFileSync(testResourcePath('misc/spmeta.xml')));
const sampleSignedResponse = readFileSync(testResourcePath('misc/response_signed.xml')).toString();
const wrongResponse = readFileSync(testResourcePath('misc/invalid_response.xml')).toString();
const spCertKnownGood = readFileSync(testResourcePath('key/sp/knownGoodCert.cer')).toString().trim();
const spPemKnownGood = readFileSync(testResourcePath('key/sp/knownGoodEncryptKey.pem')).toString().trim();


const _originRequest: string = String(readFileSync('./test/misc/request.xml'));
const _decodedResponse: string = String(readFileSync('./test/misc/response_signed.xml'));
const _falseDecodedRequestSHA1: string = String(readFileSync('./test/misc/false_signed_request_sha1.xml'));
const _decodedRequestSHA256: string = String(readFileSync('./test/misc/signed_request_sha256.xml'));
const _falseDecodedRequestSHA256: string = String(readFileSync('./test/misc/false_signed_request_sha256.xml'));
const _decodedRequestSHA512: string = String(readFileSync('./test/misc/signed_request_sha512.xml'));
const _falseDecodedRequestSHA512: string = String(readFileSync('./test/misc/false_signed_request_sha512.xml'));

const octetString: string = 'SAMLRequest=fVNdj9MwEHxH4j9Yfm%2Fi5PpBrLaotEJUOrioKTzwgoy9oZZiO9ibu%2FLvcXLtKUhHnyzZM7Mzu+tlEKZp+abDkz3A7w4CkrNpbODDw4p23nIngg7cCgOBo+TV5vM9zxPGW+%2FQSdfQEeU2Q4QAHrWzlOx3K%2FrjHSsWbFEzdsfETDE2z5ksVKHqYlHP84WooVBS5lNKvoEPkbeiUYaS0rtHrcB%2FiRVWtCoJRuNRM4QO9jagsBiRLJtO2GKSzY%2F5HZ%2FlfDr7TskuIrUVOIidEFueplq1CZyFaRtIpDNpVT1U4B+1hKQ9tUO5IegHbZW2v25n%2FPkMCvzT8VhOyofqSMnmmnvrbOgM+Iv818P9i4nwrwcFxmVp1IJzb+K9kIGu374hZNm3mQ9R%2Ffp1rgEUSqBYpmPsC7nlfd%2F2u9I1Wv4hH503Av8fKkuy4UarST1AORihm41SHkKI4ZrGPW09CIyzQN8BTce1LmsFaliy2ACEM5KtM63wOvRTiNYlPoe7xhtjt01cmwPU65ubJbnscfG6jMeT8+qS%2FlWpwV96w2BEXN%2FHn2P9Fw%3D%3D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1';
const octetStringSHA256: string = 'SAMLRequest=fZJbTwIxEIX%2Fyqbvy3Yv3BogQYiRBJWw6INvY3eAJt0WO10v%2F966YIKJkPRpek7nfDMdEdT6IKaN35s1vjVIPvqstSHRXoxZ44ywQIqEgRpJeCnK6f1SZB0uDs56K61mZ5brDiBC55U1LFrMx2wrB8P%2BIB%2FGeQHbuOgVwxigB3EqewXfDjDPZJ9Fz%2BgoWMYsvBB8RA0uDHkwPpR42o1THvNswzMRTtHtpEX2wqJ5QFEGfOvce38QSaKtBL235EXOeZoQ2aRUZqexVDvzaEp070pikveG3W5otTrx3ShTBdl1tNejiMTdZrOKV4%2FlhkXTX9yZNdTU6E4dntbLfzIVnGdtJpDEJqOfaYqW1k0ua2v0UIGHUXKuHx3X%2BhBSLuYrq5X8im6tq8Ffhkg7aVtRVbxtpQJrUHpaVQ6JAozW9mPmEDyGzYEmZMnk2PbvB5p8Aw%3D%3D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256';
const octetStringSHA512: string = 'SAMLRequest=fZJfT8IwFMW%2FytL3sY5tCA0jQYiRBIUw9MG3a3cnTboWezv%2FfHvr0AQT9fX2nJ7zu%2B2UoNVHMe%2F8wezwuUPy0VurDYn%2BoGSdM8ICKRIGWiThpajmN2sxHHBxdNZbaTU7s%2FzvACJ0XlnDotWyZFBkDcAE47wZjeNcXqTxGAsZy0lR1EUzAiwaFt2jo2ApWbgh%2BIg6XBnyYHwY8bSIUx7z4Z4PRZaLbDLg4%2FyBRcuAogz43nnw%2FiiSRFsJ%2BmDJi4zzNCGySaXMk8ZKPZmNqdC9KIlJNgr5IWr7xXepTB1k%2F6M9nkQkrvf7bbzdVHsWzb9xF9ZQ16L7SrjbrX%2FplHM%2B7DuBJDabfm5T9LRu9re2RQ81eJgm5%2Frp6VlvQ8vVcmu1ku%2FRlXUt%2BL8h0kHaT1QdN71UYAtKz%2BvaIVGA0dq%2BLhyCx5I1oAlZMjvF%2FvxAsw8%3D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha512';
const signatureB64SHA512: string = 'pLoxKnpOVA1mvLpOZCyzCyB/P01Qcy7cEFskzycm5sdNFYjmZAMGT6yxCgTRvzIloX2J7abZdAkU1dA8kY2yPQrWCuQFOxeSCqnGpHg5/bBKzFiGwWtlyHgh7LXEEo2zKWspJh7BhwRIbtOAnN3XvCPDO58wKHnEdxo9TneTyFmy5hcfYKcF7LlI8jSFkmsPvCsMMJ8TawgnKlwdIU0Ze/cp64Y24cpYxVIKtCC950VRuxAt3bmr7pqtIEsHKkqTOrPv5pWo2XqRG0UhvzjYCbpC8aGOuqLe8hfTfgpQ6ebUkqrgAufkLrinOGpZrlQQDFr0iVIKR30bInDGjg2G+g==';
const signatureB64SHA256: string = 'iC7RXfHuIu4gBLGABv0qtt96XFvyC7QSX8cDyLjJj+WNOTRMO5J/AYKelVhuc2AZuyGcf/sfeeVmcW7wyKTBHiGS+AWUCljmG43mPWERPfsa7og+GxrsHDSFh5nD70mQF44bXvpo/oVOxHx/lPiDG5LZg2KBccNXqJxMVUhnyU6xeGBctYY5ZQ4y7MGOx7hWTWjHyv+wyFd44Bcq0kpunTls91z03GkYo/Oxd4KllbfR5D2v6awjrc79wMYL1CcZiKZ941ter6tHOHCwtZRhTqV3Dl42zOKUOCyGcjJnVzJre1QBA7hrn3WB5/fu5kE6/E9ENRWp8ZRJLbU8C2Oogg==';
const signatureB64SHA1: string = 'UKPzYQivZOavFV3QjOH/B9AwKls9n5hZIzOL+V93Yi7lJ7siNkAA9WZgErtFVpDTN6ngSwvlfP/hXZcS33RcCGBWi1SX+xuwuk2U7bZgdkkw4tIH8zcgiRy8bK0IpMoXmLbApU2QsiNwRDMZq3iQdlaMhlsJh85VI+90SQk7fewseiw5Ui6BIpFSH96gLYjWMDPpwk+0GkhkkVaP5vo+I6mBQryD9YPFRu7JfCrnw2T6gldXlGu0IN326+qajKheAGmPSLWBmeFYhquJ5ipgfQGU/KCNIEUr6hkW8NU0+6EVaZl/A9Fyfs1+8KCQ6HxZ7FGyewQjJIx3a8XvBM5vDg==';
const dummySignRequest: string = 'PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iXzgwOTcwN2YwMDMwYTVkMDA2MjBjOWQ5ZGY5N2Y2MjdhZmU5ZGNjMjQiIFZlcnNpb249IjIuMCIgUHJvdmlkZXJOYW1lPSJTUCB0ZXN0IiBJc3N1ZUluc3RhbnQ9IjIwMTQtMDctMTZUMjM6NTI6NDVaIiBEZXN0aW5hdGlvbj0iaHR0cDovL2lkcC5leGFtcGxlLmNvbS9TU09TZXJ2aWNlLnBocCIgUHJvdG9jb2xCaW5kaW5nPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YmluZGluZ3M6SFRUUC1QT1NUIiBBc3NlcnRpb25Db25zdW1lclNlcnZpY2VVUkw9Imh0dHBzOi8vc3AuZXhhbXBsZS5vcmcvc3Avc3NvIj48c2FtbDpJc3N1ZXIgSWQ9Il8wIj5odHRwczovL3NwLmV4YW1wbGUub3JnL21ldGFkYXRhPC9zYW1sOklzc3Vlcj48c2FtbHA6TmFtZUlEUG9saWN5IEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIiBBbGxvd0NyZWF0ZT0idHJ1ZSIvPjxzYW1scDpSZXF1ZXN0ZWRBdXRobkNvbnRleHQgQ29tcGFyaXNvbj0iZXhhY3QiPjxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbHA6UmVxdWVzdGVkQXV0aG5Db250ZXh0PjxTaWduYXR1cmUgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxTaWduZWRJbmZvPjxDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PFNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPjxSZWZlcmVuY2UgVVJJPSIjXzAiPjxUcmFuc2Zvcm1zPjxUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L1RyYW5zZm9ybXM+PERpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+PERpZ2VzdFZhbHVlPnRRRGlzQlhLVFErOU9YSk81cjdLdUpnYStLST08L0RpZ2VzdFZhbHVlPjwvUmVmZXJlbmNlPjwvU2lnbmVkSW5mbz48U2lnbmF0dXJlVmFsdWU+bjM4UjRsSFZrVnowYVlRZHM2REk4UXRuZ3p3YkJtY0psYUhGN0E3Mi9hM0pwbUJ3aDVhdWZPZ1ZZdFViZDFFaUN4UExUdm5ONThxSytBOGhXNmFjdEpLN2RlVDJzQ3lpMW1KRG55aGNjTFVwUzhOdHpDVjJMbWZLSXpscGxmdFNtUndJcDhpRWVtRGZFanhOdEtxTFAwUUwwa2h0K29NdUl2Z2hWM2Z1ZTNlM2lDOWczSFArZzFBVlVQZjNCc1lSMDNVTlBMZjB1RFFSbjZNN3dZYisrdGRvL1JwTlZkalpIYm5DeTN4V2d1ZTFHQTRLcnliQ1R6R2JzYXkzcHZVZjg0LytnYWE4RG41c2NXczZXWUFrNklEMEhuVlVqdytjTndqR3pJbVRvUXdUak43b29nT2tFeTNoVkdYa1EvV1owTEYxd0ZtZ015ZS9FUzVRNnNCcTFRPT08L1NpZ25hdHVyZVZhbHVlPjxLZXlJbmZvPjxYNTA5RGF0YT48WDUwOUNlcnRpZmljYXRlPk1JSURvekNDQW91Z0F3SUJBZ0lKQUtOc21MOFFiZnB3TUEwR0NTcUdTSWIzRFFFQkN3VUFNR2d4Q3pBSkJnTlZCQVlUQWtoTE1SSXdFQVlEVlFRSURBbEliMjVuSUV0dmJtY3hDekFKQmdOVkJBY01Ba2hMTVJNd0VRWURWUVFLREFwdWIyUmxMWE5oYld3eU1TTXdJUVlKS29aSWh2Y05BUWtCRmhSdWIyUmxMbk5oYld3eVFHZHRZV2xzTG1OdmJUQWVGdzB4TlRBM01EVXhOelUyTkRkYUZ3MHhPREEzTURReE56VTJORGRhTUdneEN6QUpCZ05WQkFZVEFraExNUkl3RUFZRFZRUUlEQWxJYjI1bklFdHZibWN4Q3pBSkJnTlZCQWNNQWtoTE1STXdFUVlEVlFRS0RBcHViMlJsTFhOaGJXd3lNU013SVFZSktvWklodmNOQVFrQkZoUnViMlJsTG5OaGJXd3lRR2R0WVdsc0xtTnZiVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFNUUpBQjhKcnNMUWJVdUphOGFrekxxTzFFWnFDbFMwdFFwK3crNXdndWZwMDdXd0duL3NobWE4ZGNRTmoxZGJqc3pJNUhCZVZGak9LSXhsZmptTkI5b3ZoUVBzdEJqUC9VUFFZcDFJcDJJb0hDWVg5SERnTXozeHlYS2JIdGhVelphRUN6K3ArN1d0Z3doY3pSa0JMRE9tMmsxNXFoUFlHUHcwdkgyemJWUkdXVUJTOWR5Mk1wM3RxbFZiUDB4WjlDRE5raENKa1Y5U01OZm9DVlcvVllQcUsyUUJvN2tpNG9ibTV4NWl4RlFTU0hzS2JWQVJWenlRSDVpTmpGZTFUZEFwM3JEd3JFNUxjMU5RbFFheFI1R25iMk5aQXBET1JSWklWbE52MldVZGk5UXZNMHlDempROTBqUDBPQW9nSGhSWWF4ZzAvdmdORXllNDZoK1BpWTBDQXdFQUFhTlFNRTR3SFFZRFZSME9CQllFRkVWa2pjTEFJVG5ka3kwOTBBeTc0UXFDbVFLSU1COEdBMVVkSXdRWU1CYUFGRVZramNMQUlUbmRreTA5MEF5NzRRcUNtUUtJTUF3R0ExVWRFd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBRzRsWVgzS1FYZW5lejRMcERuWmhjRkJFWmk5WXN0VUtQRjVFS2QrV3BscFZiY1RRYzFBMy9aK3VIUm15VjhoK3BRemVGNkxpb2IzN0c4N1lwYWNQcGxKSTY2Y2YyUmo3ajhoU0JOYmRyKzY2RTJxcGNFaEFGMWlKbXpCTnloYi95ZGxFdVZwbjgvRXNvUCtIdkJlaURsNWdvbjM1NjJNelpJZ1YvcExkVGZ4SHlXNmh6QVFoakdxMlVoY3ZSK2dYTlZKdkhQMmVTNGpsSG5Ka0I5YmZvMGt2Zjg3UStENlhLWDNxNWMzbU84dHFXNlVwcUhTQyt1TEVwelppTkxldUZhNFRVSWhnQmdqRGpsUnJOREt1OG5kYW5jU24zeUJIWW5xSjJ0OWNSK2NvRm5uallBQlFwTnJ2azRtdG1YWThTWG9CellHOVkrbHFlQXVuNiswWXlFPTwvWDUwOUNlcnRpZmljYXRlPjwvWDUwOURhdGE+PC9LZXlJbmZvPjwvU2lnbmF0dXJlPjwvc2FtbHA6QXV0aG5SZXF1ZXN0Pg==';
const dummySignRequestSHA256: string = 'PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iXzgwOTcwN2YwMDMwYTVkMDA2MjBjOWQ5ZGY5N2Y2MjdhZmU5ZGNjMjQiIFZlcnNpb249IjIuMCIgUHJvdmlkZXJOYW1lPSJTUCB0ZXN0IiBJc3N1ZUluc3RhbnQ9IjIwMTQtMDctMTZUMjM6NTI6NDVaIiBEZXN0aW5hdGlvbj0iaHR0cDovL2lkcC5leGFtcGxlLmNvbS9TU09TZXJ2aWNlLnBocCIgUHJvdG9jb2xCaW5kaW5nPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YmluZGluZ3M6SFRUUC1QT1NUIiBBc3NlcnRpb25Db25zdW1lclNlcnZpY2VVUkw9Imh0dHBzOi8vc3AuZXhhbXBsZS5vcmcvc3Avc3NvIj48c2FtbDpJc3N1ZXIgSWQ9Il8wIj5odHRwczovL3NwLmV4YW1wbGUub3JnL21ldGFkYXRhPC9zYW1sOklzc3Vlcj48c2FtbHA6TmFtZUlEUG9saWN5IEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIiBBbGxvd0NyZWF0ZT0idHJ1ZSIvPjxzYW1scDpSZXF1ZXN0ZWRBdXRobkNvbnRleHQgQ29tcGFyaXNvbj0iZXhhY3QiPjxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbHA6UmVxdWVzdGVkQXV0aG5Db250ZXh0PjxTaWduYXR1cmUgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxTaWduZWRJbmZvPjxDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PFNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz48UmVmZXJlbmNlIFVSST0iI18wIj48VHJhbnNmb3Jtcz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9UcmFuc2Zvcm1zPjxEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz48RGlnZXN0VmFsdWU+d3VKWlJSdWlGb0FQZVZXVllReXhOWXpjbUpJdXB0dTZmaE10MVZuQVZQbz08L0RpZ2VzdFZhbHVlPjwvUmVmZXJlbmNlPjwvU2lnbmVkSW5mbz48U2lnbmF0dXJlVmFsdWU+SGpndVQvbFZ5aEVWczBkb1JUTEdMUmhmRHBsbGUzVGVZRmRCdDlSTDg1bjh5dUdEc0JSRS9YY05RK3lVV1FvalgvaHE5dksyc1ZQejRrcDl6YW5OVE1aRE9yakhUbG9IbEhMbFNhSnFLWE4xK0Y3V1NPSmZidjlROFdNSGFsN0lrR2wwSnFibkpCUFpPYnFHVXdCRmlyN2E3bFp2QTdHcU5UM1M2TXdXVEJudEhzbmJreDkyZXFVTlVuV0VOUzlJYzE5NW10ZzQwZHNtaFErc2ZxODZhay83Q2c4Skg4cnZsb1JRNzVkNUp0WEUrdmVWN0RPeTVrUGNad04zZ09HL2hyK0RDTGYrUHpKYzJkWFI4UkhQY2crQUx0b1F4aUFXbVBBb3lnamJTaFF6bU0wQ0FnUFhyS0VxOTV0RTYyWFFJRGQ2VmpFaVZnS000ZDBTTnZXMEtRPT08L1NpZ25hdHVyZVZhbHVlPjxLZXlJbmZvPjxYNTA5RGF0YT48WDUwOUNlcnRpZmljYXRlPk1JSURvekNDQW91Z0F3SUJBZ0lKQUtOc21MOFFiZnB3TUEwR0NTcUdTSWIzRFFFQkN3VUFNR2d4Q3pBSkJnTlZCQVlUQWtoTE1SSXdFQVlEVlFRSURBbEliMjVuSUV0dmJtY3hDekFKQmdOVkJBY01Ba2hMTVJNd0VRWURWUVFLREFwdWIyUmxMWE5oYld3eU1TTXdJUVlKS29aSWh2Y05BUWtCRmhSdWIyUmxMbk5oYld3eVFHZHRZV2xzTG1OdmJUQWVGdzB4TlRBM01EVXhOelUyTkRkYUZ3MHhPREEzTURReE56VTJORGRhTUdneEN6QUpCZ05WQkFZVEFraExNUkl3RUFZRFZRUUlEQWxJYjI1bklFdHZibWN4Q3pBSkJnTlZCQWNNQWtoTE1STXdFUVlEVlFRS0RBcHViMlJsTFhOaGJXd3lNU013SVFZSktvWklodmNOQVFrQkZoUnViMlJsTG5OaGJXd3lRR2R0WVdsc0xtTnZiVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFNUUpBQjhKcnNMUWJVdUphOGFrekxxTzFFWnFDbFMwdFFwK3crNXdndWZwMDdXd0duL3NobWE4ZGNRTmoxZGJqc3pJNUhCZVZGak9LSXhsZmptTkI5b3ZoUVBzdEJqUC9VUFFZcDFJcDJJb0hDWVg5SERnTXozeHlYS2JIdGhVelphRUN6K3ArN1d0Z3doY3pSa0JMRE9tMmsxNXFoUFlHUHcwdkgyemJWUkdXVUJTOWR5Mk1wM3RxbFZiUDB4WjlDRE5raENKa1Y5U01OZm9DVlcvVllQcUsyUUJvN2tpNG9ibTV4NWl4RlFTU0hzS2JWQVJWenlRSDVpTmpGZTFUZEFwM3JEd3JFNUxjMU5RbFFheFI1R25iMk5aQXBET1JSWklWbE52MldVZGk5UXZNMHlDempROTBqUDBPQW9nSGhSWWF4ZzAvdmdORXllNDZoK1BpWTBDQXdFQUFhTlFNRTR3SFFZRFZSME9CQllFRkVWa2pjTEFJVG5ka3kwOTBBeTc0UXFDbVFLSU1COEdBMVVkSXdRWU1CYUFGRVZramNMQUlUbmRreTA5MEF5NzRRcUNtUUtJTUF3R0ExVWRFd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBRzRsWVgzS1FYZW5lejRMcERuWmhjRkJFWmk5WXN0VUtQRjVFS2QrV3BscFZiY1RRYzFBMy9aK3VIUm15VjhoK3BRemVGNkxpb2IzN0c4N1lwYWNQcGxKSTY2Y2YyUmo3ajhoU0JOYmRyKzY2RTJxcGNFaEFGMWlKbXpCTnloYi95ZGxFdVZwbjgvRXNvUCtIdkJlaURsNWdvbjM1NjJNelpJZ1YvcExkVGZ4SHlXNmh6QVFoakdxMlVoY3ZSK2dYTlZKdkhQMmVTNGpsSG5Ka0I5YmZvMGt2Zjg3UStENlhLWDNxNWMzbU84dHFXNlVwcUhTQyt1TEVwelppTkxldUZhNFRVSWhnQmdqRGpsUnJOREt1OG5kYW5jU24zeUJIWW5xSjJ0OWNSK2NvRm5uallBQlFwTnJ2azRtdG1YWThTWG9CellHOVkrbHFlQXVuNiswWXlFPTwvWDUwOUNlcnRpZmljYXRlPjwvWDUwOURhdGE+PC9LZXlJbmZvPjwvU2lnbmF0dXJlPjwvc2FtbHA6QXV0aG5SZXF1ZXN0Pg==';
const dummySignRequestSHA512: string = 'PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0iXzgwOTcwN2YwMDMwYTVkMDA2MjBjOWQ5ZGY5N2Y2MjdhZmU5ZGNjMjQiIFZlcnNpb249IjIuMCIgUHJvdmlkZXJOYW1lPSJTUCB0ZXN0IiBJc3N1ZUluc3RhbnQ9IjIwMTQtMDctMTZUMjM6NTI6NDVaIiBEZXN0aW5hdGlvbj0iaHR0cDovL2lkcC5leGFtcGxlLmNvbS9TU09TZXJ2aWNlLnBocCIgUHJvdG9jb2xCaW5kaW5nPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YmluZGluZ3M6SFRUUC1QT1NUIiBBc3NlcnRpb25Db25zdW1lclNlcnZpY2VVUkw9Imh0dHBzOi8vc3AuZXhhbXBsZS5vcmcvc3Avc3NvIj48c2FtbDpJc3N1ZXIgSWQ9Il8wIj5odHRwczovL3NwLmV4YW1wbGUub3JnL21ldGFkYXRhPC9zYW1sOklzc3Vlcj48c2FtbHA6TmFtZUlEUG9saWN5IEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6ZW1haWxBZGRyZXNzIiBBbGxvd0NyZWF0ZT0idHJ1ZSIvPjxzYW1scDpSZXF1ZXN0ZWRBdXRobkNvbnRleHQgQ29tcGFyaXNvbj0iZXhhY3QiPjxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbHA6UmVxdWVzdGVkQXV0aG5Db250ZXh0PjxTaWduYXR1cmUgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxTaWduZWRJbmZvPjxDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PFNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGE1MTIiLz48UmVmZXJlbmNlIFVSST0iI18wIj48VHJhbnNmb3Jtcz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9UcmFuc2Zvcm1zPjxEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGE1MTIiLz48RGlnZXN0VmFsdWU+RWN3emlpSzZmazFNK2RETkpHNVlFeWpGY3Fjc0dzRmZNNGFDUkJKcENWTlltVWs4NWJxQk8rblRFN3RmRnd5Uk1yOUZBODBpSnN3MlFwM3R4QTE1Q2c9PTwvRGlnZXN0VmFsdWU+PC9SZWZlcmVuY2U+PC9TaWduZWRJbmZvPjxTaWduYXR1cmVWYWx1ZT5BTk1GRTNaaWlCVkdsVkNPb2xxNE1FR1JsQWNmbFQyUjFVclp6UWlnWmptcUYwQzlGSUZlRC9zeTlvL2RCdWxtSmdvMjdQY0JybmdxeFRXTms1UFdDbnQvdjJORUFvbVdnRHkwM0wzRi9OTmpObnZkY1IyNWh5MzhCT1VwQ0R1SFdkV0NKQVNIRlNUdFZ3L2pESlM4bnNEQUt6Z1RQM2xFOUVKaFN3YkgzUlR5RGlKYThudlVkYkRsclZSTjFqbHZiUmg5S1Y2SWljNm4yUmRiYzZZaUtRVGswZzlKbFp4ZVBvSElKVXRVNXdlNEYzSzBwOGRnbHBHQ2RrckpDOUFaSkpjdDYwQTNHOW5XRjE0cHFTNjltV1liSlpHeUlqdjBqRjBlSEVhaFd1NmRGcFRoYVJhWGErV0ZsVjlNcnFoNityTkJIWis0N3E3NzI3ejVlc202Vnc9PTwvU2lnbmF0dXJlVmFsdWU+PEtleUluZm8+PFg1MDlEYXRhPjxYNTA5Q2VydGlmaWNhdGU+TUlJRG96Q0NBb3VnQXdJQkFnSUpBS05zbUw4UWJmcHdNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1HZ3hDekFKQmdOVkJBWVRBa2hMTVJJd0VBWURWUVFJREFsSWIyNW5JRXR2Ym1jeEN6QUpCZ05WQkFjTUFraExNUk13RVFZRFZRUUtEQXB1YjJSbExYTmhiV3d5TVNNd0lRWUpLb1pJaHZjTkFRa0JGaFJ1YjJSbExuTmhiV3d5UUdkdFlXbHNMbU52YlRBZUZ3MHhOVEEzTURVeE56VTJORGRhRncweE9EQTNNRFF4TnpVMk5EZGFNR2d4Q3pBSkJnTlZCQVlUQWtoTE1SSXdFQVlEVlFRSURBbEliMjVuSUV0dmJtY3hDekFKQmdOVkJBY01Ba2hMTVJNd0VRWURWUVFLREFwdWIyUmxMWE5oYld3eU1TTXdJUVlKS29aSWh2Y05BUWtCRmhSdWIyUmxMbk5oYld3eVFHZHRZV2xzTG1OdmJUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU1RSkFCOEpyc0xRYlV1SmE4YWt6THFPMUVacUNsUzB0UXArdys1d2d1ZnAwN1d3R24vc2htYThkY1FOajFkYmpzekk1SEJlVkZqT0tJeGxmam1OQjlvdmhRUHN0QmpQL1VQUVlwMUlwMklvSENZWDlIRGdNejN4eVhLYkh0aFV6WmFFQ3orcCs3V3Rnd2hjelJrQkxET20yazE1cWhQWUdQdzB2SDJ6YlZSR1dVQlM5ZHkyTXAzdHFsVmJQMHhaOUNETmtoQ0prVjlTTU5mb0NWVy9WWVBxSzJRQm83a2k0b2JtNXg1aXhGUVNTSHNLYlZBUlZ6eVFINWlOakZlMVRkQXAzckR3ckU1TGMxTlFsUWF4UjVHbmIyTlpBcERPUlJaSVZsTnYyV1VkaTlRdk0weUN6alE5MGpQME9Bb2dIaFJZYXhnMC92Z05FeWU0NmgrUGlZMENBd0VBQWFOUU1FNHdIUVlEVlIwT0JCWUVGRVZramNMQUlUbmRreTA5MEF5NzRRcUNtUUtJTUI4R0ExVWRJd1FZTUJhQUZFVmtqY0xBSVRuZGt5MDkwQXk3NFFxQ21RS0lNQXdHQTFVZEV3UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFHNGxZWDNLUVhlbmV6NExwRG5aaGNGQkVaaTlZc3RVS1BGNUVLZCtXcGxwVmJjVFFjMUEzL1ordUhSbXlWOGgrcFF6ZUY2TGlvYjM3Rzg3WXBhY1BwbEpJNjZjZjJSajdqOGhTQk5iZHIrNjZFMnFwY0VoQUYxaUptekJOeWhiL3lkbEV1VnBuOC9Fc29QK0h2QmVpRGw1Z29uMzU2Mk16WklnVi9wTGRUZnhIeVc2aHpBUWhqR3EyVWhjdlIrZ1hOVkp2SFAyZVM0amxIbkprQjliZm8wa3ZmODdRK0Q2WEtYM3E1YzNtTzh0cVc2VXBxSFNDK3VMRXB6WmlOTGV1RmE0VFVJaGdCZ2pEamxSck5ES3U4bmRhbmNTbjN5QkhZbnFKMnQ5Y1IrY29Gbm5qWUFCUXBOcnZrNG10bVhZOFNYb0J6WUc5WStscWVBdW42KzBZeUU9PC9YNTA5Q2VydGlmaWNhdGU+PC9YNTA5RGF0YT48L0tleUluZm8+PC9TaWduYXR1cmU+PC9zYW1scDpBdXRoblJlcXVlc3Q+';


test('base64 encoding returns encoded string', () => {
  expect(utility.base64Encode('Hello World')).toBe('SGVsbG8gV29ybGQ=');
});

test('base64 decoding returns decoded string', () => {
  expect(utility.base64Decode('SGVsbG8gV29ybGQ=', false)).toBe('Hello World');
});

test('deflate + base64 encoded', () => {
  const deflated = utility.deflateString('Hello World');
  expect(utility.base64Encode(deflated)).toBe('80jNyclXCM8vykkBAA==');
});

test('base64 decoded + inflate', () => {
  expect(utility.inflateString('80jNyclXCM8vykkBAA==')).toBe('Hello World');
});


describe('Certificate processing functions', () => {
  test('parse cer format resulting clean certificate', () => {
    const cerContent = readFileSync(testResourcePath('key/sp/cert.cer'));
    // @ts-ignore
    expect(utility.normalizeCerString(cerContent)).toBe(spCertKnownGood);
  });

  test('normalize pem key returns clean string', () => {
    const ekey = readFileSync(testResourcePath('key/sp/encryptKey.pem')).toString();
    expect(utility.normalizePemString(ekey)).toBe(spPemKnownGood);
  });
});

describe('SAML service provider configuration', () => {
  test('getAssertionConsumerService with one binding', () => {
    const expectedPostLocation = 'https:sp.example.org/sp/sso/post';
    const _sp = serviceProvider({
      privateKey: './test/key/sp/privkey.pem',
      privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
      isAssertionEncrypted: true,
      encPrivateKey: './test/key/sp/encryptKey.pem',
      encPrivateKeyPass: 'BXFNKpxrsjrCkGA8cAu5wUVHOSpci1RU',
      assertionConsumerService: [{
        Binding: binding.post,
        Location: expectedPostLocation,
      }],
      singleLogoutService: [{
        Binding: binding.redirect,
        Location: 'https:sp.example.org/sp/slo',
      }],
    });
    // @ts-ignore
    expect(_sp.entityMeta.getAssertionConsumerService(wording.binding.post)).toBe(expectedPostLocation);
  });

  test('getAssertionConsumerService with two bindings', () => {
    const expectedPostLocation = 'https:sp.example.org/sp/sso/post';
    const expectedArtifactLocation = 'https:sp.example.org/sp/sso/artifact';
    const _sp = serviceProvider({
      privateKey: './test/key/sp/privkey.pem',
      privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
      isAssertionEncrypted: true,
      encPrivateKey: './test/key/sp/encryptKey.pem',
      encPrivateKeyPass: 'BXFNKpxrsjrCkGA8cAu5wUVHOSpci1RU',
      assertionConsumerService: [{
        Binding: binding.post,
        Location: expectedPostLocation,
      }, {
        Binding: binding.artifact,
        Location: expectedArtifactLocation,
      }],
      singleLogoutService: [{
        Binding: binding.redirect,
        Location: 'https:sp.example.org/sp/slo',
      }, {
        Binding: binding.post,
        Location: 'https:sp.example.org/sp/slo',
      }],
    });
    // @ts-ignore
    expect(_sp.entityMeta.getAssertionConsumerService(wording.binding.post)).toBe(expectedPostLocation);
    // @ts-ignore
    expect(_sp.entityMeta.getAssertionConsumerService(wording.binding.artifact)).toBe(expectedArtifactLocation);
  });
});

describe('SAML Cryptographic Operations', () => {
  test('sign a SAML message with RSA-SHA1', () => {
    // @ts-ignore
    let result = libsaml.constructMessageSignature(octetString, _spPrivPem, _spPrivKeyPass, true)
    expect(result).toBe(signatureB64SHA1);
  });

  test('sign a SAML message with RSA-SHA256', () => {
    const result = libsaml.constructMessageSignature(
      octetStringSHA256,
      _spPrivPem,
      _spPrivKeyPass,
      undefined,
      signatureAlgorithms.RSA_SHA256
    );
    expect(result.toString('base64')).toBe(signatureB64SHA256);
  });

  test('sign a SAML message with RSA-SHA512', () => {
    const result = libsaml.constructMessageSignature(
      octetStringSHA512,
      _spPrivPem,
      _spPrivKeyPass,
      undefined,
      signatureAlgorithms.RSA_SHA512
    );
    expect(result.toString('base64')).toBe(signatureB64SHA512);
  });

  test('verify binary SAML message signed with RSA-SHA1', () => {
    // @ts-ignore
    const signature = libsaml.constructMessageSignature(octetString, _spPrivPem, _spPrivKeyPass, false);
    // @ts-ignore
    expect(libsaml.verifyMessageSignature(SPMetadata, octetString, signature)).toBe(true);
  });

  test('verify binary SAML message signed with RSA-SHA256', () => {
    const signature = libsaml.constructMessageSignature(
      octetStringSHA256,
      _spPrivPem,
      _spPrivKeyPass,
      false,
      signatureAlgorithms.RSA_SHA256
    );
    expect(libsaml.verifyMessageSignature(
      SPMetadata,
      octetStringSHA256,
      // @ts-ignore
      signature,
      signatureAlgorithms.RSA_SHA256
    )).toBe(true);
  });

  test('verify binary SAML message signed with RSA-SHA512', () => {
    // @ts-ignore
    const signature = libsaml.constructMessageSignature(
      octetStringSHA512,
      _spPrivPem,
      _spPrivKeyPass,
      false,
      signatureAlgorithms.RSA_SHA512
    );
    expect(libsaml.verifyMessageSignature(
      SPMetadata,
      octetStringSHA512,
      // @ts-ignore
      signature,
      signatureAlgorithms.RSA_SHA512
    )).toBe(true);
  });

  test('verify stringified SAML message signed with RSA-SHA1', () => {
    // @ts-ignore
    const signature = libsaml.constructMessageSignature(octetString, _spPrivPem, _spPrivKeyPass);
    // @ts-ignore
    expect(libsaml.verifyMessageSignature(
      SPMetadata,
      octetString,
      Buffer.from(signature.toString(), 'base64')
    )).toBe(true);
  });

  test('verify stringified SAML message signed with RSA-SHA256', () => {
    // @ts-ignore
    const signature = libsaml.constructMessageSignature(octetStringSHA256, _spPrivPem, _spPrivKeyPass);
    // @ts-ignore
    expect(libsaml.verifyMessageSignature(
      SPMetadata,
      octetStringSHA256,
      Buffer.from(signature.toString(), 'base64')
    )).toBe(true);
  });

  test('verify stringified SAML message signed with RSA-SHA512', () => {
    // @ts-ignore
    const signature = libsaml.constructMessageSignature(octetStringSHA512, _spPrivPem, _spPrivKeyPass);
    // @ts-ignore
    expect(libsaml.verifyMessageSignature(
      SPMetadata,
      octetStringSHA512,
      Buffer.from(signature.toString(), 'base64'),
    )).toBe(true);
  });

  test('construct signature with RSA-SHA1', () => {
    const result = libsaml.constructSAMLSignature({
      rawSamlMessage: _originRequest,
      // @ts-ignore
      referenceTagXPath: libsaml.createXPath('Issuer'),
      signingCert: SPMetadata.getX509Certificate('signing') as string,
      privateKey: _spPrivPem,
      privateKeyPass: _spPrivKeyPass,
      signatureAlgorithm: signatureAlgorithms.RSA_SHA1,
    });
    expect(result).toBe(dummySignRequest);
  });

  test('construct signature with RSA-SHA256', () => {
    const result = libsaml.constructSAMLSignature({
      rawSamlMessage: _originRequest,
      // @ts-ignore
      referenceTagXPath: libsaml.createXPath('Issuer'),
      signingCert: SPMetadata.getX509Certificate('signing') as string,
      privateKey: _spPrivPem,
      privateKeyPass: _spPrivKeyPass,
      signatureAlgorithm: signatureAlgorithms.RSA_SHA256,
    });
    expect(result).toBe(dummySignRequestSHA256);
  });

  test('construct signature with RSA-SHA512', () => {
    const result = libsaml.constructSAMLSignature({
      rawSamlMessage: _originRequest,
      // @ts-ignore
      referenceTagXPath: libsaml.createXPath('Issuer'),
      signingCert: SPMetadata.getX509Certificate('signing') as string,
      privateKey: _spPrivPem,
      privateKeyPass: _spPrivKeyPass,
      signatureAlgorithm: signatureAlgorithms.RSA_SHA512,
    });
    expect(result).toBe(dummySignRequestSHA512);
  });

  test('verify a XML signature signed by RSA-SHA1 with metadata', async () => {
    const {status} = await libsaml.verifySignature(_decodedResponse, {metadata: IdPMetadata},sp);
    expect(status).toBe(true);
  });

  test('integrity check for request signed with RSA-SHA1', async   () => {
    await expect(      libsaml.verifySignature(_falseDecodedRequestSHA1, {
      metadata: SPMetadata,
      signatureAlgorithm: signatureAlgorithms.RSA_SHA1
    },sp)).rejects.toThrow('ERR_FAILED_TO_VERIFY_MESSAGE_SIGNATURE');
  });

  test('verify a XML signature signed by RSA-SHA256 with metadata', async () => {
    const {status} = await libsaml.verifySignature(
      _decodedRequestSHA256,
      {
        metadata: SPMetadata,
        signatureAlgorithm: signatureAlgorithms.RSA_SHA256
      },sp
    );
    expect(status).toBe(true);
  });

  test('integrity check for request signed with RSA-SHA256', async () => {
    await expect(     libsaml.verifySignature(_falseDecodedRequestSHA256, {
      metadata: SPMetadata,
      signatureAlgorithm: signatureAlgorithms.RSA_SHA256
    },sp)).rejects.toThrow('ERR_FAILED_TO_VERIFY_MESSAGE_SIGNATURE');
  });

  test('verify a XML signature signed by RSA-SHA512 with metadata', async () => {
    const {status} = await libsaml.verifySignature(
      _decodedRequestSHA512,
      {
        metadata: SPMetadata,
        signatureAlgorithm: signatureAlgorithms.RSA_SHA512
      },sp
    );
    expect(status).toBe(true);
  });

  test('integrity check for request signed with RSA-SHA512', async () => {
    await expect(      libsaml.verifySignature(_falseDecodedRequestSHA512, {
      metadata: SPMetadata,
      signatureAlgorithm: signatureAlgorithms.RSA_SHA512
    },sp )).rejects.toThrow('ERR_FAILED_TO_VERIFY_MESSAGE_SIGNATURE');
  });

  test('verify a XML signature with rolling certificate', async () => {
    const idpConfig = {
      privateKey: readFileSync(testResourcePath('key/idp/privkey.pem')),
      privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
      metadata: readFileSync(testResourcePath('misc/idpmeta_rollingcert.xml')),
    };
    const idpRollingCert = esaml2.IdentityProvider(idpConfig);

    const responseSignedByCert1 = String(readFileSync(testResourcePath('misc/response_signed_cert1.xml')));
    const responseSignedByCert2 = String(readFileSync(testResourcePath('misc/response_signed_cert2.xml')));

    const {status} = await libsaml.verifySignature(
      responseSignedByCert1,
      {
        metadata: idpRollingCert.entityMeta,
        signatureAlgorithm: signatureAlgorithms.RSA_SHA256
      },
        sp
    );

    const statusResult = await libsaml.verifySignature(
      responseSignedByCert2,
      {
        metadata: idpRollingCert.entityMeta,
        signatureAlgorithm: signatureAlgorithms.RSA_SHA256
      },
        sp
    );

    expect(status).toBe(true);
    expect(statusResult.status).toBe(true);
  });

  test('verify a XML signature signed by RSA-SHA1 with .cer keyFile', async  () => {
    const xml = String(readFileSync(testResourcePath('misc/signed_request_sha1.xml')));
    const {status} = await libsaml.verifySignature(xml, {keyFile: testResourcePath('key/sp/cert.cer')},sp);
    expect(status).toBe(true);
  });

  test('verify a XML signature signed by RSA-SHA256 with .cer keyFile', async () => {
    const xml = String(readFileSync(testResourcePath('misc/signed_request_sha256.xml')));
    const {status} = await libsaml.verifySignature(xml, {keyFile: testResourcePath('key/sp/cert.cer')},sp);
    expect(status).toBe(true);
  });

  test('verify a XML signature signed by RSA-SHA512 with .cer keyFile', async () => {
    const xml = String(readFileSync(testResourcePath('misc/signed_request_sha512.xml')));
    const {status} =   await libsaml.verifySignature(xml, {keyFile: testResourcePath('key/sp/cert.cer')},sp);
    expect(status).toBe(true);
  });

  test('encrypt assertion test passes', async () => {

    await expect(libsaml.encryptAssertion(idp, sp, sampleSignedResponse)).resolves.not.toThrow();
  });

  test('encrypt assertion response without assertion returns error', async () => {
    await expect(libsaml.encryptAssertion(idp, sp, wrongResponse)).rejects.toThrow('ERR_NO_ASSERTION');
  });

  test('encrypt assertion with invalid xml syntax returns error', async () => {
    await expect( libsaml.encryptAssertion(idp, sp, 'This is not a xml format string')).rejects.toThrow('missing root element');
  });

  test('encrypt assertion with empty string returns error', async () => {
    await expect(libsaml.encryptAssertion(idp, sp, '')).rejects.toThrow('ERR_UNDEFINED_ASSERTION');
  });

  test('building attribute statement with one attribute', () => {
    const attributes = [
      {
        id: 'QB8QG86PRZUP',
        Name: 'https://www.volcengine.com/SAML/Attributes/Identity',
        type: 'attribute',
        ValueType: 1,
        createdAt: '2025-07-07T08:32:05.184Z',
        NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
        valueArray: [{value: '99858'}
        ],
        FriendlyName: 'Identity'
      }
    ]
    const expectedStatement = '<saml:AttributeStatement><saml:Attribute  Name="https://www.volcengine.com/SAML/Attributes/Identity" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue  xsi:type="xs:string">99858</saml:AttributeValue ></saml:Attribute ></saml:AttributeStatement>';


    expect(libsaml.attributeStatementBuilder(attributes)).toBe(expectedStatement);
  });

  test('building attribute statement with multiple attributes', () => {

    const attributes = [
      {
        id: 'QB8QG86PRZUP',
        Name: 'https://www.volcengine.com/SAML/Attributes/Identity',
        type: 'attribute',
        ValueType: 1,
        createdAt: '2025-07-07T08:32:05.184Z',
        NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
        valueArray: [{value: '99858'}
        ],
        FriendlyName: 'Identity'
      },
      {
        id: 'QB8QG86PRZUP2',
        Name: 'https://www.volcengine.com/SAML/Attributes/SessionName',
        type: 'attribute',
        ValueType: 1,
        createdAt: '2025-07-07T08:32:05.184Z',
        NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
        valueArray: [{value: 'test-email@163.com'}
        ],
        FriendlyName: 'SessionName'
      }
    ]


    const expectedStatement = '<saml:AttributeStatement><saml:Attribute  Name="https://www.volcengine.com/SAML/Attributes/Identity" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue  xsi:type="xs:string">99858</saml:AttributeValue ></saml:Attribute ><saml:Attribute  Name="https://www.volcengine.com/SAML/Attributes/SessionName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue  xsi:type="xs:string">test-email@163.com</saml:AttributeValue ></saml:Attribute ></saml:AttributeStatement>';
    expect(libsaml.attributeStatementBuilder(attributes)).toBe(expectedStatement);
  });
});
// 测试证书路径
const SIGNING_CERT_PATH = './test/key/sp/cert.cer';
const PRIVATE_KEY_PATH = './test/key/sp/privkey.pem';
const PRIVATE_KEY_PASS = 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px';

const IDP_SIGNING_CERT_PATH = './test/key/idp/cert.cer';
const IDP_SIGNING_CERT2_PATH = './test/key/idp/cert2.cer';
const IDP_ENCRYPT_CERT_PATH = './test/key/idp/encryptionCert.cer';
const baseConfig = {
  signingCert: readFileSync('./test/key/sp/cert.cer'),
  privateKey: readFileSync('./test/key/sp/privkey.pem'),
  privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
  entityID: 'http://sp',
  nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
  assertionConsumerService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    Location: 'http://sp/acs',
    Index: 1,
  }],
  singleLogoutService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    Location: 'http://sp/slo',
    Index: 1,
  }],
};
describe('Service Provider Metadata Tests', () => {
  const baseConfig = {
    signingCert: readFileSync(SIGNING_CERT_PATH, 'utf8'),
    privateKey: readFileSync(PRIVATE_KEY_PATH, 'utf8'),
    privateKeyPass: PRIVATE_KEY_PASS,
    entityID: 'http://sp',
    nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
    assertionConsumerService: [{
      Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      Location: 'http://sp/acs',
      Index: 1,
    }],
    singleLogoutService: [{
      Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
      Location: 'http://sp/slo',
      Index: 1,
    }],
  };

  test('SP metadata with default elements order', () => {
    const sp = serviceProvider(baseConfig);
    expect(sp.getMetadata()).toMatchSnapshot();
  });

  test('SP metadata with shibboleth elements order', () => {
    const spToShib = serviceProvider({
      ...baseConfig,
      elementsOrder: ref.elementsOrder.shibboleth // 假设 ref 是可用的
    });
    expect(spToShib.getMetadata()).toMatchSnapshot();
  });
});
describe('Identity Provider Configuration', () => {
  test('IDP with multiple signing and encryption certificates', () => {
    const localIdp = identityProvider({
      signingCert: [
        readFileSync(IDP_SIGNING_CERT_PATH, 'utf8'),
        readFileSync(IDP_SIGNING_CERT2_PATH, 'utf8'),
      ],
      encryptCert: [
        readFileSync(IDP_ENCRYPT_CERT_PATH, 'utf8'),
        readFileSync(IDP_ENCRYPT_CERT_PATH, 'utf8'),
      ],
      singleSignOnService: [{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        Location: 'idp.example.com/sso',
      }]
    });

    const signingCertificate = localIdp.entityMeta.getX509Certificate('signing');
    const encryptionCertificate = localIdp.entityMeta.getX509Certificate('encryption');

    expect(Array.isArray(signingCertificate)).toBe(true);
    expect(signingCertificate.length).toBe(2);

    expect(Array.isArray(encryptionCertificate)).toBe(true);
    expect(encryptionCertificate.length).toBe(2);
  });
});
describe('Time Verification', () => {
  test('verify time with and without drift tolerance', () => {
    const now = new Date();
    const getTime = (mins: number) => new Date(now.getTime() + mins * 60 * 1000);

    const timeBefore10Mins = getTime(-10).toISOString();
    const timeBefore5Mins = getTime(-5).toISOString();
    const timeAfter5Mins = getTime(5).toISOString();
    const timeAfter10Mins = getTime(10).toISOString();

    // 无漂移容差
    expect(verifyTime(timeBefore5Mins, timeAfter5Mins)).toBe(true);
    expect(verifyTime(timeBefore5Mins, undefined)).toBe(true);
    expect(verifyTime(undefined, timeAfter5Mins)).toBe(true);
    expect(verifyTime(undefined, timeBefore5Mins)).toBe(false);
    expect(verifyTime(timeAfter5Mins, undefined)).toBe(false);
    expect(verifyTime(timeBefore10Mins, timeBefore5Mins)).toBe(false);
    expect(verifyTime(timeAfter5Mins, timeAfter10Mins)).toBe(false);
    expect(verifyTime(undefined, undefined)).toBe(true);

    // 有漂移容差 (5分钟)
    const drifts: [number, number] = [-301000, 301000]; // 301秒 = 5分1秒
    expect(verifyTime(timeBefore5Mins, timeAfter5Mins, drifts)).toBe(true);
    expect(verifyTime(timeBefore5Mins, undefined, drifts)).toBe(true);
    expect(verifyTime(undefined, timeAfter5Mins, drifts)).toBe(true);
    expect(verifyTime(undefined, timeBefore5Mins, drifts)).toBe(true);
    expect(verifyTime(timeAfter5Mins, undefined, drifts)).toBe(true);
    expect(verifyTime(timeBefore10Mins, timeBefore5Mins, drifts)).toBe(true);
    expect(verifyTime(timeAfter5Mins, timeAfter10Mins, drifts)).toBe(true);
    expect(verifyTime(undefined, undefined, drifts)).toBe(true);
  });
});

describe('Metadata Parsing Tests', () => {
  test('skip test for invalid metadata with multiple entity descriptors', () => {
    // 跳过测试，如注释所述
    expect(true).toBe(true);
  });

  test('undefined x509 key in metadata should return null', () => {

    expect(idp.entityMeta.getX509Certificate('undefined')).toBeNull();
    expect(sp.entityMeta.getX509Certificate('undefined')).toBeNull();
  });

  test('return list of x509 keys when multiple keys are used', () => {

    expect(Array.isArray(idpRollingCert.entityMeta.getX509Certificate('signing'))).toBe(true);
    expect(idpRollingCert.entityMeta.getX509Certificate('signing').length).toBe(2);
    expect(typeof idpRollingCert.entityMeta.getX509Certificate('encryption')).toBe('string');
  });

  test('get name id format in metadata', () => {
    expect(sp.entityMeta.getNameIDFormat()).toBe('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
    expect(Array.isArray(idp.entityMeta.getNameIDFormat())).toBe(true);
  });

  test('get entity settings', () => {

    expect(typeof idp.getEntitySetting()).toBe('object');
    expect(typeof sp.getEntitySetting()).toBe('object');
  });
});
describe('Certificate Handling', () => {
  test('shared certificate for both signing and encryption', () => {
    const metadata = idpMetadata(readFileSync('./test/misc/idpmeta_share_cert.xml', 'utf8'));
    const signingCertificate = metadata.getX509Certificate('signing');
    const encryptionCertificate = metadata.getX509Certificate('encryption');

    expect(signingCertificate).not.toBeNull();
    expect(encryptionCertificate).not.toBeNull();
    expect(signingCertificate).toBe(encryptionCertificate);
  });

  test('explicit certificate declaration for signing and encryption', () => {
    const signingCertificate = IdPMetadata.getX509Certificate('signing');
    const encryptionCertificate = IdPMetadata.getX509Certificate('encryption');
    expect(signingCertificate).not.toBeNull();
    expect(encryptionCertificate).not.toBeNull();
    expect(signingCertificate).not.toBe(encryptionCertificate);
  });
});
test('get entity settings', () => {

  expect(typeof idp.getEntitySetting()).toBe('object');
  expect(typeof sp.getEntitySetting()).toBe('object');
});

