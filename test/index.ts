import esaml2 = require("../index");
import * as fs from 'fs';
import test from 'ava';

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

const xpath = require('xpath');
const dom = require('xmldom').DOMParser;
const select = require('xml-crypto').xpath;

// Define of metadata
const _spKeyFolder = './test/key/sp/';
const _spPrivPem = _spKeyFolder + 'privkey.pem';
const _spPrivKey = _spKeyFolder + 'nocrypt.pem';
const _spPrivKeyPass = 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px';

// Define an identity provider
const idp = identityProvider({
  privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
  privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  isAssertionEncrypted: true,
  encPrivateKey: fs.readFileSync('./test/key/idp/encryptKey.pem'),
  encPrivateKeyPass: 'g7hGcRmp8PxT5QeP2q9Ehf1bWe9zTALN',
  metadata: './test/metadata/IDPMetadata.xml'
});

const sp = serviceProvider({
  privateKey: fs.readFileSync('./test/key/sp/privkey.pem'),
  privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
  isAssertionEncrypted: true, // for logout purpose
  encPrivateKey: fs.readFileSync('./test/key/sp/encryptKey.pem'),
  encPrivateKeyPass: 'BXFNKpxrsjrCkGA8cAu5wUVHOSpci1RU',
  metadata: './test/metadata/SPMetadata.xml'
});

// Define metadata
const IdPMetadata = idpMetadata('./test/misc/IDPMetadata.xml');
const SPMetadata = spMetadata('./test/misc/SPMetadata.xml');
const sampleSignedResponse = fs.readFileSync('./test/misc/SignSAMLResponse.xml').toString();
const wrongResponse = fs.readFileSync('./test/misc/wrongResponse.xml').toString();
const spCertKnownGood = fs.readFileSync('./test/key/sp/knownGoodCert.cer').toString().trim();
const spPemKnownGood = fs.readFileSync('./test/key/sp/knownGoodEncryptKey.pem').toString().trim();

function writer(str) {
  fs.writeFileSync('test.txt', str);
}

// start testing

test('base64 encoding returns encoded string', t => {
	t.is(utility.base64Encode('Hello World'), 'SGVsbG8gV29ybGQ=');
});
test('base64 decoding returns decoded string', t => {
	t.is(utility.base64Decode('SGVsbG8gV29ybGQ='), 'Hello World');
});
test('deflate + base64 encoded', t => {
	t.is(utility.base64Encode(utility.deflateString('Hello World')), '80jNyclXCM8vykkBAA==');
});
test('base64 decoded + inflate', t => {
  t.is(utility.inflateString('80jNyclXCM8vykkBAA=='), 'Hello World');
});
test('parse cer format resulting clean certificate', t => {
  t.is(utility.normalizeCerString(fs.readFileSync('./test/key/sp/cert.cer')), spCertKnownGood);
});
test('normalize pem key returns clean string', t => {
	const ekey = fs.readFileSync('./test/key/sp/encryptKey.pem').toString();
	t.is(utility.normalizePemString(ekey), spPemKnownGood);
});

test('getAssertionConsumerService with one binding', t => {
	const expectedPostLocation = 'https://sp.example.org/sp/sso/post';
	const sp = serviceProvider({
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
	t.is(sp.entityMeta.getAssertionConsumerService(wording.binding.post), expectedPostLocation);
});
test('getAssertionConsumerService with two bindings', t => {
	const expectedPostLocation = 'https://sp.example.org/sp/sso/post';
	const expectedArtifactLocation = 'https://sp.example.org/sp/sso/artifact';
	const sp = serviceProvider({
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
	t.is(sp.entityMeta.getAssertionConsumerService(wording.binding.post), expectedPostLocation);
  t.is(sp.entityMeta.getAssertionConsumerService(wording.binding.arifact), expectedArtifactLocation);
});

