import test from "ava";
import { SignedXml } from "xml-crypto";
import libSaml from "../src/libsaml";

const fakeMetadataInvalid = {
  getX509Certificate: (_usage: string) => null,
};

const fakeMetadataValid = {
  getX509Certificate: (_usage: string) => "VALIDCERT",
};

test("throws ERR_UNDEFINED_SIGNATURE_VERIFIER_OPTIONS when neither keyFile nor metadata provided", (t) => {
  const xml = "<Response><Signature></Signature></Response>";
  const error = t.throws(() => {
    libSaml.verifySignature(xml, { signatureAlgorithm: "dummy" } as any);
  });
  t.is(error!.message, "ERR_UNDEFINED_SIGNATURE_VERIFIER_OPTIONS");
});

test("throws ERR_ZERO_SIGNATURE when no signature element exists", (t) => {
  const xml = "<Response></Response>";
  const error = t.throws(() => {
    libSaml.verifySignature(xml, {
      keyFile: "dummy.pem",
      signatureAlgorithm: "dummy",
    } as any);
  });
  t.is(error!.message, "ERR_ZERO_SIGNATURE");
});

test("throws ERR_POTENTIAL_WRAPPING_ATTACK when wrapping element is present", (t) => {
  // Construct XML with a wrapping assertion inside SubjectConfirmationData
  const xml = `
    <Response>
      <Signature>
        <X509Data>
          <X509Certificate>VALIDCERT</X509Certificate>
        </X509Data>
      </Signature>
      <Assertion ID="ID">
        <Subject>
          <SubjectConfirmation>
            <SubjectConfirmationData>
              <Assertion></Assertion>
            </SubjectConfirmationData>
          </SubjectConfirmation>
        </Subject>
      </Assertion>
    </Response>
  `;
  const error = t.throws(() => {
    libSaml.verifySignature(xml, {
      keyFile: "dummy.pem",
      signatureAlgorithm: "dummy",
    } as any);
  });
  t.is(error!.message, "ERR_POTENTIAL_WRAPPING_ATTACK");
});

test("throws INVALID_CERTIFICATE_PROVIDED when metadata returns no certificate", (t) => {
  // Signature element is present and metadata returns null certificate.
  const xml = `
    <Response>
      <Signature>
        <X509Data>
          <X509Certificate>ANOTHERCERT</X509Certificate>
        </X509Data>
      </Signature>
      <Assertion ID="ID">Content</Assertion>
    </Response>
  `;
  const error = t.throws(() => {
    libSaml.verifySignature(xml, {
      metadata: fakeMetadataInvalid,
      signatureAlgorithm: "dummy",
    } as any);
  });
  t.is(error!.message, "INVALID_CERTIFICATE_PROVIDED");
});

test("returns valid verification result when signature is valid", (t) => {
  // Override SignedXml methods to simulate valid signature checking
  const origCheckSignature = SignedXml.prototype.checkSignature;
  const origLoadSignature = SignedXml.prototype.loadSignature;
  SignedXml.prototype.checkSignature = () => true;
  SignedXml.prototype.loadSignature = () => {};

  // Create a minimal XML with a Signature element containing a valid certificate node
  const xml = `
    <Response>
      <Signature>
        <X509Data>
          <X509Certificate>VALIDCERT</X509Certificate>
        </X509Data>
      </Signature>
      <Assertion ID="ID">AssertionContent</Assertion>
    </Response>
  `;
  const result = libSaml.verifySignature(xml, {
    metadata: fakeMetadataValid,
    signatureAlgorithm: "dummy",
  } as any);
  t.true(Array.isArray(result));
  t.true(result[0] === true);
  t.regex(typeof result[1] === "string" ? result[1] : "", /Assertion/);

  // Restore the original methods
  SignedXml.prototype.checkSignature = origCheckSignature;
  SignedXml.prototype.loadSignature = origLoadSignature;
});
