# 2.10.1

* Adds @authenio/samlify-xsd-schema-validator as dependency by default
This is to support running test cases

* Changes to libsaml.ts verifySignature. This is an internal function, but we still document changes
  - Does not raise error when signature is missing/invalid. Instead it now returns false. This is to simplify logic
  - When there are encrypted assertions, returns the entire response, as the "verifiedAssertionNode"

* Update logic around handling encrypted assertions
