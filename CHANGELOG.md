# 2.10.1

* Changes to libsaml.ts verifySignature. This is an internal function, but we still document changes
  - Does not raise error when signature is missing/invalid. Instead it now returns false. This is to simplify logic
  - When there are encrypted assertions, returns the entire response, as the "verifiedAssertionNode"

* Fix logic around handling encrypted assertions
