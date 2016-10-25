# Change Log

## [2.0](#)

**Breaking changes**
+ The file name SamlLib is renamed as libsaml

**New features and support**
+ Use Typescript 2.0 in development
+ Write in ES2015/2016 style
+ Support Yarn package manager

## [1.1](#)

**Implemented enhancements:**
+ Support RSASHA1, RSASHA256, RSASHA512 signature algorithms #6
+ Support AES128, AES256, TRI-DEC for assertion encryption #7
+ Improve the readability of README.md #8
+ Add more test cases
+ Delete the duplicated method `Metadata.prototype.createKeySection`
+ Continuous code refractoring

**Merged pull requests:**
+ PR #2 Bad reference to IDPSSODescriptor

**Remarks:**
+ All release now follows Semantic Versioning 2.0.0
+ Thanks @markstos and @peterwillis
