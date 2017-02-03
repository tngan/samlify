# CHANGELOG

## [2.0-alpha](#)

**Important changes**
+ The file name SamlLib is renamed as libsaml
+ The file name IdentityProvider is renamed as entity-idp
+ The file name ServiceProvider is renamed as entity-sp
+ API breaking change #13

**New features and support**
+ Use Typescript 2.0 in development
+ Write in ES2015/2016 style
+ Support yarn package installer
+ The name of API methods in v1.0 is no longer to be supported
+ All example repo now share same node_modules and no need to run npm install/yarn separately

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
