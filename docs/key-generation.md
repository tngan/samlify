# Key generation

We use openssl to generate the keys and certificate for testing purpose. It is optional to use password protection for private key. The following is the commands to generate private key and self-signed certificate.

```console
> openssl genrsa -passout pass:foobar -out encryptKey.pem 4096
> openssl req -new -x509 -key encryptKey.pem -out encryptionCert.cer -days 3650
```