# Key Generation

The commands below use OpenSSL to generate a private key and a self-signed certificate for testing. Passphrase protection on the private key is optional but recommended.

```console
$ openssl genrsa -passout pass:foobar -out encryptKey.pem 4096
$ openssl req -new -x509 -key encryptKey.pem -out encryptionCert.cer -days 3650
```
