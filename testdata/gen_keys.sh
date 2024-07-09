#!/bin/bash
#
# RSA (relevant for PS256, PS384, PS512, RS256, RS384, RS512)
#
openssl genrsa -out rsa/private.pem 2048
openssl rsa -in rsa/private.pem -pubout -outform PEM -out rsa/public.pem
# for a specific test we want to use a key id. Let's use the SHA1 sum of the private key as kid
openssl rsa -in rsa/private.pem -outform DER -pubout 2>/dev/null | openssl sha1 -c | cut -f2 -d '='| tr -d ': ' | tr -d '\n' >rsa/kid.txt
#
# ECDSA (relevant for ES256, ES384, ES512)
#
openssl ecparam -name prime256v1 -genkey -outform PEM -noout -out ecdsa/es256/private.pem
openssl ec -in ecdsa/es256/private.pem -pubout > ecdsa/es256/public.pem
openssl ecparam -name secp384r1 -genkey -outform PEM -noout -out ecdsa/es384/private.pem
openssl ec -in ecdsa/es384/private.pem -pubout > ecdsa/es384/public.pem
openssl ecparam -name secp521r1 -genkey -outform PEM -noout -out ecdsa/es512/private.pem
openssl ec -in ecdsa/es512/private.pem -pubout > ecdsa/es512/public.pem
#
#  ED25519 (relevant for EdDSA)
#
openssl genpkey -algorithm ed25519 -out ed25519/private.pem
openssl pkey -in ed25519/private.pem -pubout -out ed25519/public.pem
#
# Secret (relevant for HS256, HS384, HS512)
#
echo -n  $RANDOM | md5sum | head -c 20 >secret/secret.txt
