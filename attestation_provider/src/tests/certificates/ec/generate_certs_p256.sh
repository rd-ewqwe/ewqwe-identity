#!/bin/bash
set -e

# Generate P-256 (secp256r1) certificates with PKCS#8 keys
echo "Generating P-256 (secp256r1) certificates with PKCS#8 keys..."

# Clean up old files
rm -f ewqwe.root.key.pem ewqwe.chain.pem ewqwe.server.key.pem ewqwe.server.cert.pem
rm -f ewqwe.user1.key.pem ewqwe.user1.cert.pem ewqwe.user2.key.pem ewqwe.user2.cert.pem
rm -f ewqwe.user1.p12 ewqwe.user2.p12
rm -f *.csr

# 1. Generate Root CA
echo "Generating Root CA..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out ewqwe.root.key.pem
openssl req -new -x509 -days 3650 -key ewqwe.root.key.pem -out ewqwe.chain.pem \
    -subj "/CN=acme.com" \
    -addext "subjectAltName=IP:127.0.0.1" \
    -addext "basicConstraints=CA:TRUE,pathlen:0" \
    -addext "keyUsage = digitalSignature,cRLSign,keyCertSign" \
    -addext "extendedKeyUsage = serverAuth, clientAuth" \
    -addext "crlDistributionPoints=URI:https://acme.com/crl.pem"

# 2. Generate Server Certificate
echo "Generating Server Certificate..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out ewqwe.server.key.pem
openssl req -new -key ewqwe.server.key.pem -out server.csr \
    -subj "/CN=ewqwe.acme.com" \
    -addext "subjectAltName=IP:127.0.0.1"

openssl x509 -req -sha256 -in server.csr -CA ewqwe.chain.pem -CAkey ewqwe.root.key.pem \
    -CAcreateserial -out ewqwe.server.cert.pem -days 365 \
    -extfile <(cat server_extensions && echo "subjectAltName=IP:127.0.0.1") \
    -extensions v3_req

# 3. Generate User 1 Certificate
echo "Generating User 1 Certificate..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out ewqwe.user1.key.pem
openssl req -new -key ewqwe.user1.key.pem -out user1.csr \
    -subj "/CN=user1.acme.com" \
    -addext "subjectAltName=IP:127.0.0.1"
openssl x509 -req  -sha256 -in user1.csr -CA ewqwe.chain.pem -CAkey ewqwe.root.key.pem \
    -CAcreateserial -out ewqwe.user1.cert.pem -days 365 \
    -extfile <(cat user_extensions && echo "subjectAltName=IP:127.0.0.1") \
    -extensions v3_req

# 4. Generate User 2 Certificate
echo "Generating User 2 Certificate..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out ewqwe.user2.key.pem
openssl req -new -key ewqwe.user2.key.pem -out user2.csr \
    -subj "/CN=user2.acme.com" \
    -addext "subjectAltName=IP:127.0.0.1"
openssl x509 -req  -sha256 -in user2.csr -CA ewqwe.chain.pem -CAkey ewqwe.root.key.pem \
    -CAcreateserial -out ewqwe.user2.cert.pem -days 365 \
    -extfile <(cat user_extensions && echo "subjectAltName=IP:127.0.0.1") \
    -extensions v3_req

# Clean up CSR files
rm -f *.csr *.srl

# 5. Generate PKCS12 files for users
echo "Generating PKCS12 files..."
openssl pkcs12 -export -out ewqwe.user1.p12 \
    -inkey ewqwe.user1.key.pem \
    -in ewqwe.user1.cert.pem \
    -certfile ewqwe.chain.pem \
    -passout pass:secret

openssl pkcs12 -export -out ewqwe.user2.p12 \
    -inkey ewqwe.user2.key.pem \
    -in ewqwe.user2.cert.pem \
    -certfile ewqwe.chain.pem \
    -passout pass:secret

echo "Done! Generated P-256 certificates with PKCS#8 keys:"
echo "  Root CA: ewqwe.chain.pem (key: ewqwe.root.key.pem)"
echo "  Server: ewqwe.server.cert.pem (key: ewqwe.server.key.pem)"
echo "  User 1: ewqwe.user1.cert.pem (key: ewqwe.user1.key.pem, p12: ewqwe.user1.p12)"
echo "  User 2: ewqwe.user2.cert.pem (key: ewqwe.user2.key.pem, p12: ewqwe.user2.p12)"
echo "  PKCS12 password: secret"
