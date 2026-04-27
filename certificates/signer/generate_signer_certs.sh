#!/bin/bash
set -e
# Generate P-256 (secp256r1) certificates with PKCS#8 keys
echo "Generating P-256 (secp256r1) certificates with PKCS#8 keys..."

# 0.Clean up old files
rm -f ewqwe.signer.ca.key.pem ewqwe.signer.ca.pem ewqwe.signer.leaf.key.pem ewqwe.signer.leaf.cert.pem
rm -f *.csr

# 1. Generate Root CA
echo "Generating Root CA..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out ewqwe.signer.ca.key.pem
openssl req -new -x509 -days 3650 -key ewqwe.signer.ca.key.pem -out ewqwe.signer.ca.pem \
    -subj "/CN=acme.com" \
    -addext "subjectAltName=DNS:demo.ewqwe.local,DNS:localhost,IP:127.0.0.1" \
    -addext "basicConstraints=CA:TRUE,pathlen:0" \
    -addext "keyUsage = digitalSignature,cRLSign,keyCertSign" \
    -addext "extendedKeyUsage = serverAuth, clientAuth" \
    -addext "crlDistributionPoints=URI:https://demo.ewqwe.local/crl.pem"

# 2. Generate Signer Certificate
echo "Generating Signer Certificate..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out ewqwe.signer.leaf.key.pem
openssl req -new -key ewqwe.signer.leaf.key.pem -out ewqwe.signer.leaf.csr \
    -subj "/CN=ewqwe.acme.com" \
    -addext "subjectAltName=DNS:demo.ewqwe.local,DNS:localhost,IP:127.0.0.1"
openssl x509 -req -sha256 -in ewqwe.signer.leaf.csr -CA ewqwe.signer.ca.pem -CAkey ewqwe.signer.ca.key.pem \
    -CAcreateserial -out ewqwe.signer.leaf.cert.pem -days 3650 \
    -extfile <(cat signer_extensions) \
    -extensions v3_req

# 3. Clean up CSR files
rm -f *.csr *.srl

# 4. Generate full-chain PEM (leaf + CA) for JAR signing x5c header
echo "Generating full-chain PEM..."
cat ewqwe.signer.leaf.cert.pem ewqwe.signer.ca.pem > ewqwe.signer.leaf.fullchain.pem

echo "Done! Generated P-256 certificates with PKCS#8 keys:"
echo "  Root CA: ewqwe.signer.ca.pem (key: ewqwe.signer.ca.key.pem)"
echo "  Server: ewqwe.signer.leaf.cert.pem (key: ewqwe.signer.leaf.key.pem)"
echo "  Server full chain: ewqwe.signer.leaf.fullchain.pem (leaf + CA, for JAR x5c)"