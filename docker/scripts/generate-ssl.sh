#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SSL_DIR="../nginx/ssl"
CERT_FILE="$SSL_DIR/localhost.crt"
KEY_FILE="$SSL_DIR/localhost.key"

echo -e "${YELLOW}🔐 Generating SSL certificates for local development...${NC}"

# Create SSL directory if it doesn't exist
mkdir -p "$SSL_DIR"

# Check if certificates already exist
if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo -e "${GREEN}✅ SSL certificates already exist${NC}"
    
    # Check if certificates are still valid (not expired)
    if openssl x509 -checkend 86400 -noout -in "$CERT_FILE" &> /dev/null; then
        echo -e "${GREEN}✅ SSL certificates are still valid${NC}"
        exit 0
    else
        echo -e "${YELLOW}⚠️  SSL certificates are expired, regenerating...${NC}"
    fi
fi

# Generate private key
echo -e "${YELLOW}🔑 Generating private key...${NC}"
openssl genrsa -out "$KEY_FILE" 2048

# Generate certificate signing request
echo -e "${YELLOW}📋 Generating certificate signing request...${NC}"
openssl req -new -key "$KEY_FILE" -out "$SSL_DIR/localhost.csr" -subj "/C=US/ST=Dev/L=Development/O=AuthService/OU=IT/CN=localhost"

# Create certificate extensions file
cat > "$SSL_DIR/localhost.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
DNS.3 = auth-service
DNS.4 = nextjs-app
DNS.5 = vue-app
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate self-signed certificate
echo -e "${YELLOW}📜 Generating self-signed certificate...${NC}"
openssl x509 -req -in "$SSL_DIR/localhost.csr" -signkey "$KEY_FILE" -out "$CERT_FILE" -days 365 -extensions v3_req -extfile "$SSL_DIR/localhost.ext"

# Set appropriate permissions
chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

# Clean up temporary files
rm -f "$SSL_DIR/localhost.csr" "$SSL_DIR/localhost.ext"

echo -e "${GREEN}✅ SSL certificates generated successfully!${NC}"
echo -e "${YELLOW}📍 Certificate: $CERT_FILE${NC}"
echo -e "${YELLOW}📍 Private Key: $KEY_FILE${NC}"
echo ""
echo -e "${YELLOW}💡 To trust the certificate in your browser:${NC}"
echo "   1. Open https://localhost in your browser"
echo "   2. Click 'Advanced' -> 'Proceed to localhost (unsafe)'"
echo "   3. Or add the certificate to your system's trusted certificates"
echo ""
echo -e "${YELLOW}💡 To add to macOS Keychain:${NC}"
echo "   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $CERT_FILE"
echo ""
echo -e "${YELLOW}💡 To add to Linux certificate store:${NC}"
echo "   sudo cp $CERT_FILE /usr/local/share/ca-certificates/localhost.crt"
echo "   sudo update-ca-certificates"