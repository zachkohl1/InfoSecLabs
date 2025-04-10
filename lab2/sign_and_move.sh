#!/bin/bash

# Sign and move client_v2 and server_v2 from ./updates with valid ECDSA signatures
# Uses separate key pairs for client and server

UPDATES_DIR="./updates"
CLIENT_PRIV="client_private.pem"
SERVER_PRIV="server_private.pem"

# Output public keys
CLIENT_PUB="client_public.pem"
SERVER_PUB="server_public.pem"
SERVER_PUB_TARGET="../server_public.pem"  # Used by the server at runtime

# Check key presence
if [[ ! -f "$CLIENT_PRIV" ]]; then
  echo "[ERROR] Missing client private key: $CLIENT_PRIV"
  exit 1
fi

if [[ ! -f "$SERVER_PRIV" ]]; then
  echo "[ERROR] Missing server private key: $SERVER_PRIV"
  exit 1
fi

mkdir -p "$UPDATES_DIR"

# Sign client_v2
if [[ -f "$UPDATES_DIR/client_v2" ]]; then
  echo "[INFO] Signing client_v2..."
  openssl dgst -sha256 -sign "$CLIENT_PRIV" -out "$UPDATES_DIR/client_v2.sig" "$UPDATES_DIR/client_v2"
  echo "[OK] client_v2 signed."
else
  echo "[WARN] client_v2 not found in $UPDATES_DIR"
fi

# Sign server_v2
if [[ -f "$UPDATES_DIR/server_v2" ]]; then
  echo "[INFO] Signing server_v2..."
  openssl dgst -sha256 -sign "$SERVER_PRIV" -out "$UPDATES_DIR/server_v2.sig" "$UPDATES_DIR/server_v2"
  echo "[OK] server_v2 signed."
else
  echo "[WARN] server_v2 not found in $UPDATES_DIR"
fi

# Regenerate public keys
openssl ec -in "$CLIENT_PRIV" -pubout -out "$CLIENT_PUB"
echo "[INFO] Regenerated $CLIENT_PUB"

openssl ec -in "$SERVER_PRIV" -pubout -out "$SERVER_PUB"
echo "[INFO] Regenerated $SERVER_PUB"

cp "$SERVER_PUB" "$SERVER_PUB_TARGET"
echo "[INFO] Updated $SERVER_PUB_TARGET used by server"

echo "[DONE] Signing complete."