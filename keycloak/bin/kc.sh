#!/bin/bash
# Keycloak Standalone Launcher Script (CloudGovRealm)
echo "========================================================"
echo " Starting Keycloak IdP Standalone Server on :8080..."
echo "========================================================"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../.."
python3 src/identity/keycloak_server.py

