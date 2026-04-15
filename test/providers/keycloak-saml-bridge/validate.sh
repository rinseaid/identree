#!/bin/bash
# validate.sh -- smoke-test the SAML-to-OIDC bridge environment.
# Delegates to the shared validate.sh in test/providers/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

exec bash "${SCRIPT_DIR}/../validate.sh" \
    identree-saml-bridge-client \
    http://localhost:8095 \
    "http://localhost:8184/realms/bridge" \
    ldap://localhost:3895
