# SAML Integration via OIDC Bridge

identree authenticates users via OIDC. If your organization uses a SAML-only identity provider, deploy an OIDC-to-SAML bridge between your IdP and identree.

## Recommended bridges

| Bridge | Notes |
|--------|-------|
| Keycloak | Identity brokering: accepts SAML from upstream IdP, exposes OIDC to identree |
| Authentik | SAML source + OIDC provider in one deployment |
| Dex | Lightweight, supports SAML connector to upstream IdP |

## Example: Keycloak as SAML-to-OIDC bridge

### Architecture

```
SAML IdP (Okta, Azure AD, etc.)
    |
    | SAML assertion
    v
Keycloak (bridge)
    |
    | OIDC tokens
    v
identree
```

### Configuration

1. Deploy Keycloak
2. Create a realm
3. Add a SAML Identity Provider pointing at your SAML IdP's metadata URL
4. Create an OIDC client for identree:
   - Client ID: `identree`
   - Valid Redirect URIs: `https://identree.example.com/callback`
   - Client authentication: On (confidential)
5. Map SAML attributes to OIDC claims (groups, username)
6. Configure identree:
   ```sh
   IDENTREE_OIDC_ISSUER_URL=https://keycloak.example.com/realms/your-realm
   IDENTREE_OIDC_CLIENT_ID=identree
   IDENTREE_OIDC_CLIENT_SECRET=<from keycloak>
   ```

### Why this approach

- **No SAML parsing in identree.** SAML is a complex protocol with a large attack surface (XML signature wrapping, assertion replay, etc.). Delegating it to a battle-tested implementation like Keycloak eliminates that risk.
- **Battle-tested SAML implementations.** Keycloak, Authentik, and Dex have mature SAML stacks used in production by thousands of organizations.
- **One extra container, one fewer attack surface.** The bridge adds a single container but removes an entire class of vulnerabilities from identree.
- **Protocol flexibility.** The same bridge can federate multiple upstream IdPs (SAML, LDAP, social) into a single OIDC issuer for identree.

## Example: Authentik as SAML-to-OIDC bridge

1. Deploy Authentik
2. Create a SAML Source pointing at your SAML IdP
3. Create an OAuth2/OIDC Provider for identree
4. Create an Application linking the provider to identree
5. Configure identree with the Authentik OIDC issuer URL and client credentials

## Example: Dex as SAML-to-OIDC bridge

1. Deploy Dex
2. Add a SAML connector in `dex.yaml`:
   ```yaml
   connectors:
   - type: saml
     id: enterprise-idp
     name: Enterprise IdP
     config:
       ssoURL: https://idp.example.com/saml/sso
       ca: /etc/dex/saml-ca.pem
       redirectURI: https://dex.example.com/callback
       usernameAttr: name
       emailAttr: email
       groupsAttr: groups
   ```
3. Add a static client for identree:
   ```yaml
   staticClients:
   - id: identree
     secret: <generated-secret>
     name: identree
     redirectURIs:
     - https://identree.example.com/callback
   ```
4. Configure identree:
   ```sh
   IDENTREE_OIDC_ISSUER_URL=https://dex.example.com
   IDENTREE_OIDC_CLIENT_ID=identree
   IDENTREE_OIDC_CLIENT_SECRET=<from dex>
   ```

## Testing the bridge pattern

The existing Keycloak provider test (`test/providers/keycloak/`) validates that identree works correctly with Keycloak as an OIDC provider. This is the same configuration used in the bridge architecture -- identree connects to Keycloak via OIDC regardless of how Keycloak authenticates users upstream (password, SAML, social login, etc.).

To test the full SAML-to-OIDC bridge flow with two Keycloak instances, see `test/providers/keycloak-saml-bridge/`.
