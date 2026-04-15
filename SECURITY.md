# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in identree, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Email: security@identree.dev (or the repo owner's contact)

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for a fix within 7 days.

## Security Design

identree handles authentication and authorization for Linux servers. Key security properties:

- All secrets (session, escrow, LDAP) are independently derived per trust domain
- mTLS with embedded CA for PAM client and LDAP authentication
- Audit events are hash-chained with SHA-256 for tamper detection
- Break-glass passwords are bcrypt-hashed (cost 12) with rate limiting
- SSRF protection on webhook delivery (private IP denylist)
- CSRF protection on all mutation endpoints
- Constant-time comparison for all secret verification

## Dependencies

SAML support uses github.com/crewjam/saml. We monitor this dependency for CVEs.
