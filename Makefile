COMMIT := $(shell git rev-parse HEAD 2>/dev/null || echo dev)
VERSION ?= dev

export COMMIT
export VERSION

# ── PocketID (full mode) — default test environment ───────────────────────────
.PHONY: up down build logs ps

up:
	docker compose -f test/docker-compose.yml up --build -d

down:
	docker compose -f test/docker-compose.yml down

build:
	docker compose -f test/docker-compose.yml build

logs:
	docker compose -f test/docker-compose.yml logs -f identree

ps:
	docker compose -f test/docker-compose.yml ps

# ── lldap + Dex (bridge mode) ─────────────────────────────────────────────────
.PHONY: test-lldap-dex test-lldap-dex-down test-lldap-dex-logs test-lldap-dex-setup test-lldap-dex-validate

test-lldap-dex:
	docker compose -f test/providers/lldap-dex/docker-compose.yml up --build -d

test-lldap-dex-down:
	docker compose -f test/providers/lldap-dex/docker-compose.yml down

test-lldap-dex-logs:
	docker compose -f test/providers/lldap-dex/docker-compose.yml logs -f identree

test-lldap-dex-setup:
	bash test/providers/lldap-dex/setup.sh

test-lldap-dex-validate:
	bash test/providers/validate.sh \
		identree-lldap-dex-client \
		http://localhost:8091 \
		http://localhost:5556/dex \
		ldap://localhost:3891

# ── Keycloak + lldap (bridge mode) ────────────────────────────────────────────
.PHONY: test-keycloak test-keycloak-down test-keycloak-logs test-keycloak-setup test-keycloak-validate

test-keycloak:
	docker compose -f test/providers/keycloak/docker-compose.yml up --build -d

test-keycloak-down:
	docker compose -f test/providers/keycloak/docker-compose.yml down

test-keycloak-logs:
	docker compose -f test/providers/keycloak/docker-compose.yml logs -f identree

test-keycloak-setup:
	bash test/providers/keycloak/setup.sh

test-keycloak-validate:
	bash test/providers/validate.sh \
		identree-keycloak-client \
		http://localhost:8092 \
		"http://localhost:8180/realms/identree-test" \
		ldap://localhost:3892

# ── Kanidm (bridge mode) ──────────────────────────────────────────────────────
.PHONY: test-kanidm test-kanidm-down test-kanidm-logs test-kanidm-setup test-kanidm-validate

test-kanidm:
	docker compose -f test/providers/kanidm/docker-compose.yml up --build -d

test-kanidm-down:
	docker compose -f test/providers/kanidm/docker-compose.yml down

test-kanidm-logs:
	docker compose -f test/providers/kanidm/docker-compose.yml logs -f identree

test-kanidm-setup:
	bash test/providers/kanidm/setup.sh

test-kanidm-validate:
	bash test/providers/validate.sh \
		identree-kanidm-client \
		http://localhost:8093 \
		"http://localhost:8443/oauth2/openid/identree-test" \
		ldap://localhost:3636

# ── Vault escrow (bridge mode + Vault KV v2) ──────────────────────────────────
.PHONY: test-vault-escrow test-vault-escrow-down test-vault-escrow-logs test-vault-escrow-setup test-vault-escrow-validate

test-vault-escrow:
	docker compose -f test/providers/escrow/vault/docker-compose.yml up --build -d

test-vault-escrow-down:
	docker compose -f test/providers/escrow/vault/docker-compose.yml down

test-vault-escrow-logs:
	docker compose -f test/providers/escrow/vault/docker-compose.yml logs -f identree

test-vault-escrow-setup:
	bash test/providers/escrow/vault/setup.sh

test-vault-escrow-validate:
	bash test/providers/escrow/vault/validate.sh

# ── Infisical escrow (bridge mode + Infisical Secrets Manager) ────────────────
.PHONY: test-infisical-escrow test-infisical-escrow-down test-infisical-escrow-logs test-infisical-escrow-setup test-infisical-escrow-validate

test-infisical-escrow:
	docker compose -f test/providers/escrow/infisical/docker-compose.yml up --build -d

test-infisical-escrow-down:
	docker compose -f test/providers/escrow/infisical/docker-compose.yml down -v

test-infisical-escrow-logs:
	docker compose -f test/providers/escrow/infisical/docker-compose.yml logs -f identree

test-infisical-escrow-setup:
	bash test/providers/escrow/infisical/setup.sh

test-infisical-escrow-validate:
	bash test/providers/escrow/infisical/validate.sh

# ── OpenLDAP + Dex (bridge mode, RFC 2307) ────────────────────────────────────
.PHONY: test-openldap-dex test-openldap-dex-down test-openldap-dex-logs test-openldap-dex-setup test-openldap-dex-validate

test-openldap-dex:
	docker compose -f test/providers/openldap-dex/docker-compose.yml up --build -d

test-openldap-dex-down:
	docker compose -f test/providers/openldap-dex/docker-compose.yml down -v

test-openldap-dex-logs:
	docker compose -f test/providers/openldap-dex/docker-compose.yml logs -f identree

test-openldap-dex-setup:
	bash test/providers/openldap-dex/setup.sh

test-openldap-dex-validate:
	bash test/providers/validate.sh \
		identree-openldap-dex-client \
		http://localhost:8097 \
		http://localhost:5559/dex \
		ldap://localhost:3895

# ── Authentik (bridge mode, OIDC + LDAP outpost) ──────────────────────────────
.PHONY: test-authentik test-authentik-down test-authentik-logs test-authentik-setup test-authentik-validate

test-authentik:
	docker compose -f test/providers/authentik/docker-compose.yml up --build -d

test-authentik-down:
	docker compose -f test/providers/authentik/docker-compose.yml down -v

test-authentik-logs:
	docker compose -f test/providers/authentik/docker-compose.yml logs -f identree-authentik-server-app

test-authentik-setup:
	bash test/providers/authentik/setup.sh

test-authentik-validate:
	bash test/providers/validate.sh \
		identree-authentik-client \
		http://localhost:8098 \
		"http://localhost:9000/application/o/identree" \
		ldap://localhost:3896

# ── Samba AD DC + Dex (bridge mode, AD schema) ────────────────────────────────
.PHONY: test-samba-ad-dex test-samba-ad-dex-down test-samba-ad-dex-logs test-samba-ad-dex-setup test-samba-ad-dex-validate

test-samba-ad-dex:
	docker compose -f test/providers/samba-ad-dex/docker-compose.yml up --build -d

test-samba-ad-dex-down:
	docker compose -f test/providers/samba-ad-dex/docker-compose.yml down -v

test-samba-ad-dex-logs:
	docker compose -f test/providers/samba-ad-dex/docker-compose.yml logs -f identree

test-samba-ad-dex-setup:
	bash test/providers/samba-ad-dex/setup.sh

test-samba-ad-dex-validate:
	bash test/providers/validate.sh \
		identree-samba-ad-dex-client \
		http://localhost:8099 \
		http://localhost:5560/dex \
		ldap://localhost:3897

# ── Convenience: bring down all environments ──────────────────────────────────
.PHONY: down-all

down-all: down test-lldap-dex-down test-keycloak-down test-kanidm-down test-vault-escrow-down test-infisical-escrow-down test-openldap-dex-down test-authentik-down test-samba-ad-dex-down
