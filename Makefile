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

# ── Convenience: bring down all environments ──────────────────────────────────
.PHONY: down-all

down-all: down test-lldap-dex-down test-keycloak-down test-kanidm-down test-vault-escrow-down
