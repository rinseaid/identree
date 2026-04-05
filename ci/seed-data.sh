#!/usr/bin/env bash
# ci/seed-data.sh — populate PocketID and identree with realistic test data for screenshots
set -euo pipefail

POCKETID_URL="http://localhost:1411"
IDENTREE_URL="http://localhost:8090"
API_KEY="identree-test-static-key"

# ── Helpers ────────────────────────────────────────────────────────────────────

api() {
    local method="$1"
    local path="$2"
    shift 2
    curl -sf -X "$method" \
        -H "Content-Type: application/json" \
        -H "X-API-KEY: $API_KEY" \
        "${POCKETID_URL}${path}" "$@"
}

# Parse a field from JSON using python3 (jq may not be on the runner).
json_field() {
    local field="$1"
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('${field}',''))" 2>/dev/null || true
}

check_or_die() {
    local id="$1"
    local label="$2"
    if [ -z "$id" ]; then
        echo "ERROR: failed to create ${label}" >&2
        exit 1
    fi
}

# ── Wait for services ──────────────────────────────────────────────────────────

echo "==> Waiting for PocketID..."
until curl -sf "${POCKETID_URL}/healthz" >/dev/null 2>&1; do sleep 1; done
echo "    PocketID ready."

echo "==> Waiting for identree..."
until curl -sf "${IDENTREE_URL}/healthz" >/dev/null 2>&1; do sleep 1; done
echo "    identree ready."

# ── Create users ───────────────────────────────────────────────────────────────

echo "==> Creating users..."

create_user() {
    local username="$1" first="$2" last="$3" email="$4" is_admin="${5:-false}"
    api POST /api/users -d "{
      \"username\": \"${username}\",
      \"firstName\": \"${first}\",
      \"lastName\": \"${last}\",
      \"email\": \"${email}\",
      \"isAdmin\": ${is_admin}
    }" | json_field id
}

# Admin
ADMIN_ID=$(create_user "testadmin" "Test" "Admin" "admin@corp.example" true)
check_or_die "$ADMIN_ID" "testadmin"
echo "    testadmin=${ADMIN_ID}"

# Engineering
ALICE_ID=$(create_user "alice" "Alice" "Liddell" "alice@corp.example")
BOB_ID=$(create_user "bob" "Bob" "Builder" "bob@corp.example")
CAROL_ID=$(create_user "carol" "Carol" "Danvers" "carol@corp.example")
DAVE_ID=$(create_user "dave" "Dave" "Finch" "dave@corp.example")
EVE_ID=$(create_user "eve" "Eve" "Adler" "eve@corp.example")
FRANK_ID=$(create_user "frank" "Frank" "Castle" "frank@corp.example")
echo "    engineers: alice=${ALICE_ID} bob=${BOB_ID} carol=${CAROL_ID} dave=${DAVE_ID} eve=${EVE_ID} frank=${FRANK_ID}"

# DevOps / SRE
GRACE_ID=$(create_user "grace" "Grace" "Hopper" "grace@corp.example")
HEIDI_ID=$(create_user "heidi" "Heidi" "Lamarr" "heidi@corp.example")
IVAN_ID=$(create_user "ivan" "Ivan" "Drago" "ivan@corp.example")
JUDY_ID=$(create_user "judy" "Judy" "Hopps" "judy@corp.example")
echo "    sre: grace=${GRACE_ID} heidi=${HEIDI_ID} ivan=${IVAN_ID} judy=${JUDY_ID}"

# Data / ML
KATE_ID=$(create_user "kate" "Kate" "Bishop" "kate@corp.example")
LIAM_ID=$(create_user "liam" "Liam" "Neeson" "liam@corp.example")
MAYA_ID=$(create_user "maya" "Maya" "Angelou" "maya@corp.example")
echo "    data: kate=${KATE_ID} liam=${LIAM_ID} maya=${MAYA_ID}"

# Security
NEIL_ID=$(create_user "neil" "Neil" "Gaiman" "neil@corp.example")
OLIVIA_ID=$(create_user "olivia" "Olivia" "Pope" "olivia@corp.example")
echo "    security: neil=${NEIL_ID} olivia=${OLIVIA_ID}"

# Support / QA
PEDRO_ID=$(create_user "pedro" "Pedro" "Pascal" "pedro@corp.example")
QUINN_ID=$(create_user "quinn" "Quinn" "Hughes" "quinn@corp.example")
RACHEL_ID=$(create_user "rachel" "Rachel" "Green" "rachel@corp.example")
SAM_ID=$(create_user "sam" "Sam" "Winchester" "sam@corp.example")
TARA_ID=$(create_user "tara" "Tara" "Strong" "tara@corp.example")
echo "    support/qa: pedro=${PEDRO_ID} quinn=${QUINN_ID} rachel=${RACHEL_ID} sam=${SAM_ID} tara=${TARA_ID}"

# Additional users to fill out the list
VICTOR_ID=$(create_user "victor" "Victor" "Stone" "victor@corp.example")
WENDY_ID=$(create_user "wendy" "Wendy" "Torrance" "wendy@corp.example")
XAVIER_ID=$(create_user "xavier" "Xavier" "Charles" "xavier@corp.example")
YARA_ID=$(create_user "yara" "Yara" "Greyjoy" "yara@corp.example")
ZOE_ID=$(create_user "zoe" "Zoe" "Washburne" "zoe@corp.example")
ANA_ID=$(create_user "ana" "Ana" "Folau" "ana@corp.example")
BRAN_ID=$(create_user "bran" "Bran" "Stark" "bran@corp.example")
CLEO_ID=$(create_user "cleo" "Cleo" "Selene" "cleo@corp.example")
DANI_ID=$(create_user "dani" "Dani" "Moonstar" "dani@corp.example")
echo "    additional users created."

# ── Custom claims on users ─────────────────────────────────────────────────────

echo "==> Setting user custom claims..."

set_user_claims() {
    local uid="$1"
    shift
    api PUT "/api/custom-claims/user/${uid}" -d "$@" >/dev/null || true
}

if [ -n "$ALICE_ID" ]; then
    set_user_claims "$ALICE_ID" '[
      {"key":"loginShell","value":"/bin/zsh"},
      {"key":"homeDirectory","value":"/home/alice"},
      {"key":"sshPublicKey","value":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAlicePrimaryKey alice@corp.example"},
      {"key":"sshPublicKey","value":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAliceWorkLaptop work-laptop"}
    ]'
fi

if [ -n "$BOB_ID" ]; then
    set_user_claims "$BOB_ID" '[
      {"key":"loginShell","value":"/bin/bash"},
      {"key":"homeDirectory","value":"/home/bob"},
      {"key":"sshPublicKey","value":"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQBobBuilder bob@corp.example"}
    ]'
fi

if [ -n "$GRACE_ID" ]; then
    set_user_claims "$GRACE_ID" '[
      {"key":"loginShell","value":"/bin/bash"},
      {"key":"homeDirectory","value":"/home/grace"},
      {"key":"sshPublicKey","value":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGraceHopperKey grace@corp.example"}
    ]'
fi

if [ -n "$NEIL_ID" ]; then
    set_user_claims "$NEIL_ID" '[
      {"key":"loginShell","value":"/bin/zsh"},
      {"key":"homeDirectory","value":"/home/neil"},
      {"key":"sshPublicKey","value":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINeilSecKey neil@corp.example"}
    ]'
fi

echo "    User claims set."

# ── Create groups ──────────────────────────────────────────────────────────────

echo "==> Creating groups..."

create_group() {
    local name="$1" friendly="$2"
    api POST /api/user-groups -d "{
      \"name\": \"${name}\",
      \"friendlyName\": \"${friendly}\"
    }" | json_field id
}

ADMINS_GRP=$(create_group "admins" "Administrators")
check_or_die "$ADMINS_GRP" "admins group"

DEVS_GRP=$(create_group "developers" "Developers")
OPS_GRP=$(create_group "sre" "Site Reliability Engineering")
DATA_GRP=$(create_group "data-team" "Data & ML")
SEC_GRP=$(create_group "security" "Security")
QA_GRP=$(create_group "qa" "QA & Testing")
SUPPORT_GRP=$(create_group "support" "Support")
READONLY_GRP=$(create_group "readonly" "Read-Only Access")
DEPLOY_GRP=$(create_group "deploy-agents" "Deployment Agents")
echo "    admins=${ADMINS_GRP} developers=${DEVS_GRP} sre=${OPS_GRP} data=${DATA_GRP} security=${SEC_GRP} qa=${QA_GRP} support=${SUPPORT_GRP} readonly=${READONLY_GRP} deploy=${DEPLOY_GRP}"

# ── Sudo custom claims on groups ───────────────────────────────────────────────

echo "==> Setting group sudo claims..."

set_group_claims() {
    local gid="$1"
    shift
    api PUT "/api/custom-claims/user-group/${gid}" -d "$@" >/dev/null || true
}

# admins: full root on all hosts, no password
if [ -n "$ADMINS_GRP" ]; then
    set_group_claims "$ADMINS_GRP" '[
      {"key":"sudoCommands","value":"ALL"},
      {"key":"sudoHosts","value":"ALL"},
      {"key":"sudoRunAsUser","value":"root"},
      {"key":"sudoOptions","value":"NOPASSWD"}
    ]'
fi

# developers: apt and systemctl on all hosts
if [ -n "$DEVS_GRP" ]; then
    set_group_claims "$DEVS_GRP" '[
      {"key":"sudoCommands","value":"/usr/bin/apt,/usr/bin/apt-get,/usr/bin/systemctl,/usr/bin/journalctl"},
      {"key":"sudoHosts","value":"ALL"},
      {"key":"sudoRunAsUser","value":"root"}
    ]'
fi

# sre: broader access, no password required, limited to prod hosts
if [ -n "$OPS_GRP" ]; then
    set_group_claims "$OPS_GRP" '[
      {"key":"sudoCommands","value":"/usr/bin/systemctl,/usr/sbin/service,/usr/bin/journalctl,/usr/bin/docker,/usr/local/bin/kubectl"},
      {"key":"sudoHosts","value":"prod-web-01,prod-web-02,prod-db-01,prod-lb-01"},
      {"key":"sudoRunAsUser","value":"root"},
      {"key":"sudoOptions","value":"NOPASSWD"}
    ]'
fi

# data-team: python/jupyter tooling on data hosts only
if [ -n "$DATA_GRP" ]; then
    set_group_claims "$DATA_GRP" '[
      {"key":"sudoCommands","value":"/usr/bin/python3,/usr/local/bin/pip,/usr/bin/spark-submit"},
      {"key":"sudoHosts","value":"data-worker-01,data-worker-02,data-worker-03"},
      {"key":"sudoRunAsUser","value":"root"}
    ]'
fi

# security: read-only audit tooling everywhere
if [ -n "$SEC_GRP" ]; then
    set_group_claims "$SEC_GRP" '[
      {"key":"sudoCommands","value":"/usr/bin/auditctl,/usr/sbin/ss,/usr/bin/netstat,/usr/bin/lsof"},
      {"key":"sudoHosts","value":"ALL"},
      {"key":"sudoRunAsUser","value":"root"},
      {"key":"sudoOptions","value":"NOPASSWD"}
    ]'
fi

# qa: test runners only on staging
if [ -n "$QA_GRP" ]; then
    set_group_claims "$QA_GRP" '[
      {"key":"sudoCommands","value":"/usr/bin/pytest,/usr/bin/npm,/usr/bin/yarn"},
      {"key":"sudoHosts","value":"staging-01,staging-02"},
      {"key":"sudoRunAsUser","value":"root"}
    ]'
fi

# deploy-agents: CI/CD deployment scripts with no password
if [ -n "$DEPLOY_GRP" ]; then
    set_group_claims "$DEPLOY_GRP" '[
      {"key":"sudoCommands","value":"/usr/local/bin/deploy.sh,/usr/bin/docker,/usr/local/bin/kubectl,/usr/bin/systemctl restart"},
      {"key":"sudoHosts","value":"prod-web-01,prod-web-02,staging-01,staging-02"},
      {"key":"sudoRunAsUser","value":"root"},
      {"key":"sudoOptions","value":"NOPASSWD"}
    ]'
fi

# readonly: no sudo at all
if [ -n "$READONLY_GRP" ]; then
    set_group_claims "$READONLY_GRP" '[
      {"key":"sudoCommands","value":"/usr/bin/cat,/usr/bin/less,/usr/bin/tail"},
      {"key":"sudoHosts","value":"ALL"},
      {"key":"sudoRunAsUser","value":"root"}
    ]'
fi

echo "    Group claims set."

# ── Assign users to groups ─────────────────────────────────────────────────────

echo "==> Assigning users to groups..."

add_members() {
    local gid="$1"
    shift
    # Build JSON array of quoted IDs
    local ids=""
    for id in "$@"; do
        [ -z "$id" ] && continue
        ids="${ids}\"${id}\","
    done
    ids="[${ids%,}]"
    api PUT "/api/user-groups/${gid}/users" -d "{\"userIds\":${ids}}" >/dev/null || true
}

if [ -n "$ADMINS_GRP" ]; then
    add_members "$ADMINS_GRP" "$ADMIN_ID"
fi

if [ -n "$DEVS_GRP" ]; then
    add_members "$DEVS_GRP" "$ALICE_ID" "$BOB_ID" "$CAROL_ID" "$DAVE_ID" "$EVE_ID" "$FRANK_ID" "$VICTOR_ID" "$WENDY_ID"
fi

if [ -n "$OPS_GRP" ]; then
    add_members "$OPS_GRP" "$GRACE_ID" "$HEIDI_ID" "$IVAN_ID" "$JUDY_ID"
fi

if [ -n "$DATA_GRP" ]; then
    add_members "$DATA_GRP" "$KATE_ID" "$LIAM_ID" "$MAYA_ID" "$XAVIER_ID" "$YARA_ID"
fi

if [ -n "$SEC_GRP" ]; then
    add_members "$SEC_GRP" "$NEIL_ID" "$OLIVIA_ID"
fi

if [ -n "$QA_GRP" ]; then
    add_members "$QA_GRP" "$PEDRO_ID" "$QUINN_ID" "$RACHEL_ID"
fi

if [ -n "$SUPPORT_GRP" ]; then
    add_members "$SUPPORT_GRP" "$SAM_ID" "$TARA_ID" "$ANA_ID" "$BRAN_ID"
fi

if [ -n "$READONLY_GRP" ]; then
    add_members "$READONLY_GRP" "$CLEO_ID" "$DANI_ID" "$ZOE_ID"
fi

if [ -n "$DEPLOY_GRP" ]; then
    add_members "$DEPLOY_GRP" "$GRACE_ID" "$HEIDI_ID"
fi

echo "    Group memberships set."

# ── Trigger identree LDAP sync ─────────────────────────────────────────────────

echo "==> Triggering identree directory sync..."
# Poke the webhook endpoint to force an immediate refresh (secret not set so it
# may return 400, but the presence of identree data is what matters; we also
# just wait for the automatic refresh below).
curl -sf -X POST "${IDENTREE_URL}/api/webhook/pocketid" \
    -H "Content-Type: application/json" \
    -d '{}' >/dev/null 2>&1 || true

echo "    Waiting 15s for LDAP refresh cycle..."
sleep 15

# ── Seed approved sessions ──────────────────────────────────────────────────────

echo "==> Creating approved sessions..."

seed_session() {
    local username="$1"
    local hostname="$2"
    curl -sf -X POST "${IDENTREE_URL}/dev/seed-session" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${username}\",\"hostname\":\"${hostname}\"}" >/dev/null
}

seed_session "alice"   "prod-web-01"
seed_session "alice"   "prod-web-02"
seed_session "bob"     "prod-db-01"
seed_session "carol"   "staging-01"
seed_session "grace"   "prod-lb-01"
seed_session "grace"   "prod-web-01"
seed_session "heidi"   "prod-db-01"
seed_session "ivan"    "prod-web-02"
seed_session "dave"    "staging-02"
seed_session "neil"    "prod-web-01"
seed_session "olivia"  "prod-db-01"
seed_session "frank"   "staging-01"

echo "    12 approved sessions created."

# ── Seed pending challenges ─────────────────────────────────────────────────────

echo "==> Creating pending challenges..."

create_challenge() {
    local username="$1"
    local hostname="$2"
    local reason="${3:-}"
    local body="{\"username\":\"${username}\",\"hostname\":\"${hostname}\"}"
    if [ -n "$reason" ]; then
        body="{\"username\":\"${username}\",\"hostname\":\"${hostname}\",\"reason\":\"${reason}\"}"
    fi
    curl -sf -X POST "${IDENTREE_URL}/api/challenge" \
        -H "Content-Type: application/json" \
        -H "X-Shared-Secret: test-shared-secret-1234567890abc" \
        -d "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('challenge_id',''))" 2>/dev/null || true
}

PENDING_1=$(create_challenge "kate"   "data-worker-01" "Routine maintenance")
PENDING_2=$(create_challenge "liam"   "prod-web-01"    "Incident response")
PENDING_3=$(create_challenge "maya"   "staging-01"     "Deployment")
export CI_PENDING_CHALLENGE_1="$PENDING_1"

echo "    Pending challenge IDs: ${PENDING_1} ${PENDING_2} ${PENDING_3}"
echo "    CI_PENDING_CHALLENGE_1=${PENDING_1}" > /tmp/identree-ci-env.sh

# ── Seed action history (spread over past 24 hours) ────────────────────────────

echo "==> Seeding action history..."

curl -sf -X POST "${IDENTREE_URL}/dev/seed-history" \
    -H "Content-Type: application/json" \
    -d '[
      {"username":"alice",  "action":"approved",      "hostname":"prod-web-01",    "actor":"testadmin", "minutes_ago":5},
      {"username":"bob",    "action":"approved",      "hostname":"prod-db-01",     "actor":"testadmin", "minutes_ago":18},
      {"username":"grace",  "action":"approved",      "hostname":"prod-lb-01",     "actor":"testadmin", "minutes_ago":34},
      {"username":"carol",  "action":"approved",      "hostname":"staging-01",     "actor":"testadmin", "minutes_ago":47},
      {"username":"alice",  "action":"revoked",       "hostname":"prod-web-01",    "actor":"testadmin", "minutes_ago":62},
      {"username":"dave",   "action":"approved",      "hostname":"staging-02",     "actor":"testadmin", "minutes_ago":78},
      {"username":"heidi",  "action":"approved",      "hostname":"prod-db-01",     "actor":"testadmin", "minutes_ago":95},
      {"username":"ivan",   "action":"approved",      "hostname":"prod-web-02",    "actor":"testadmin", "minutes_ago":110},
      {"username":"alice",  "action":"approved",      "hostname":"prod-web-01",    "actor":"testadmin", "minutes_ago":128},
      {"username":"neil",   "action":"approved",      "hostname":"prod-web-01",    "actor":"testadmin", "minutes_ago":145},
      {"username":"frank",  "action":"approved",      "hostname":"staging-01",     "actor":"testadmin", "minutes_ago":162},
      {"username":"olivia", "action":"approved",      "hostname":"prod-db-01",     "actor":"testadmin", "minutes_ago":180},
      {"username":"bob",    "action":"revoked",       "hostname":"prod-db-01",     "actor":"testadmin", "minutes_ago":198},
      {"username":"grace",  "action":"approved",      "hostname":"prod-web-01",    "actor":"testadmin", "minutes_ago":215},
      {"username":"carol",  "action":"auto_approved", "hostname":"staging-01",     "actor":"",          "minutes_ago":232},
      {"username":"dave",   "action":"approved",      "hostname":"staging-02",     "actor":"testadmin", "minutes_ago":250},
      {"username":"alice",  "action":"approved",      "hostname":"prod-web-02",    "actor":"testadmin", "minutes_ago":268},
      {"username":"heidi",  "action":"revoked",       "hostname":"prod-db-01",     "actor":"testadmin", "minutes_ago":285},
      {"username":"ivan",   "action":"approved",      "hostname":"prod-web-01",    "actor":"testadmin", "minutes_ago":302},
      {"username":"kate",   "action":"approved",      "hostname":"data-worker-01", "actor":"testadmin", "minutes_ago":320},
      {"username":"liam",   "action":"approved",      "hostname":"data-worker-02", "actor":"testadmin", "minutes_ago":338},
      {"username":"neil",   "action":"auto_approved", "hostname":"prod-web-01",    "actor":"",          "minutes_ago":355},
      {"username":"grace",  "action":"approved",      "hostname":"prod-lb-01",     "actor":"testadmin", "minutes_ago":373},
      {"username":"frank",  "action":"revoked",       "hostname":"staging-01",     "actor":"testadmin", "minutes_ago":390},
      {"username":"bob",    "action":"approved",      "hostname":"prod-db-01",     "actor":"testadmin", "minutes_ago":408},
      {"username":"alice",  "action":"approved",      "hostname":"prod-web-01",    "actor":"testadmin", "minutes_ago":425},
      {"username":"olivia", "action":"approved",      "hostname":"prod-web-02",    "actor":"testadmin", "minutes_ago":443},
      {"username":"dave",   "action":"auto_approved", "hostname":"staging-02",     "actor":"",          "minutes_ago":460},
      {"username":"carol",  "action":"approved",      "hostname":"staging-01",     "actor":"testadmin", "minutes_ago":478},
      {"username":"heidi",  "action":"approved",      "hostname":"prod-db-01",     "actor":"testadmin", "minutes_ago":495},
      {"username":"ivan",   "action":"revoked",       "hostname":"prod-web-02",    "actor":"testadmin", "minutes_ago":512},
      {"username":"kate",   "action":"approved",      "hostname":"data-worker-01", "actor":"testadmin", "minutes_ago":530},
      {"username":"liam",   "action":"approved",      "hostname":"data-worker-03", "actor":"testadmin", "minutes_ago":548},
      {"username":"alice",  "action":"revoked",       "hostname":"prod-web-02",    "actor":"testadmin", "minutes_ago":565},
      {"username":"grace",  "action":"approved",      "hostname":"prod-web-01",    "actor":"testadmin", "minutes_ago":583},
      {"username":"neil",   "action":"approved",      "hostname":"prod-web-01",    "actor":"testadmin", "minutes_ago":600},
      {"username":"frank",  "action":"approved",      "hostname":"staging-01",     "actor":"testadmin", "minutes_ago":618},
      {"username":"bob",    "action":"auto_approved", "hostname":"prod-db-01",     "actor":"",          "minutes_ago":635},
      {"username":"maya",   "action":"approved",      "hostname":"data-worker-02", "actor":"testadmin", "minutes_ago":1200},
      {"username":"alice",  "action":"approved",      "hostname":"prod-web-01",    "actor":"testadmin", "minutes_ago":1380}
    ]' >/dev/null

echo "    History entries injected."

# ── Seed break-glass escrow passwords ─────────────────────────────────────────

echo "==> Seeding break-glass escrow passwords..."

SHARED_SECRET="test-shared-secret-1234567890abc"

escrow_password() {
    local hostname="$1"
    local password="$2"
    # Compute HMAC escrow token: deriveKey(sharedSecret, "escrow") then HMAC("escrow:hostname:ts")
    local ts
    ts=$(date +%s)
    local token
    token=$(python3 -c "
import hmac, hashlib
key = hmac.new(b'${SHARED_SECRET}', b'escrow', hashlib.sha256).digest()
print(hmac.new(key, ('escrow:${hostname}:${ts}').encode(), hashlib.sha256).hexdigest())
")
    curl -sf -X POST "${IDENTREE_URL}/api/breakglass/escrow" \
        -H "Content-Type: application/json" \
        -H "X-Shared-Secret: ${SHARED_SECRET}" \
        -H "X-Escrow-Ts: ${ts}" \
        -H "X-Escrow-Token: ${token}" \
        -d "{\"hostname\":\"${hostname}\",\"password\":\"${password}\"}" >/dev/null
}

escrow_password "prod-web-01"      "K7#mPx!4qRz@9LvN2wYs"
escrow_password "prod-web-02"      "Bw3&fGn!8TpJ#5xMc@Yq"
escrow_password "prod-db-01"       "H9$kLm@2vXnR!7pZq#Wd"
escrow_password "prod-lb-01"       "Qx5!rTn#3JwK@8mPv$Yz"
escrow_password "staging-01"       "Dn6@wMp!4vRx#9LkJ$Qs"
escrow_password "staging-02"       "Fg8#bYn!2TqK@5xMw$Lz"
escrow_password "data-worker-01"   "Jv4!pRm#7XnL@3wKq$Ys"

echo "    7 break-glass passwords escrowed."

echo ""
echo "==> Seed complete."
echo "    PocketID users/groups, 13 approved sessions, 3 pending challenges, and 7 break-glass passwords created."
echo ""
