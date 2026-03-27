#!/bin/bash
set -e

LDAP_URI="${LDAP_URI:-ldap://identree:3389}"
LDAP_BASE="${LDAP_BASE:-dc=test,dc=local}"

# Write nslcd.conf
cat > /etc/nslcd.conf <<EOF
uid nslcd
gid nslcd

uri ${LDAP_URI}
base ${LDAP_BASE}

base passwd ou=people,${LDAP_BASE}
base group  ou=groups,${LDAP_BASE}
base shadow ou=people,${LDAP_BASE}

filter passwd (objectClass=posixAccount)
filter group  (objectClass=posixGroup)

map passwd uid              uid
map passwd uidNumber        uidNumber
map passwd gidNumber        gidNumber
map passwd homeDirectory    homeDirectory
map passwd loginShell       loginShell
map passwd gecos            cn

ldap_version 3
bind_timelimit 10
timelimit 10
idle_timelimit 60
EOF

chmod 640 /etc/nslcd.conf

# Start nslcd in background
nslcd
echo "nslcd started"

# Execute CMD
exec "$@"
