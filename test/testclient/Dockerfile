FROM golang:1.26 AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /app/identree ./cmd/identree/

FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    sssd \
    sssd-ldap \
    sssd-tools \
    libpam-sss \
    libnss-sss \
    libsss-sudo \
    ldap-utils \
    curl \
    iproute2 \
    iputils-ping \
    ca-certificates \
    sudo \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/identree /usr/local/bin/identree

# nsswitch.conf: use sss for passwd, group, and sudoers lookups.
# shadow stays files-only (no LDAP password auth — identree handles auth).
# automount removed (not configured).
RUN sed -i \
    -e 's/^passwd:.*/passwd:         files sss/' \
    -e 's/^group:.*/group:          files sss/' \
    -e 's/^shadow:.*/shadow:         files/' \
    -e '/^automount:/d' \
    -e 's/^sudoers:.*/sudoers:        files sss/' \
    /etc/nsswitch.conf && \
    grep -q '^sudoers:' /etc/nsswitch.conf || echo 'sudoers:        files sss' >> /etc/nsswitch.conf

# PAM sudo: identree is the sole auth provider.
# Replacing @include common-auth entirely prevents the pam_deny.so
# requisite in common-auth from firing after identree approves the request
# (pam_unix and pam_sss both fail for LDAP users with auth_provider=none,
# which causes pam_deny to trigger and kill auth regardless of identree's result).
# account and session keep the standard Ubuntu includes.
RUN printf '#%%PAM-1.0\nauth    required    pam_exec.so    stdout /usr/local/bin/identree\n@include common-account\n@include common-session-noninteractive\n' \
    > /etc/pam.d/sudo
# sudo-i follows the same policy if present
RUN if [ -f /etc/pam.d/sudo-i ]; then cp /etc/pam.d/sudo /etc/pam.d/sudo-i; fi

# pam_mkhomedir: auto-create home dirs for LDAP users on first interactive login
RUN echo 'session optional pam_mkhomedir.so skel=/etc/skel umask=0077' \
    >> /etc/pam.d/common-session

COPY test/testclient/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]
