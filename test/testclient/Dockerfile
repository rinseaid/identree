FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nslcd \
    libnss-ldapd \
    libpam-ldapd \
    ldap-utils \
    curl \
    iproute2 \
    iputils-ping \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# nsswitch.conf: use ldap for passwd and group lookups
RUN sed -i \
    -e 's/^passwd:.*/passwd:     files ldap/' \
    -e 's/^group:.*/group:      files ldap/' \
    -e 's/^shadow:.*/shadow:     files/' \
    /etc/nsswitch.conf

# nslcd config is written at container startup via entrypoint
COPY testclient/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]
