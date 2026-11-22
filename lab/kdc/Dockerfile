FROM debian:bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends krb5-kdc krb5-admin-server krb5-user \
 && rm -rf /var/lib/apt/lists/*
COPY krb5.conf /etc/krb5.conf
COPY kdc/kdc.conf /etc/krb5kdc/kdc.conf
COPY kdc/entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
