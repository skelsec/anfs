FROM debian:bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nfs-kernel-server rpcbind kmod procps krb5-user \
 && rm -rf /var/lib/apt/lists/*
COPY knfsd/exports /etc/exports
COPY knfsd/nfs.conf /etc/nfs.conf
COPY krb5.conf idmapd.conf /etc/
COPY storage.sh fixtures.sh krb5.sh knfsd/entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
