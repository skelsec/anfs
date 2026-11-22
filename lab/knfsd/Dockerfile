FROM debian:bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nfs-kernel-server rpcbind kmod procps \
 && rm -rf /var/lib/apt/lists/*
COPY knfsd/exports /etc/exports
COPY knfsd/nfs.conf /etc/nfs.conf
COPY storage.sh fixtures.sh knfsd/entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
