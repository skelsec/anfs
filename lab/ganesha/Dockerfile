FROM debian:bookworm-slim
# netbase provides /etc/services, without it rpcbind silently binds no ports
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nfs-ganesha nfs-ganesha-vfs rpcbind netbase dbus procps krb5-user \
 && rm -rf /var/lib/apt/lists/*
COPY ganesha/ganesha.conf /etc/ganesha/ganesha.conf
COPY krb5.conf idmapd.conf /etc/
COPY storage.sh fixtures.sh krb5.sh ganesha/entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
