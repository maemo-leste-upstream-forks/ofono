#!/bin/sh

set -e

# Filelist:
# grep -oE 'ell/.*\.(h|c)( |$)' ../Makefile.am

filelist="
ell/ell.h
ell/util.h
ell/test.h
ell/strv.h
ell/utf8.h
ell/queue.h
ell/hashmap.h
ell/string.h
ell/settings.h
ell/main.h
ell/idle.h
ell/signal.h
ell/timeout.h
ell/io.h
ell/ringbuf.h
ell/log.h
ell/checksum.h
ell/netlink.h
ell/genl.h
ell/rtnl.h
ell/dbus.h
ell/dbus-service.h
ell/dbus-client.h
ell/hwdb.h
ell/cipher.h
ell/random.h
ell/uintset.h
ell/base64.h
ell/pem.h
ell/tls.h
ell/uuid.h
ell/key.h
ell/file.h
ell/dir.h
ell/net.h
ell/dhcp.h
ell/dhcp6.h
ell/cert.h
ell/ecc.h
ell/ecdh.h
ell/time.h
ell/gpio.h
ell/path.h
ell/icmp6.h
ell/acd.h
ell/tester.h
ell/cleanup.h
ell/private.h
ell/useful.h
ell/missing.h
ell/util.c
ell/test.c
ell/strv.c
ell/utf8.c
ell/queue.c
ell/hashmap.c
ell/string.c
ell/settings.c
ell/main-private.h
ell/main.c
ell/idle.c
ell/signal.c
ell/timeout.c
ell/io.c
ell/ringbuf.c
ell/log.c
ell/checksum.c
ell/netlink-private.h
ell/netlink.c
ell/genl.c
ell/rtnl.c
ell/dbus-private.h
ell/dbus.c
ell/dbus-message.c
ell/dbus-util.c
ell/dbus-service.c
ell/dbus-client.c
ell/dbus-name-cache.c
ell/dbus-filter.c
ell/gvariant-private.h
ell/gvariant-util.c
ell/siphash-private.h
ell/siphash.c
ell/hwdb.c
ell/cipher.c
ell/random.c
ell/uintset.c
ell/base64.c
ell/asn1-private.h
ell/pem-private.h
ell/pem.c
ell/tls-private.h
ell/tls.c
ell/tls-record.c
ell/tls-extensions.c
ell/tls-suites.c
ell/uuid.c
ell/key.c
ell/file.c
ell/dir.c
ell/net-private.h
ell/net.c
ell/dhcp-private.h
ell/dhcp.c
ell/dhcp-transport.c
ell/dhcp-lease.c
ell/dhcp6-private.h
ell/dhcp6.c
ell/dhcp6-transport.c
ell/dhcp6-lease.c
ell/dhcp-util.c
ell/dhcp-server.c
ell/cert-private.h
ell/cert.c
ell/cert-crypto.c
ell/ecc-private.h
ell/ecc.h
ell/ecc-external.c
ell/ecc.c
ell/ecdh.c
ell/time.c
ell/time-private.h
ell/gpio.c
ell/path.c
ell/icmp6.c
ell/icmp6-private.h
ell/acd.c
ell/tester.c
"

mkdir -p ../ell

cd ../ell
touch internal

git clone --depth 1 https://git.kernel.org/pub/scm/libs/ell/ell.git

cd ell
cp -va $filelist ..

cd ..
rm -rf ell
