#!/bin/bash

sudo apt-get update

sudo apt-get -y install build-essential make autoconf automake

sudo apt-get -y install libgmp-dev libsystemd-dev libcurl4-openssl-dev libldap-dev libtss2-dev libgcrypt20-dev libpam0g-dev libip4tc-dev pkg-config init libtss2-tcti-tabrmd0


pushd ~

curl -L https://github.com/strongswan/strongswan/releases/download/6.0.1/strongswan-6.0.1.tar.gz -o strongswan-6.0.1.tar.gz

tar -xzf strongswan-6.0.1.tar.gz

pushd strongswan-6.0.1

./configure --prefix=/usr --sysconfdir=/etc --enable-charon --enable-systemd \
--disable-defaults \
--enable-static \
--enable-test-vectors \
--enable-pki --enable-ikev2 --enable-vici --enable-swanctl \
--enable-ldap \
--enable-pkcs11 \
--enable-tpm \
--enable-aesni \
--enable-aes \
--enable-rc2 \
--enable-sha2 \
--enable-sha1 \
--enable-md5 \
--enable-mgf1 \
--enable-rdrand \
--enable-random \
--enable-nonce \
--enable-x509 \
--enable-revocation \
--enable-constraints \
--enable-pubkey \
--enable-pkcs1 \
--enable-pkcs7 \
--enable-pkcs8 \
--enable-pkcs12 \
--enable-pgp \
--enable-dnskey \
--enable-sshkey \
--enable-pem \
--enable-openssl \
--enable-gcrypt \
--enable-af-alg \
--enable-fips-prf  \
--enable-gmp  \
--enable-curve25519 \
--enable-agent \
--enable-chapoly \
--enable-xcbc \
--enable-cmac \
--enable-hmac \
--enable-ctr \
--enable-ccm \
--enable-gcm \
--enable-ntru \
--enable-drbg \
--enable-curl \
--enable-attr \
--enable-kernel-netlink \
--enable-resolve \
--enable-socket-default \
--enable-connmark \
--enable-forecast \
--enable-farp \
--enable-stroke \
--enable-vici \
--enable-updown \
--enable-eap-identity \
--enable-eap-aka \
--enable-eap-md5 \
--enable-eap-gtc \
--enable-eap-mschapv2 \
--enable-eap-dynamic \
--enable-eap-radius \
--enable-eap-tls \
--enable-eap-ttls \
--enable-eap-peap \
--enable-eap-tnc \
--enable-xauth-generic \
--enable-xauth-eap \
--enable-xauth-pam \
--enable-tnc-tnccs \
--enable-dhcp \
--enable-lookip \
--enable-error-notify \
--enable-certexpire \
--enable-led \
--enable-addrblock \
--enable-unity \
--enable-counters \
--enable-whitelist 

make

sudo make install

popd

popd


sudo systemctl enable strongswan

sudo systemctl start strongswan

pushd ~

git clone https://github.com/xdp-project/xdp-tools

sudo apt update

sudo apt install -y clang llvm libelf-dev libpcap-dev libc6-dev-i386 m4

sudo apt install -y linux-tools-$(uname -r)

sudo apt install -y linux-headers-$(uname -r)

pushd xdp-tools

./configure

popd

pushd xdp-tools

make

sudo make install

popd


pushd xdp-tools/lib/libbpf/src

sudo make install

popd

popd
