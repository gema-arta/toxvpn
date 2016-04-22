#!/bin/bash

. arm.in

#  multistrap fakeroot fakechroot

JAIL_PATH=$(mktemp -d)/debian-jessie-${ARCH}
JAIL_SRC_PATH=/tmp/src

DST_PATH=${JAIL_PATH}/${JAIL_SRC_PATH}
ORIGIN_PATH=../

function run() {
  echo "$@"
  fakeroot -- $@
}

export PATH=$PATH:/usr/local/sbin:/usr/sbin:/sbin
fakechroot fakeroot qemu-debootstrap --variant=fakechroot --arch ${ARCH} --include=libcap-dev,libnl-route-3-dev,libnl-3-dev,libjansson-dev,libsodium-dev,linux-user-chroot jessie ${JAIL_PATH} http://ftp.byfly.by/pub/debian
mkdir -p ${DST_PATH}
cp -r ${ORIGIN_PATH}/* ${DST_PATH}/
fakechroot chroot ${JAIL_PATH} /usr/bin/make -C ${JAIL_SRC_PATH} toxcore
fakechroot chroot ${JAIL_PATH} /usr/bin/make -C ${JAIL_SRC_PATH}
