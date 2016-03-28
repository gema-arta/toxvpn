# ToxVPN

ToxVPN is fully decentralized VPN solution for you.
It uses libtoxcore and libsodium as trasnport/authentication framework to ensure the proper level of security. ToxVPN doesn't need central server like OpenVPN or CiscoVPN and provides sufficient level of security thought using libsodium.

# Building

## Dependencies

### Ubuntu 15.10

```
echo "deb https://pkg.tox.chat/debian stable wily" | sudo tee /etc/apt/sources.list.d/tox.list
wget -qO - https://pkg.tox.chat/debian/pkg.gpg.key | sudo apt-key add -
sudo apt-get install apt-transport-https
sudo apt-get update
apt install -y libcap-dev libnl-route-3-dev libnl-3-dev libjansson-dev libsodium-dev libtox-dev
```

## Chroot

### ArchLinux
`packer -S binfmt-qemu-static qemu-user-static binfmt-support`

### Debian
`apt install -y -qq qemu-user-static qemu-user-binfmt`

### Boostraping
```
# debootstrap --arch mips --include=libcap-dev,libnl-route-3-dev,libnl-3-dev,libjansson-dev,libsodium-dev,libtox-dev,apt-transport-https,wget,apt jessie debian-jessie-mips ftp://ftp.byfly.by/pub/debian

# cp /usr/bin/qemu-mips-static debian-jessie-mips/usr/bin
# chroot debian-jessie-mips /bin/bash
```
