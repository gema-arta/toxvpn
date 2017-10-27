# ToxVPN

ToxVPN is fully decentralized VPN solution for you.
It uses libtoxcore and libsodium as trasnport/authentication framework to ensure the proper level of security. ToxVPN doesn't need central server like OpenVPN or CiscoVPN and provides sufficient level of security thought using libsodium.

## Building
[![pipeline status](https://gitlab.com/denis4net/toxvpn/badges/master/pipeline.svg)](https://gitlab.com/denis4net/toxvpn/commits/master)

`make all`

## Installation

```
$ export OUTFILE=toxvpn
$ export PREFIX=/usr
$ install -m 0755 $(OUTFILE)  $(PREFIX)/bin/$(OUTFILE)
$ mkdir -p $(PREFIX)/lib/systemd/system/
```

You can set net_admin capabilities if you don't wan to execute `toxvpn` with root permissions
`$ setcap cap_net_admin+ep $(PREFIX)/bin/$(OUTFILE)`

Then create a folder for service files
`# mkdir -p /var/run/toxvpn`

Now you can execute it:

```
usage: ./toxvpn options
-h      show help
-s <secret>  use passed hex secret
-p <proxy>   use socks|http://hostname:port> proxy server
-n <subnetwork/prefix length>
-c <address>:<secret>    connect to server using tox address
-f <file>   load/save settings from/to file
```

## Usage

Start a master node:

```
$ /usr/bin/toxvpn
Starting toxvpn 0.0.988608 593a5165de7dbcef9b0d9f7cdecc03b28fecd3b3
Hostname: denis-book
Your address 6WJw9C7rdY5cC3NbEVtWRpr4ZQHHKPAF91Ud17x4hk3vYbuZp6Rc:52CiKXtQ4jJhB2y94q63kfXZwNd1BWmQKKN1m2c2j7W4
Listening on 33445/udp 0/tcp
[25] Added address 10.239.205.236 on "tun0"
[25] created interface "tun0" 10.239.205.236/24
[25] Connecting to "185.25.116.107:33445" DHT node
[25] Connecting to "198.46.138.44:33445" DHT node
[25] connected to DHT via UDP
^T[25] Received Tox friend request from 6B593C02E5C99192 with attached secret "3BBD925FC39BC17D1246A95465C2F7A5ABF6027CB7A7B7C44FA81DE8B2DE602D"
[25] Approved friend 0 with PK 9291C9E5023C596BBD0A2EB10840CBF5FC8A22018D6A69FB93DE73360FB17566
[25] Connected friend 0 via UDP
[25] Received membership response - toxvpn_id: A982A6C5, friendnumber: 0, flags: 1
[25] broadcast new members table. Reason: new member was added
```

Copy master-node address `6WJw9C7rdY5cC3NbEVtWRpr4ZQHHKPAF91Ud17x4hk3vYbuZp6Rc:52CiKXtQ4jJhB2y94q63kfXZwNd1BWmQKKN1m2c2j7W4`. And use it for executing other clients:

```
toxvpn -c 6WJw9C7rdY5cC3NbEVtWRpr4ZQHHKPAF91Ud17x4hk3vYbuZp6Rc:52CiKXtQ4jJhB2y94q63kfXZwNd1BWmQKKN1m2c2j7W4
Starting toxvpn 0.0.988608 593a5165de7dbcef9b0d9f7cdecc03b28fecd3b3
Hostname: denis-book
Your address NgYTLGXGyihxyUqcRrtvrRvTuqKsQCpHLDZmZbVxtnV1kabPHa4z:52CiKXtQ4jJhB2y94q63kfXZwNd1BWmQKKN1m2c2j7W4
Listening on 33446/udp 0/tcp
[92] Added node 6WJw9C7rdY5cC3NbEVtWRpr4ZQHHKPAF91Ud17x4hk3vYbuZp6Rc
[92] Connecting to "198.98.51.198:443" DHT node
[92] Connecting to "198.98.51.198:443" DHT node
[92] connected to DHT via UDP
[92] Connected friend 0 via UDP
[92] created interface "" 10.239.205.229/24
[92] Received request - toxvpn_id: A982A6C5, friendnumber: 0, flags: 0
[92] Added address 10.239.205.229 on "tun1"
[92] sending a toxvpn invitation response to 0
[0x1f77848] added vpn member 10.239.205.236:0 to table
[0x1f77848] added vpn member 10.239.205.229:-2 to table
[92] broadcast new members table. Reason: new members table was received
```

The file `/var/run/toxvpn-members.$pid` is memory-mapped file which contains mesh network information, including IP addresses and public addresses of participiating nodes.

```
$ cat /var/run/toxvpn-members.16072
vpn A982A6C5 2
10.239.205.236  25375AEC67FFC7077BD5D4D5295FA72E9B01A349FB0CF7C22DF4302D185EE476    node-hostname.0
10.239.205.229  9291C9E5023C596BBD0A2EB10840CBF5FC8A22018D6A69FB93DE73360FB17566    node-hostname.1
```