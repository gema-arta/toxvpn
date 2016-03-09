#ifndef TOXVPN_INTERAL_H
#define TOXVPN_INTERAL_H

#define INTERFACE_NAME_SIZE 128
#define TOXVPN_DEVTUN 1     //os support /dev/tun interface

#define TOXVPN_PACKET_TYPE_INVALID 0
#define TOXVPN_PACKET_TYPE_MEMBERSHIP_REQUEST 1
#define TOXVPN_PACKET_TYPE_MEMBERSHIP_RESPONSE 2
#define TOXVPN_PACKET_TYPE_IPv4_PACKET 10
#define TOXVPN_PACKET_TYPE_IPv6_PACKET 11
#define TOXVPN_PACKET_TYPE_MEMBERS_TABLE 20
#define TOXVPN_PACKET_TYPE_GET_MEMBERS_TABLE 21

#include <tox/tox.h>
#include "toxvpn.h"
#include "network.h"
#include <stdlib.h>
#include <stdint.h>
#include <netinet/ip.h>

#define INVALID_FD -1
#define _POSIX_C_SOURCE 200900
struct VPNAddress {
    IP ip;
    IP subnet;
    uint8_t prefix;
};

struct VPNMember {
    struct { //< Serializable part of vpn member record
        IP ip;
        uint8_t status;
        time_t update_timestamp;                //< timestamp of entry update. Update user pk will be in issuer_pk
        uint8_t member_pk[TOX_PUBLIC_KEY_SIZE]; //NOTE: duplicate friendnumber
        uint8_t issuer_pk[TOX_PUBLIC_KEY_SIZE]; //< the public key of a VPNMember issuer
        //TODO: add signature, signed by issuer private key
    };

    uint32_t friendnumber;
    time_t last_packet_recv_timestamp;
    time_t last_packet_sent_timestamp;
};

typedef struct VPNMembersTable {
    struct VPNMember *members;
    size_t count;
    size_t capacity;
} VPNMembersTable;

typedef struct VPNInterface {
    char name[INTERFACE_NAME_SIZE];
    uint8_t shareid[TOXVPN_SHAREID_SIZE];
#if defined(TOXVPN_DEVTUN)
    int fd;
#endif
    ToxVPNContext *context;
    uint32_t id;
    struct VPNMembersTable members_table;
    struct VPNAddress address;
    struct {
        int no;
        const char *description;
    } error;

    bool autoadd_friends;

    struct {
        uint8_t buffer[TOXVPN_MTU];
        size_t actual_size; ///< actual read data size
        size_t packet_size; ///< packet size of packet to receive
    } read_buffer;

} VPNInterface;

/**
 * NOTE: All Packet headers store data in network (BE) order
 */

struct SerializedVPNMember {
    struct {
        uint8_t family;
        uint8_t data[16]; //< there can be IPv4 or IPv4 address data. IPv4 starts from first bytes.
    } ip;

    uint8_t member_pk[TOX_PUBLIC_KEY_SIZE];
    int32_t update_timestamp;               //< should be stored in network (BE) order
    uint8_t issuer_pk[TOX_PUBLIC_KEY_SIZE]; //< the public key of a VPNMember issuer
    //TODO: add signature of the record
    uint8_t status;
} __attribute__((packed));

struct VPNPacketHeader {
    uint8_t tox_packet_type;
    uint8_t type;
    uint8_t shareid[TOXVPN_SHAREID_SIZE];
} __attribute__((packed));

struct VPNMembershipRequestPacket {
    struct VPNPacketHeader header;
    IP subnet;
    uint8_t prefix;
    uint8_t flags;
} __attribute__((packed));

struct VPNMembershipResponsePacket {
    struct VPNPacketHeader header;
    uint8_t flags;
} __attribute__((packed));

struct VPNMembersTablePacketHeader {
    struct VPNPacketHeader header;
    uint32_t payload_size;
} __attribute__((packed));

#endif // TOXVPN_INTERAL_H

