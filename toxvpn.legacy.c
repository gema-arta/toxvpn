#include <tox/tox.h>
#include "toxvpn_internal.h"
#include "vpn_member.h"
#include "sys_interface.h"
#include "network.h"
#include "ip_packet.h"
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <strings.h>
#include <assert.h>
#include <jansson.h>

static void packet_init(const VPNInterface * const i, struct VPNPacketHeader *header)
{
    bzero(header, sizeof *header);
    memcpy(header->shareid, i->shareid, TOXVPN_SHAREID_SIZE);
}

static bool compute_ip(const uint8_t *nonce, const IP* subnet_addr, uint8_t prefix, IP* out)
{
    assert(subnet_addr->family == AF_INET);

    uint32_t node_address = ((const uint32_t*) nonce)[0];
    ip_init(out, subnet_addr->family == AF_INET6);

    uint32_t mask = 0;
    const size_t iteration_count = ((sizeof(mask) * 8) - prefix);

    int i;
    for (i = 0; i < iteration_count; ++i) {
        mask |= 1 << i;
    }

    mask = htonl(mask);

    //we should avoid situation where is node address equal to address of subnetwork or subnet broadcast
    while ((mask & node_address) == 0 || (mask & node_address) == mask) {
        node_address = rand();
    }

    out->ip4.uint32 = (subnet_addr->ip4.uint32) | (mask & node_address);

    return true;
}

static inline size_t interface_get_count(ToxVPNContext *context)
{
    return context->toxvpn_interfaces.n;
}

static inline VPNInterface *interface_get(const ToxVPNContext *context, int i)
{
    assert(context->toxvpn_interfaces.n > i);
    return ((VPNInterface **) context->toxvpn_interfaces.data)[i];
}

static VPNInterface *interface_find_by_shareid(const ToxVPNContext *context, const uint8_t* shareid)
{
    assert(context->tox);
    assert(shareid);

    for (int j = 0; j < interface_get_count(context->tox); j++) {
        if (memcmp(shareid, interface_get(context->tox, j)->shareid, TOXVPN_SHAREID_SIZE) == 0) {
            return interface_get(context->tox, j);
        }
    }

    return NULL;
}

static VPNInterface *interface_find_by_id(const ToxVPNContext *context, uint32_t id)
{
    assert(id != UINT32_MAX);
    BS_LIST *interfaces = &context->toxvpn_interfaces;

    for (int j = 0; j < interface_get_count(context->tox); j++) {
        if (interfaces->ids[j] == id) {
            return interface_get(context->tox, j);
        }
    }

    return NULL;
}

static bool interface_add(ToxVPNContext *context, const VPNInterface *i)
{
    BS_LIST *interfaces = &context->toxvpn_interfaces;

    if (interface_get_count(context->tox) == 0) {
        bs_list_init(interfaces, sizeof(i), 2);
    }

    return bs_list_add(interfaces, &i, (int) i->id);
}

static int interface_free(VPNInterface* i)
{
    assert(i);

    if (i) {
        sysnet_interface_release(i);
        vpn_members_table_free(&i->members_table);
        free(i);
        return 0;
    } else {
        return -1;
    }
}

static int interface_init_low_level(VPNInterface *i)
{
    if (sysnet_interface_create(i) != 0 || sysnet_interface_up(i) != 0 ||
            sysnet_interface_set_addr(i) != 0 || sysnet_interface_set_mtu(i, TOXVPN_MTU) != 0) {
#if DEBUG
        tox_trace(i->tox, "interface_init_low_level() can't setup devtun");
#endif
        return -1;
    }
    else {
        return 0;
    }
}

static VPNInterface *interface_create(Tox *tox, const char *subnet_str, uint8_t mask_prefix,
                                      const uint8_t *toxvpn_shareid, int init_system_interface)
{
    VPNInterface *i = calloc(sizeof(struct VPNInterface), 1);
    i->fd = INVALID_FD;
    i->tox = tox;

    addr_parse_ip(subnet_str, &i->address.subnet);
    i->address.prefix = mask_prefix;

    //Generate random shareid, if needed
    if (toxvpn_shareid != NULL) {
        memcpy(i->shareid, toxvpn_shareid, TOXVPN_SHAREID_SIZE);
    } else {
        randombytes(i->shareid, TOXVPN_SHAREID_SIZE);
    }

    memcpy(&i->id,  i->shareid, sizeof(i->id));

    //Compute toxvpn IP
    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(tox, pk);
    compute_ip(pk, &i->address.subnet, i->address.prefix, &i->address.ip);

    vpn_members_table_init(&i->members_table);

    if (init_system_interface)
    {
        if (interface_init_low_level(i)) {
            goto error;
        }

        vpn_members_table_add_self(i, &i->members_table);
    }

    tox_trace(tox, "created interface \"%s\" %s/%u",
                 i->name, ip_ntoa(&i->address.ip), (uint32_t) i->address.prefix);

    //TODO: add configuration
    i->autoadd_friends = true;

    return i;

error:
    if (i != NULL) {
        interface_free(i);
    }
    return NULL;
}

static int interface_remove_and_release(ToxVPNContext *context, uint32_t id)
{
    BS_LIST *interfaces = &context->toxvpn_interfaces;
    VPNInterface *i = interface_find_by_id(context->tox, id);
    bs_list_remove(interfaces, i, id);
    return interface_free(i);
}

/*
 * Send functions
 */
static int send_lossless_packet(VPNInterface *i, int friendnumber, const uint8_t *data, size_t size)
{
    struct VPNPacketHeader *header = (struct VPNPacketHeader*) data;
    header->tox_packet_type = PACKET_ID_TOXVPN_LOSSLESS_PACKET;
    return !tox_friend_send_lossless_packet(i->tox, friendnumber, data, size, 0);
}

static int send_lossy_packet(VPNInterface *i, uint32_t friendnumber, const uint8_t *data, size_t size)
{
    struct VPNPacketHeader *header = (struct VPNPacketHeader*) data;
    header->tox_packet_type = PACKET_ID_TOXVPN_LOSSY_PACKET;

    struct VPNMember *member = vpn_members_table_find_by_friendnumber(&i->members_table, friendnumber);
    if (member == NULL) {
        return -1;
    }

    member->last_packet_sent_timestamp = time(NULL);
    return !tox_friend_send_lossy_packet(i->tox, friendnumber, (const void *) data, size, 0);
}

static int broadcast_lossy_packet(VPNInterface *i, const void *data, size_t size)
{
    int j;
    int status = 0;
    for (j = 0; j < i->members_table.count; j++) {
        const uint32_t friendnumber = i->members_table.members[j].friendnumber;
        status |= send_lossy_packet(i, friendnumber, data, size);
    }

    return !status;
}

static int broadcast_lossless_packet(VPNInterface *i, const void *data, size_t size)
{
    int j;
    int status = 0;

    for (j = 0; j < i->members_table.count; j++) {
        const uint32_t friendnumber = i->members_table.members[j].friendnumber;
        status |= send_lossless_packet(i, friendnumber, data, size);
    }

    return !status;
}

static bool send_members_table(VPNInterface *i, uint32_t friendnumber)
{
    assert(i);

    size_t payload_size;
    uint8_t *serialialized_table = vpn_members_table_serialize(i->tox, &i->members_table,
                                                               &payload_size);

    const size_t raw_packet_size = sizeof(struct VPNMembersTablePacketHeader) + payload_size;

    uint8_t *raw_packet = malloc(raw_packet_size);
    struct VPNMembersTablePacketHeader *packet_header = (struct VPNMembersTablePacketHeader*) raw_packet;

    packet_init(i, &packet_header->header);
    packet_header->header.type = TOXVPN_PACKET_TYPE_MEMBERS_TABLE;
    packet_header->payload_size = htonl(payload_size);

    memcpy(raw_packet + sizeof(struct VPNMembersTablePacketHeader), serialialized_table, payload_size);

    bool status;

    if (friendnumber == TOXVPN_FRIENDID_BROADCAST) {
        status = (broadcast_lossless_packet(i, raw_packet, raw_packet_size) == 0);
    }
    else {
        status = (send_lossless_packet(i, friendnumber, raw_packet, raw_packet_size) == 0);
    }

    free(raw_packet);
    free(serialialized_table);

    return status;
}


/*
 * Packet handlers
 */
static bool process_membership_request(ToxVPNContext *context, uint32_t friendnumber, const uint8_t *packet, size_t packet_length)
{
    struct VPNMembershipRequestPacket *request_packet = (struct VPNMembershipRequestPacket*) packet;
    const uint8_t *toxvpn_shareid = request_packet->header.shareid;

    VPNInterface *i = interface_create(context, ip_ntoa(&request_packet->subnet), request_packet->prefix, toxvpn_shareid, 0);
    if (!interface_add(context, i)) {
        tox_trace(context->tox, "Can't add toxvpn interface on request received");
    }

    if (context->toxvpn_membership_request) {
        context->toxvpn_membership_request(context, i->id, friendnumber, request_packet->flags, context->toxvpn_membership_request_data);
    } else {
        tox_trace(context->tox, "Received membership request callback was not set");
    }

    return true;
}

static bool process_incoming_members_table(VPNInterface* interface, uint32_t friendnumber,
                                           const uint8_t *data, size_t data_length)
{
    assert(data_length > sizeof(struct VPNMembersTablePacketHeader));
    const struct VPNMembersTablePacketHeader *packet_header = (struct VPNMembersTablePacketHeader *) data;
    assert(packet_header->header.type == TOXVPN_PACKET_TYPE_MEMBERS_TABLE);
    const uint8_t *serialized_table_ptr = data + sizeof(struct VPNMembersTablePacketHeader);

    size_t payload_size = ntohl(packet_header->payload_size);

    assert(payload_size == data_length - sizeof(struct VPNMembersTablePacketHeader));
    struct VPNMembersTable received_table;
    vpn_members_table_deserialize(interface->tox, serialized_table_ptr, payload_size, &received_table);

    bool members_table_changed = vpn_members_table_merge(&interface->members_table, &received_table);
    vpn_members_table_free(&received_table);

#if DEBUG
    vpn_members_table_print(&interface->members_table, "process_incomming_members_table: table after merging");
#endif

    //check new ip address, if our address was updated than update VPNInterface.address.ip field
    for (int i = 0; i < interface->members_table.count; i++) {
        struct VPNMember *member_ptr = &interface->members_table.members[i];

        if (member_ptr->friendnumber == TOXVPN_FRIENDID_SELF &&
            !ip_equal(&member_ptr->ip, &interface->address.ip)) {
            tox_trace(interface->tox, "updating local vpn ip address to %s", ip_ntoa(&member_ptr->ip));
            ip_copy(&interface->address.ip, &member_ptr->ip);
        }
        else if (member_ptr->friendnumber == TOXVPN_FRIENDID_INVALID && interface->autoadd_friends) {

            member_ptr->friendnumber = tox_friend_add_norequest(interface->tox, member_ptr->member_pk, NULL);
            char *pk_hex_str = bin_to_hex_str(member_ptr->member_pk, TOX_PUBLIC_KEY_SIZE);

            if (member_ptr->friendnumber == TOXVPN_FRIENDID_INVALID) {
                tox_trace(interface->tox, "added friend %lu with pk \"%s\". IP: %s. Reason: new members table was received.",
                          member_ptr->friendnumber, pk_hex_str, ip_ntoa(&member_ptr->ip));
            }
            else {
                tox_trace(interface->tox, "error autoadding new friend with pk: %s", pk_hex_str);
            }

            free(pk_hex_str);
        }
    }

    /* If members table was changed - broadcast it to all friends */
    if (members_table_changed) {
        tox_trace(interface->tox, "broadcast new members table. Reason: new members table was received");
        send_members_table(interface, TOXVPN_FRIENDID_BROADCAST);
    }

    return true;
}

static bool process_membership_response(VPNInterface *interface, uint32_t friendnumber, const uint8_t *packet, size_t packet_length)
{
    assert(interface);
    ToxVPNContext *context = interface->context;
    struct VPNMembershipResponsePacket *response_packet = (struct VPNMembershipResponsePacket*) packet;

    if (context->toxvpn_membership_request) {
        context->toxvpn_membership_response(interface->context, interface->id, friendnumber, response_packet->flags, context->toxvpn_membership_response_data);
    }

    if (response_packet->flags == TOXVPN_MEMBERSHIP_ACCEPT) {
        toxvpn_friend_add(interface->tox, interface->id, friendnumber);
        /* If members table was changed - broadcast it to all friends */
        tox_trace(interface->tox, "broadcast new members table. Reason: new member was added");
        send_members_table(interface, TOXVPN_FRIENDID_BROADCAST); //broadcast members table
    } else {
        tox_trace((Tox *) m, "invite to toxvpn was discarded");
    }

    return true;
}

static int process_incoming_ip_packet(VPNInterface *i, uint32_t friendnumber, const uint8_t *ip_packet, size_t ip_packet_len)
{
    struct VPNMember *member = vpn_members_table_find_by_friendnumber(&i->members_table, friendnumber);
    if (member == NULL)
    {
#if DEBUG
        tox_trace(i->tox, "received ip packet but member was not invited");
        return -1;
#endif
    }
    IP dst_ip;
    ip_extract_dst(ip_packet, ip_packet_len, &dst_ip);
    if (!ip_equal(&dst_ip, &i->address.ip) && !ip_is_multicast(& dst_ip) && !ip_is_broadcast(&dst_ip, &i->address))
    {
#if DEBUG
        char self_addr_str[96];
        sprintf(self_addr_str, "%s", ip_ntoa(&i->address.ip));
        tox_trace(i->tox, "received packet with incorrect destination address %s. Our address is %s. Packet will be ignored",
                     ip_ntoa(&dst_ip), self_addr_str);
#endif
        return -1;
    }

    member->last_packet_recv_timestamp = time(NULL);
    return sysnet_interface_write(i, ip_packet, ip_packet_len, true);
}

/**
 * @brief tunneled IP packets handeling
*/
static int process_outgoing_ip_packet(VPNInterface *i, void *data, size_t size)
{
    IP dst_ip, src_ip;

    if (ip_extract_dst(data, size, &dst_ip) != 0 || ip_extract_src(data, size, &src_ip) != 0) {
        return -1;
    }

    struct VPNMember *member = vpn_members_table_find_by_ip(&i->members_table, &dst_ip);

    struct {
        struct VPNPacketHeader header;
        uint8_t data[size]; //TODO: do something with it :)
    } outcoming_packet;

    packet_init(i, &outcoming_packet.header);
    outcoming_packet.header.tox_packet_type = PACKET_ID_TOXVPN_LOSSY_PACKET;
    outcoming_packet.header.type = src_ip.family == AF_INET ? TOXVPN_PACKET_TYPE_IPv4_PACKET : TOXVPN_PACKET_TYPE_IPv6_PACKET;
    memcpy(outcoming_packet.data, data, size);

    int status = 0;

    if (member) {
#if DEBUG
        tox_trace(i->tox, "sending IP packet - size: %lu, friendnumber: %u", size, member->friendnumber);
#endif
        status = send_lossy_packet(i, member->friendnumber, (const void *) &outcoming_packet, sizeof(outcoming_packet));
    }
    else if(ip_is_broadcast(&dst_ip, &i->address) || ip_is_multicast(&dst_ip)) {
        status = broadcast_lossy_packet(i, (const uint8_t *) &outcoming_packet, sizeof(outcoming_packet));
    }
    else {
#if DEBUG
        tox_trace(i->tox, "can't send packet to non-member %s", ip_ntoa(&dst_ip));
#endif
        size_t icmp_message_size;
        uint8_t *icmp_message_ptr = ip_compose_icmp_unreacheable_message(&i->address.subnet, &src_ip, &icmp_message_size);
        sysnet_interface_write(i, icmp_message_ptr, icmp_message_size, true);
        free(icmp_message_ptr);

        return -2;
    }

    return !status;
}

/**
 * @brief process_packet all toxvpn packets handler
 */
static void process_packet(Tox *tox, uint32_t friendnumber, const uint8_t *packet, size_t length, void *userdata)
{
    assert(tox);
    if (sizeof(struct VPNPacketHeader) > length) {
        tox_trace(tox, "received invalid size package: %lu", length);
        return;
    }

    struct VPNPacketHeader *packet_header = (struct VPNPacketHeader*) packet;
    VPNInterface *i = (VPNInterface*) interface_find_by_shareid(tox, packet_header->shareid);

#if DEBUG
    char *shareid_str = bin_to_hex_str(packet_header->shareid, TOXVPN_SHAREID_SIZE);
    tox_trace(tox, "received packet %d:%d from friend %d, packet size: %lu, shareid: %s",
                 packet_header->tox_packet_type, packet_header->type, friendnumber, length, shareid_str);
    free(shareid_str);
#endif
    if (packet_header->type == TOXVPN_PACKET_TYPE_MEMBERSHIP_REQUEST) {
       process_membership_request(tox, friendnumber, packet, length);
    } else if (packet_header->type == TOXVPN_PACKET_TYPE_MEMBERSHIP_RESPONSE) {
        assert(i);
        process_membership_response(i, friendnumber, packet, length);
    } else if (packet_header->type == TOXVPN_PACKET_TYPE_IPv4_PACKET || packet_header->type == TOXVPN_PACKET_TYPE_IPv6_PACKET) {
        assert(i);
        const uint8_t *ip_packet = packet + sizeof(struct VPNPacketHeader);
        size_t ip_packet_len = length - sizeof(struct VPNPacketHeader);
        process_incoming_ip_packet(i, friendnumber, ip_packet, ip_packet_len);
    } else if (packet_header->type == TOXVPN_PACKET_TYPE_MEMBERS_TABLE) {
        assert(i);
        process_incoming_members_table(i, friendnumber, packet, length);
    } else if (packet_header->type == TOXVPN_PACKET_TYPE_GET_MEMBERS_TABLE) {
        assert(i);
        send_members_table(i, friendnumber);
    } else {
        tox_trace(tox, "received invalid packet");
    }

    return;
}

uint32_t toxvpn_friend_add(ToxVPNContext *context, uint32_t toxvpn_id, uint32_t friendnumber)
{
    VPNInterface *i = interface_find_by_id(context, toxvpn_id);
    struct VPNMember member = {};

    member.friendnumber = friendnumber;
    member.update_timestamp = time(NULL);

    tox_self_get_public_key(i->tox, member.issuer_pk);
    tox_friend_get_public_key(i->tox, friendnumber, member.member_pk, 0);

    struct VPNAddress member_address;
    member_address.prefix = i->address.prefix;
    ip_copy(&member_address.subnet, &i->address.subnet);

    if (!compute_ip(member.member_pk, &i->address.subnet, member_address.prefix, &member_address.ip))
        return -1;

    ip_copy(&member.ip, &member_address.ip);

    vpn_members_table_add(&i->members_table, &member);
#if DEBUG
    //vpn_members_table_print(&i->members_table, "toxvpn_friend_add");
#endif
    return 0;
}

#if 0
static int toxvpn_friend_rem(Tox *tox, uint32_t toxvpn_id, uint32_t friendnumber)
{
    VPNInterface *i = interface_find_by_id(tox, toxvpn_id);
    vpn_members_table_rem(&i->members_table, friendnumber);
    return 0;
}
#endif

/* ToxVPN Public API */
bool toxvpn_attach(Tox *tox)
{
    assert(tox);
    tox_callback_friend_lossy_packet(tox, process_packet, NULL);
    tox_callback_friend_lossless_packet(tox, process_packet, NULL);
    return true;
}

uint32_t toxvpn_new(ToxVPNContext *context, const char *subnet_str, uint8_t mask_cidr)
{
    VPNInterface *i = interface_create(context, subnet_str, mask_cidr, NULL, 1);

    if (i == NULL) {
#if DEBUG
        tox_trace(tox, "toxvpn_new() can't create interface %s/%d", subnet_str, mask_cidr);
#endif
        return -1;
    }

    if (!interface_add(context, i))
    {
#if DEBUG
        tox_trace(tox, "toxvpn_new() interface has been already added");
#endif
    }

    return i->id;
}

//TODO: rename to toxvpn_net_get_ip()
const char* toxvpn_self_get_ip(ToxVPNContext *context, uint32_t toxvpn_id)
{
    VPNInterface *i = interface_find_by_id(context, toxvpn_id);

    if (i == NULL)
        return NULL;

    return ip_ntoa(&i->address.ip);
}

//TODO: rename to toxvpn_net_get_name()
const char* toxvpn_self_get_name(ToxVPNContext *context, uint32_t toxvpn_id)
{
    VPNInterface *i = interface_find_by_id(context, toxvpn_id);
    return i == NULL ? NULL : i->name;
}

//TODO: rename to toxvpn_net_get_shareid()
bool toxvpn_self_get_shareid(ToxVPNContext *context, uint32_t toxvpn_id, uint8_t *share_id)
{
    VPNInterface *i = interface_find_by_id(context->tox, toxvpn_id);

    if (i == NULL) {
        return false;
    }
    memcpy(share_id, i->shareid, TOXVPN_SHAREID_SIZE);
    return true;
}

const char* toxvpn_friend_get_ip(ToxVPNContext *context, uint32_t toxvpn_id, uint32_t friendnumber)
{
    VPNInterface *vi = interface_find_by_id(context, toxvpn_id);
    if (vi == NULL)
        return NULL;

    struct VPNMember *member = vpn_members_table_find_by_friendnumber(&vi->members_table, friendnumber);
    if (member == NULL)
        return NULL;

    return ip_ntoa(&member->ip);
}

size_t toxvpn_friend_get_list_size(ToxVPNContext *context, uint32_t toxvpn_id)
{
    VPNInterface *i = interface_find_by_id(context, toxvpn_id);
    return i == NULL ? 0 : i->members_table.count;
}

bool toxvpn_friend_get_list(ToxVPNContext *context, uint32_t toxvpn_id, uint32_t *list)
{
    VPNInterface *vi = interface_find_by_id(context->tox, toxvpn_id);
    if (vi == NULL)
        return false;

    for (int j = 0; j < vi->members_table.count; ++j) {
        list[j] = vi->members_table.members[j].friendnumber;
    }
    return true;
}

bool toxvpn_get_list(ToxVPNContext *context, uint32_t *list)
{
    for (int i =0; i < interface_get_count(context->tox); i++) {
        list[i] = interface_get(context->tox, i)->id;
    }

    return true;
}

size_t toxvpn_get_list_size(ToxVPNContext *context)
{
    return interface_get_count(context);
}


bool toxvpn_response_membership(ToxVPNContext *context, uint32_t toxvpn_id, uint32_t friendnumber, uint8_t flags)
{
    VPNInterface *i = interface_find_by_id(context, toxvpn_id);
    assert(i);

    if (flags & TOXVPN_MEMBERSHIP_ACCEPT)
    {
        if (sysnet_interface_is_initialized(i)) {
#if DEBUG
            tox_trace(tox, "toxvpn_response_membership(): toxvpn is already initialized");
            return TOX_ERR_FRIEND_CUSTOM_PACKET_INVALID;
#endif
        }
        else {
            if (interface_init_low_level(i)) {
                return -2;
            }
        }
    }

    struct VPNMembershipResponsePacket response_packet;
    packet_init(i, &response_packet.header);

    response_packet.header.tox_packet_type = PACKET_ID_TOXVPN_LOSSLESS_PACKET;
    response_packet.header.type = TOXVPN_PACKET_TYPE_MEMBERSHIP_RESPONSE;

    response_packet.flags = flags;

    int status = send_lossless_packet(i, friendnumber, (uint8_t*) &response_packet, sizeof(response_packet));
    tox_trace(context, "sending a toxvpn invitation response to %u", friendnumber);

    if (flags & TOXVPN_MEMBERSHIP_DISCARD)
    {
        interface_remove_and_release(context, i->fd);
    }

    return status == 0;
}

bool toxvpn_request_membership(ToxVPNContext *context, uint32_t toxvpn_id, uint32_t friendnumber, uint8_t flags)
{
    VPNInterface *i = interface_find_by_id(context, toxvpn_id);

    if (i == NULL) {
        return -1;
    }
    struct VPNMembershipRequestPacket request_packet;
    packet_init(i, &request_packet.header);

    request_packet.header.tox_packet_type = PACKET_ID_TOXVPN_LOSSLESS_PACKET;
    request_packet.header.type = TOXVPN_PACKET_TYPE_MEMBERSHIP_REQUEST;
    request_packet.flags = 0;

    ip_copy(&request_packet.subnet, &i->address.subnet);
    request_packet.prefix = i->address.prefix;

    TOX_ERR_FRIEND_CUSTOM_PACKET error;
    tox_friend_send_lossless_packet(i->tox, friendnumber, (uint8_t*) &request_packet, sizeof(request_packet), &error);
    return error == 0;
}

int toxvpn_iterate(Tox *tox)
{
    for (int j = 0; j < interface_get_count(tox); j++) {
        VPNInterface *interface = interface_get(tox, j);

        if (!interface->error.no && sysnet_interface_is_initialized(interface)) {

            const size_t bytes_to_read = interface->read_buffer.packet_size ?
                        (interface->read_buffer.packet_size - interface->read_buffer.actual_size) : TOXVPN_MTU;
            const int bytes_read = sysnet_interface_read(interface,
                                                         (void*) interface->read_buffer.buffer + interface->read_buffer.actual_size, bytes_to_read);

            if (bytes_read == -1) {
                if (errno != EAGAIN) { //devtun interface was opened in nonblocking mode
                    interface->error.no = errno;
                    interface->error.description = strerror(errno);
                    tox_trace(tox, "an error has occured during reading from devtun %s: %s",
                                 interface->name, interface->error.description);
                }

                continue;
            }
            else if(bytes_read > 0)
            {
                //TODO: check ip header integrity

                interface->read_buffer.actual_size += bytes_read;
                const size_t ip_packet_size = interface->read_buffer.packet_size ?
                            interface->read_buffer.packet_size :
                            ip_extract_size(interface->read_buffer.buffer, interface->read_buffer.actual_size);
#if DEBUG
                tox_trace(tox, "read %lu, [%lu:%lu] bytes from \"%s\"",
                             bytes_read, interface->read_buffer.actual_size, ip_packet_size, interface->name);
#endif
                // ip_packet_size could be 0, if packet size is smaller than IP header, but bytes_read can't be
                if (ip_packet_size == (interface->read_buffer.actual_size)) {
                    process_outgoing_ip_packet(interface, interface->read_buffer.buffer, interface->read_buffer.actual_size);

                    interface->read_buffer.actual_size = 0;
                    interface->read_buffer.packet_size = 0;
                }
                else
                {
                    interface->read_buffer.packet_size = ip_packet_size;
                }
            }
        }
    }

    return 0;
}

int toxvpn_kill(Tox *tox, uint32_t toxvpn_id)
{
    return interface_remove_and_release(tox, toxvpn_id);
}


#define TOXVPN_SETTINGS_KEY_VPNS "vpns"
#define TOXVPN_SETTINGS_KEY_SUBNET "subnet"
#define TOXVPN_SETTINGS_KEY_SUBNETPREFIX "subnet_prefix"
#define TOXVPN_SETTINGS_KEY_SHAREID "shareid"
#define TOXVPN_SETTINGS_KEY_MEMBERS "members"
#define TOXVPN_SETTINGS_KEY_MEMBERPK "member_pk"
#define TOXVPN_SETTINGS_KEY_ISSUERPK "issuer_pk"
#define TOXVPN_SETTINGS_KEY_UPDATETS "update_timestamp"
#define TOXVPN_SETTINGS_KEY_STATUS "update_timestamp"
#define TOXVPN_SETTINGS_KEY_IP "ip"

char* toxvpn_settings_dump(const ToxVPNContext *context)
{
    json_t *root = json_object();
    char str_buffer[256];

    sprintf(str_buffer, "%u.%u", tox_version_major(), tox_version_minor());
    json_object_set(root, "version", json_string(str_buffer));

    const size_t vpn_count = interface_get_count(context);
    uint32_t *vpn_ids = calloc(vpn_count, sizeof(uint32_t));
    if (!toxvpn_get_list(context, vpn_ids)) {
        free(vpn_ids);
        return false;
    }

    json_t *vpns_array = json_array();
    json_object_set(root, TOXVPN_SETTINGS_KEY_VPNS, vpns_array);

    for (int i = 0; i < vpn_count; i++)
    {
        VPNInterface *interface = interface_get(context, i);

        json_t *vpn_obj = json_object();

        json_object_set(vpn_obj, TOXVPN_SETTINGS_KEY_SUBNET, json_string(ip_ntoa(&interface->address.ip)));
        json_object_set(vpn_obj, TOXVPN_SETTINGS_KEY_SUBNETPREFIX, json_integer(interface->address.prefix));

        char *shareid_str = bin_to_hex_str(interface->shareid, TOXVPN_SHAREID_SIZE);
#if DEBUG
        tox_trace(tox, "dumping information about vpn \"%s\"", shareid_str);
#endif
        json_object_set(vpn_obj, TOXVPN_SETTINGS_KEY_SHAREID, json_string(shareid_str));
        free(shareid_str);

        json_t *members_array = json_array();

        for (int j = 0; j < interface->members_table.count; ++j) {
            json_t *member_obj = json_object();

            struct VPNMember *member = &interface->members_table.members[j];

            char *pk_str = bin_to_hex_str(member->member_pk, TOX_PUBLIC_KEY_SIZE);
            json_object_set(member_obj, TOXVPN_SETTINGS_KEY_MEMBERPK, json_string(pk_str));
            free(pk_str);

            pk_str = bin_to_hex_str(member->issuer_pk, TOX_PUBLIC_KEY_SIZE);
            json_object_set(member_obj, TOXVPN_SETTINGS_KEY_ISSUERPK, json_string(pk_str));
            free(pk_str);

            json_object_set(member_obj, TOXVPN_SETTINGS_KEY_UPDATETS, json_integer(member->update_timestamp));

            json_object_set(member_obj, TOXVPN_SETTINGS_KEY_UPDATETS, json_integer(member->status));

            json_object_set(member_obj, TOXVPN_SETTINGS_KEY_IP, json_string(ip_ntoa(&member->ip)));

            json_array_append(vpn_obj, member_obj);
        }

        json_object_set(vpn_obj, TOXVPN_SETTINGS_KEY_MEMBERS, members_array);
        json_array_append(vpns_array, vpn_obj);
    }

    free(vpn_ids);

    return json_dumps(root, 0);
}

bool toxvpn_settings_load(ToxVPNContext *context, const uint8_t *data, size_t size)
{
    json_error_t error;

    json_t *root = json_loadb(data, size, 0, &error);

    if (!root || !json_is_object(root)) {
        tox_trace(context->tox, "toxvpn_settings_load failed at %d:%d- %s", error.line, error.column, error.text);
        goto error;
    }

    json_t *vpns_array = json_object_get(root, TOXVPN_SETTINGS_KEY_VPNS);

    for (int i = 0; i < json_array_size(vpns_array) && vpns_array; i++) {
        json_t *vpn_object = json_array_get(vpns_array, i);

        uint8_t *shareid_str = hex_string_to_bin(json_string_value(json_object_get(vpn_object, TOXVPN_SETTINGS_KEY_SHAREID)));

        VPNInterface *interface = interface_create(tox, json_string_value(json_object_get(vpn_object, TOXVPN_SETTINGS_KEY_SUBNET)),
                         json_integer_value(json_object_get(vpn_object, TOXVPN_SETTINGS_KEY_SUBNETPREFIX)), shareid_str, true);

        if (!interface)
        {
            tox_trace(tox, "can't create network with shareid %s", shareid_str);
            goto error;
        }

        free(shareid_str);

        json_t *members_array = json_object_get(vpn_object, TOXVPN_SETTINGS_KEY_MEMBERS);
        for (int j = 0; j < json_array_size(members_array); j++) {
            struct VPNMember member;
            vpn_member_init(&member);

            json_t *member_obj = json_array_get(members_array, j);
            assert(member_obj);

            addr_parse_ip(json_string_value(json_object_get(member_obj, TOXVPN_SETTINGS_KEY_IP)), &member.ip);

            uint8_t *issuer_pk = hex_string_to_bin(json_string_value(json_object_get(member_obj, TOXVPN_SETTINGS_KEY_ISSUERPK)));
            memcpy(member.issuer_pk, issuer_pk, TOX_PUBLIC_KEY_SIZE);
            free(issuer_pk);

            uint8_t *member_pk = hex_string_to_bin(json_string_value(json_object_get(member_obj, TOXVPN_SETTINGS_KEY_MEMBERPK)));
            memcpy(member.member_pk, member_pk, TOX_PUBLIC_KEY_SIZE);
            free(member_pk);

            member.update_timestamp = json_integer_value(json_object_get(member_obj, TOXVPN_SETTINGS_KEY_UPDATETS));
            member.status = json_integer_value(json_object_get(member_obj, TOXVPN_SETTINGS_KEY_STATUS));

            vpn_members_table_add(&interface->members_table, &member);
        }

        interface_add(tox, interface);
    }
    return true;

error:
    return false;
}
