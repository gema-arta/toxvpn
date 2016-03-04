#ifndef VPN_MEMBERS_H
#define VPN_MEMBERS_H

#include "toxvpn.h"
#include "toxvpn_internal.h"

void vpn_members_table_init(VPNMembersTable *table);
void vpn_members_table_add(VPNMembersTable *table, const struct VPNMember *member);
void vpn_members_table_add_self(VPNInterface *interface, VPNMembersTable *table);

int vpn_members_table_rem(VPNMembersTable *table, uint32_t friendnumber);
uint8_t* vpn_members_table_serialize(Tox *tox, VPNMembersTable *table, size_t *size);
/**
 * @brief vpn_members_table_deserialize
 * @param tox
 * @param serialized_data
 * @param size
 * @param table
 * @return count of deserialized entries
 */
size_t vpn_members_table_deserialize(Tox *tox, const uint8_t *serialized_data, size_t size, struct VPNMembersTable *table);
bool vpn_members_table_merge(VPNMembersTable *dst_table, VPNMembersTable *derived_table);
void vpn_members_table_free(VPNMembersTable *table);
struct VPNMember* vpn_members_table_find_by_friendnumber(const VPNMembersTable* table, int32_t friendnumber);
struct VPNMember* vpn_members_table_find_by_ip(const VPNMembersTable* table, const IP *ip);
void vpn_members_table_print(const VPNMembersTable *table, const char *message, ...);

void vpn_member_init(struct VPNMember *m);
bool vpn_member_equal(struct VPNMember* m1, struct VPNMember* m2);
bool vpn_member_serialize(Tox *tox, struct VPNMember *member_ptr, struct SerializedVPNMember *serialized_member_ptr);
bool vpn_member_deserialize(Tox *tox, struct SerializedVPNMember *serialized_member_ptr, struct VPNMember *member_ptr);

#endif
