#include <tox/tox.h>
#include <stdlib.h>
#include <strings.h>
#include <assert.h>
#include <stdarg.h>
#include "util.h"
#include "vpn_member.h"

void vpn_members_table_init(VPNMembersTable *table)
{
    table->capacity = 2;
    table->count = 0;
    table->members = malloc(table->capacity * sizeof(struct VPNMember));
}

void vpn_members_table_add(VPNMembersTable *table, const struct VPNMember *member_ptr)
{
    assert(member_ptr);

    if (table->capacity < table->count + 1) {
        assert(table->capacity > 0);
        struct VPNMember *new_members = calloc(table->capacity * 2, sizeof(struct VPNMember));
        memcpy(new_members, table->members, table->count * sizeof(struct VPNMember));
        free(table->members);
        table->members = new_members;
        table->capacity *= 2;
    }

    assert(table->members != NULL);
    memcpy(&table->members[table->count], member_ptr, sizeof(*member_ptr));

    table->count += 1;
}

void vpn_members_table_add_self(VPNInterface *interface, struct VPNMembersTable *table)
{
    struct VPNMember my_member;
    vpn_member_init(&my_member);
    my_member.friendnumber = TOXVPN_FRIENDID_SELF;
    ip_copy(&my_member.ip, &interface->address.ip);

    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(interface->context->tox, pk);
    memcpy(my_member.issuer_pk, pk, TOX_PUBLIC_KEY_SIZE);
    memcpy(my_member.member_pk, pk, TOX_PUBLIC_KEY_SIZE);
    my_member.update_timestamp = time(NULL);

    vpn_members_table_add(table, &my_member);
}

int vpn_members_table_rem(VPNMembersTable *table, uint32_t friendnumber)
{
    int i;

    for (i = 0; i < table->count; ++i) {
        if (table->members[i].friendnumber == friendnumber) {
            memmove(table->members+i, table->members+i+1, table->count-i-1);
            table->count -= 1;
            return 0;
        }
    }

    return -1;
}

void vpn_member_copy(struct VPNMember* dst, const struct VPNMember* src)
{
    memcpy(dst, src, sizeof(*dst));
}

bool vpn_member_serialize(Tox *tox, struct VPNMember *member_ptr,
                          struct SerializedVPNMember *serialized_member_ptr)
{
    bzero(serialized_member_ptr, sizeof(*serialized_member_ptr));

    serialized_member_ptr->status = member_ptr->status;
    serialized_member_ptr->update_timestamp = htonl(member_ptr->update_timestamp);

    /* IP structure store IP address in BE */
    /* uint8_t */
    serialized_member_ptr->ip.family = member_ptr->ip.family;
    /* in all cases copy all address bytes (16) */
    memcpy(serialized_member_ptr->ip.data, &member_ptr->ip.ip6, sizeof(member_ptr->ip.ip6));
    memcpy(serialized_member_ptr->member_pk, member_ptr->member_pk, TOX_PUBLIC_KEY_SIZE);
    memcpy(serialized_member_ptr->issuer_pk, member_ptr->issuer_pk, TOX_PUBLIC_KEY_SIZE);

#if DEBUG
        char *pk_str = bin_to_hex_str(serialized_member_ptr->member_pk, TOX_PUBLIC_KEY_SIZE);
        tox_trace(tox, "vpn_member_serialize - friend_pk: %s, friendnumber: %lu",
                  pk_str, member_ptr->friendnumber);
        free(pk_str);
#endif
    return true;
}

bool vpn_member_deserialize(Tox *tox, struct SerializedVPNMember *serialized_member_ptr,
                            struct VPNMember *member_ptr)
{
    bzero(member_ptr, sizeof(*member_ptr));
    ip_init(&member_ptr->ip, serialized_member_ptr->ip.family == AF_INET6);
    memcpy(&member_ptr->ip.ip6, serialized_member_ptr->ip.data, sizeof(member_ptr->ip.ip6));

    member_ptr->status = serialized_member_ptr->status;
    member_ptr->update_timestamp = ntohl(serialized_member_ptr->update_timestamp);
    memcpy(member_ptr->issuer_pk, serialized_member_ptr->issuer_pk, TOX_PUBLIC_KEY_SIZE);
    memcpy(member_ptr->member_pk, serialized_member_ptr->member_pk, TOX_PUBLIC_KEY_SIZE);

    member_ptr->friendnumber = tox_friend_by_public_key(tox, serialized_member_ptr->member_pk, NULL);

    if (member_ptr->friendnumber == TOXVPN_FRIENDID_INVALID) {
        uint8_t my_pk[TOX_PUBLIC_KEY_SIZE];
        tox_self_get_public_key(tox, my_pk);

        if (memcmp(my_pk, serialized_member_ptr->member_pk, TOX_PUBLIC_KEY_SIZE) != 0) {
#if DEBUG
            char *pk_str = bin_to_hex_str(serialized_member_ptr->member_pk, TOX_PUBLIC_KEY_SIZE);
            tox_trace(tox, "vpn_member_deserialize: can't find friend with PK: %s", pk_str);
            free(pk_str);
#endif
            return false;
        }
        else {
            member_ptr->friendnumber = TOXVPN_FRIENDID_SELF;
        }
    }

    return true;
}

/**
 * @brief vpn_members_table_serialize
 * @param tox
 * @param table
 * @param size
 * @return array wchich contains serialized VPN member table
 */
uint8_t* vpn_members_table_serialize(Tox *tox, VPNMembersTable *table, size_t *size)
{
    int i;
    assert(size);
    /* vpn members friends count + yourself */
    *size = (sizeof(struct SerializedVPNMember) * table->count + 1);

    struct SerializedVPNMember *serialized_table =
            (struct SerializedVPNMember*) calloc(*size, sizeof(struct SerializedVPNMember));

    for (i = 0; i < table->count; i++) {
        struct VPNMember *member_ptr = table->members + i;
        struct SerializedVPNMember serialized_member;
        vpn_member_serialize(tox, member_ptr, &serialized_member);
        memcpy(serialized_table + i, &serialized_member, sizeof(serialized_member));
    }

    return (uint8_t*) serialized_table;
}

size_t vpn_members_table_deserialize(Tox *tox, const uint8_t *serialized_data, size_t size,
                                     struct VPNMembersTable *table)
{
    vpn_members_table_init(table);

    struct SerializedVPNMember *serialized_table = (struct SerializedVPNMember*) serialized_data;
    assert(serialized_table->ip.family == AF_INET || serialized_table->ip.family == AF_INET6);

    const size_t count = size / sizeof(struct SerializedVPNMember);
    int i;
    for (i = 0; i < count ; i++)
    {
        struct SerializedVPNMember *serialized_member_ptr = serialized_table + i;
        struct VPNMember member;
        vpn_member_deserialize(tox, serialized_member_ptr, &member);
        vpn_members_table_add(table, &member);
    }

    return count;
}

/**
 * @brief vpn_members_table_merge
 * @param dst_table_ptr
 * @param input_table_ptr
 * @return true, if table has been changed, otherwise - false.
 */
bool vpn_members_table_merge(VPNMembersTable *dst_table_ptr, VPNMembersTable *input_table_ptr)
{
    int i, j;
    bool changed = false;

    for (i = 0; i < input_table_ptr->count; ++i) {
        const struct VPNMember *i_member = &input_table_ptr->members[i];

        bool found = false;

        for (j = 0; j < dst_table_ptr->count; ++j) {
            struct VPNMember *j_member = &dst_table_ptr->members[j];

            if (memcmp(i_member->member_pk, j_member->member_pk, TOX_PUBLIC_KEY_SIZE) == 0) {
                if (i_member->update_timestamp > j_member->update_timestamp) {
                    memcpy(j_member, i_member, sizeof(*i_member));
                    tox_trace(NULL, "[%p] updated vpn member %s:%d",
                              dst_table_ptr, ip_ntoa(&i_member->ip), i_member->friendnumber);
                    changed = true;
                }

                found = true;
            }
        }

        if (!found)  {
            vpn_members_table_add(dst_table_ptr, i_member);
            tox_trace(NULL, "[%p] added vpn member %s:%d to table",
                      dst_table_ptr, ip_ntoa(&i_member->ip), i_member->friendnumber);
            changed = true;
        }
    }

    return changed;
}

void vpn_members_table_free(VPNMembersTable *table)
{
    free(table->members);
    table->members = NULL;
    table->capacity = 0;
    table->count = 0;
}

struct VPNMember* vpn_members_table_find_by_friendnumber(const VPNMembersTable* table, int32_t friendnumber)
{
    int j;

    for (j = 0; j < table->count; ++j) {
        if (friendnumber == table->members[j].friendnumber) {
            return &table->members[j];
        }
    }

    return NULL;
}

struct VPNMember* vpn_members_table_find_by_ip(const VPNMembersTable* table, const IP *ip)
{
    int j;

    for (j = 0; j < table->count; ++j) {
        if (ip_equal(ip, &table->members[j].ip)) {
            return &table->members[j];
        }
    }

    return NULL;
}

void vpn_members_table_print(const VPNMembersTable *table, const char* message, ...)
{
    va_list al;
    va_start(al, message);
    fprintf(stderr, "VPNMemebrsTable [%p] ", table);
    vfprintf(stderr, message, al);
    fprintf(stderr, "\n");

    for (int j = 0; j < table->count; j++) {
        const struct VPNMember* member = table->members+j;
        char *member_pk_hex = bin_to_hex_str_alloc(member->member_pk, TOX_PUBLIC_KEY_SIZE);
        tox_trace(NULL, "\tfriend number: %u, IP: %s, update_ts: %d, pk: %s",
                  member->friendnumber, ip_ntoa(&member->ip), member->update_timestamp, member_pk_hex);
        free(member_pk_hex);
    }
}

void vpn_member_init(struct VPNMember *m)
{
    bzero(m, sizeof(struct VPNMember));
    ip_init(&m->ip, false);
    m->friendnumber = TOXVPN_FRIENDID_INVALID;
}

bool vpn_member_equal(struct VPNMember *m1, struct VPNMember *m2)
{
    return ip_equal(&m1->ip, &m2->ip) &&
            memcmp(m1->member_pk, m2->member_pk, TOX_PUBLIC_KEY_SIZE) == 0 &&
            memcmp(m1->issuer_pk, m2->issuer_pk, TOX_PUBLIC_KEY_SIZE) == 0 &&
            m1->update_timestamp == m2->update_timestamp;
}
