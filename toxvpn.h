#ifndef VPN_H
#define VPN_H

#include <tox/tox.h>
#include <netinet/ip.h>
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TOXVPN_SHAREID_SIZE 16
#define TOXVPN_MTU 1300 //MAX_CRYPTO_DATA_SIZE - sizeof(struct iphdr)

#define PACKET_ID_TOXVPN_LOSSLESS_PACKET 170
#define PACKET_ID_TOXVPN_LOSSY_PACKET 210

#define TOXVPN_MEMBERSHIP_ACCEPT 1
#define TOXVPN_MEMBERSHIP_DISCARD 2

#define TOXVPN_FRIENDID_INVALID UINT32_MAX
#define TOXVPN_FRIENDID_BROADCAST (UINT32_MAX - 2)
#define TOXVPN_FRIENDID_SELF (UINT32_MAX - 1)

typedef struct ToxVPNContext {
    Tox *tox;
    void (*toxvpn_membership_request)(struct ToxVPNContext *toxvpn, int32_t, int32_t, uint8_t, void*);
    void *toxvpn_membership_request_data;
    void (*toxvpn_membership_response)(struct ToxVPNContext *toxvpn, int32_t, int32_t, uint8_t, void*);
    void *toxvpn_membership_response_data;
    BS_LIST toxvpn_interfaces;
} ToxVPNContext;

ToxVPNContext* toxvpn_create_context(Tox *tox);



/**
 * @brief toxvpn_new
 * @param context
 * @param subnet
 * @param mask
 * @return on error value that less than 0, elsewise new toxvpn_id
 */
uint32_t toxvpn_new(ToxVPNContext *context, const char *subnet, uint8_t mask_cidr);

/**
 * @brief toxvpn_callback_membership_request
 * @param context
 * @param callback
 *  @param pointer to Tox instance
 *  @param friendnumber friend number
 *  @param toxvpn_id ToxVPN id
 *  @param flags flags for feature use
 *  @param userdata userdata that should be passed
 * @param userdata userdata to pass in callback
 */
void toxvpn_callback_membership_request(ToxVPNContext *context, void (*callback)(ToxVPNContext *tox, int32_t toxvpn_id, int32_t friendnumber, uint8_t flags, void *userdata), void *userdata);

/**
 * @brief toxvpn_callback_membership_response
 * @param context
 * @param callback
 *  @param pointer to Tox instance
 *  @param friendnumber friend number
 *  @param toxvpn_id ToxVPN id
 *  @param flags flags for feature use
 *  @param userdata userdata that should be passed
 * @param userdata userdata to pass in callback
 */
void toxvpn_callback_membership_response(ToxVPNContext *context, void (*callback)(ToxVPNContext *tox, int32_t toxvpn_id, int32_t friendnumber, uint8_t flags, void *userdata), void *userdata);

bool toxvpn_request_membership(ToxVPNContext *context, uint32_t toxvpn_id, uint32_t friendnumber, uint8_t flags);
bool toxvpn_response_membership(ToxVPNContext *context, uint32_t toxvpn_id, uint32_t friendnumber, uint8_t flags);

/**
 * @brief toxvpn_kill release vpn, free resources and shutdown link
 * @param context
 * @param toxvpn_id
 * @return 0 on success, elsewise -1
 */
int toxvpn_kill(ToxVPNContext *context, uint32_t toxvpn_id);
int toxvpn_events_loop(ToxVPNContext *context);

const char* toxvpn_self_get_ip(ToxVPNContext *context, uint32_t toxvpn_id);
const char* toxvpn_self_get_name(ToxVPNContext *context, uint32_t toxvpn_id);
bool toxvpn_self_get_shareid(ToxVPNContext *context, uint32_t toxvpn_id, uint8_t *share_id);

uint32_t toxvpn_friend_add(ToxVPNContext *context, uint32_t toxvpn_id, uint32_t friendnumber);
bool toxvpn_friend_get_list(ToxVPNContext *context, uint32_t toxvpn_id, uint32_t *list);
size_t toxvpn_friend_get_count(ToxVPNContext *context, uint32_t toxvpn_id);
const char* toxvpn_friend_get_ip(ToxVPNContext *context, uint32_t toxvpn_id, uint32_t friendnumber);

size_t toxvpn_get_count(const ToxVPNContext *context);
bool toxvpn_get_list(const ToxVPNContext *context, uint32_t *list);

char* toxvpn_settings_dump(const ToxVPNContext *context);
bool toxvpn_settings_load(ToxVPNContext *context, const uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif // VPN_H

