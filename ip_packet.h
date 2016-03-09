#ifndef IP_PACKET_H
#define IP_PACKET_H

#include "toxvpn_internal.h"

size_t ip_extract_size(const uint8_t *data, size_t size);
int ip_extract_dst(const void *data, size_t size, IP *ip);
int ip_extract_src(const void *data, size_t size, IP *ip);
bool ip_is_multicast(const IP *ip);
bool ip_is_broadcast(const IP *ip, const struct VPNAddress *addresses);
uint8_t *ip_compose_icmp_unreacheable_message(const IP *src, const IP *dst, size_t *size);
#endif // IP_PACKET_H
