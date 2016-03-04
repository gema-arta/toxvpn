#ifndef TOXVPN_NET_INTERFACE_H
#define TOXVPN_NET_INTERFACE_H
#include "toxvpn_internal.h"

int sysnet_interface_up(VPNInterface *i);
int sysnet_interface_down(VPNInterface *i);
int32_t sysnet_interface_get_index(VPNInterface *i);
int sysnet_interface_set_addr(VPNInterface *i);
int sysnet_interface_create(VPNInterface *i);
int sysnet_interface_release(VPNInterface *i);
int sysnet_interface_write(VPNInterface *i, const void *data, size_t size, bool forced_write);
int sysnet_interface_read(VPNInterface *i, void *data, size_t size);
int sysnet_interface_set_mtu(VPNInterface *i, unsigned int mtu);
int sysnet_interface_is_initialized(const VPNInterface *i);
#endif // TOXVPN_NET_INTERFACE_H
