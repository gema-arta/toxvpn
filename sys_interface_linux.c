#include "sys_interface.h"

#if defined(TOXVPN_DEVTUN)
#include <asm/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/capability.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netlink/netlink.h>
#include <netlink/addr.h>
#include <netlink/socket.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <stropts.h>
#endif

#include <assert.h>


static int sysnet_get_permissions()
{
    cap_t caps = cap_get_proc();
    if (caps == NULL) {
        perror("cap_get_proc()");
        return errno;
    }

    cap_value_t cap_list = CAP_NET_ADMIN;
    int error = 0;

    if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap_list, CAP_SET) == -1) {
        error = errno;
        perror("cap_set_flags(CAP_NET_ADMIN)");
    }

    if (cap_set_proc(caps) == -1) {
        error = errno;
        perror("cap_set_proc(CAP_NET_ADMIN)");
    }

    if (cap_free(caps) == -1) {
        error = errno;
        perror("cap_free()");
    }

    return error;
}

int sysnet_interface_set_mtu(VPNInterface *i, unsigned int mtu)
{
    int err;

    struct nl_cache *link_cache;
    struct nl_sock *sock;
    struct rtnl_link *link;
    struct rtnl_link *new_link;

    sock = nl_socket_alloc();
    nl_connect(sock, NETLINK_ROUTE);

    rtnl_link_alloc_cache(sock, AF_UNSPEC, &link_cache);
    link = rtnl_link_get_by_name(link_cache, i->name);
    new_link = rtnl_link_alloc();

    if (!link)
    {
        tox_trace(i->context->tox, "can't find link \"%s\"", i->name);
        return -1;
    }

    rtnl_link_set_mtu(new_link, mtu);

    if ((err = rtnl_link_change(sock, link, new_link, 0)) < 0) {
        tox_trace(i->context->tox, "unable to change link \"%s\" flags: %s", rtnl_link_get_name(link), nl_geterror(err));
    }

    rtnl_link_put(link);
    rtnl_link_put(new_link);
    nl_cache_free(link_cache);
    nl_socket_free(sock);

    return 0;
}

int sysnet_interface_set(VPNInterface *i, int up)
{
    int err;

    struct nl_cache *link_cache;
    struct nl_sock *sock;
    struct rtnl_link *link;
    struct rtnl_link *new_link;

    sock = nl_socket_alloc();
    nl_connect(sock, NETLINK_ROUTE);

    rtnl_link_alloc_cache(sock, AF_UNSPEC, &link_cache);
    link = rtnl_link_get_by_name(link_cache, i->name);
    new_link = rtnl_link_alloc();

    if (!link)
    {
        tox_trace(i->context->tox, "Can't find link \"%s\"", i->name);
        return -1;
    }

    unsigned int new_flags = up ? IFF_UP : 0;
    rtnl_link_set_flags(new_link, new_flags);

    if ((err = rtnl_link_change(sock, link, new_link, 0)) < 0) {
        tox_trace(i->context->tox, "Unable to change link \"%s\" flags: %s", rtnl_link_get_name(link), nl_geterror(err));
    }

    rtnl_link_put(link);
    rtnl_link_put(new_link);
    nl_cache_free(link_cache);
    nl_socket_free(sock);

    return 0;
}

int sysnet_interface_up(VPNInterface *i)
{
    return sysnet_interface_set(i, 1);
}

int sysnet_interface_down(VPNInterface *i)
{
    return sysnet_interface_set(i, 0);
}

int sysnet_interface_set_addr(VPNInterface *i)
{
    int err;

    struct nl_cache *link_cache;
    struct nl_sock *sock;
    struct rtnl_addr *addr;
    struct rtnl_link *link;
    struct nl_addr *local_addr;

    sock = nl_socket_alloc();
    nl_connect(sock, NETLINK_ROUTE);

    rtnl_link_alloc_cache(sock, AF_UNSPEC, &link_cache);

    addr = rtnl_addr_alloc();
    link = rtnl_link_get_by_name(link_cache, i->name);
    local_addr = nl_addr_build(i->address.ip.family, &i->address.ip.ip4, sizeof(i->address.ip.ip4));

    rtnl_addr_set_local(addr, local_addr);
    rtnl_addr_set_family(addr, i->address.ip.family);
    rtnl_addr_set_prefixlen(addr, i->address.prefix);
    rtnl_addr_set_link(addr, link);

    if ((err = rtnl_addr_add(sock, addr, 0)) < 0) {
        tox_trace(i->context->tox, "Unable to add address %s on %s: %s", ip_ntoa(&i->address.ip), rtnl_link_get_name(link), nl_geterror(err));
    }
    else {
        tox_trace(i->context->tox, "Added address %s on \"%s\"", ip_ntoa(&i->address.ip), i->name);
    }

    rtnl_link_put(link);
    rtnl_addr_put(addr);
    nl_cache_free(link_cache);
    nl_addr_put(local_addr);
    nl_socket_free(sock);

    return err;
}

int sysnet_interface_create(VPNInterface *i)
{
    assert(i);
#if defined(TOXVPN_DEVTUN)
    if (sysnet_get_permissions() != 0) {
        perror("sysnet_interface_create() can't get admin permissions");
        return -1;
    }

    struct ifreq ifr;
    int fd;

    if ((fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0) {
        free(i);
        perror("sysnet_interface_create() can't open /dev/net/tun");
        return -2;
    }

    memset(&ifr, 0, sizeof(ifr));

     /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
      *        IFF_TAP   - TAP device
      *
      *        IFF_NO_PI - Do not provide packet information
      *
      *   If flag IFF_NO_PI is not set each frame format is:
      *     Flags [2 bytes]
      *     Proto [2 bytes]
      *     Raw protocol(IP, IPv6, etc) frame.
      */
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        free(i);
        perror("sysnet_interface_create() can't create tun interface");
        return -3;
    }

    i->fd = fd;
    strcpy(i->name, ifr.ifr_name);
#endif
    return i->fd < 0;
}

int sysnet_interface_is_initialized(const VPNInterface *i)
{
    return i->fd != INVALID_FD;
}

int sysnet_interface_write(VPNInterface *i, const void *data, size_t size, bool forced_write)
{

#if DEBUG && DUMP_WRITTEN_PACKET
    FILE *dump_file = fopen(i->name, "ab+");
    if (dump_file != NULL) {
        fwrite(data, size, 1, dump_file);
        fclose(dump_file);
    }
#endif

    if (forced_write) {
        size_t written = 0;
        while (written != size)
        {
            int status = write(i->fd, data, size);
            if (status == -1 && errno != EAGAIN) {
                return -1;
            }
            else {
                written += status;
            }
            assert(written <= size);
        }

        return written;
    }
    else  {
        return write(i->fd, data, size);
    }
}

int sysnet_interface_read(VPNInterface *i, void *data, size_t size)
{
    return read(i->fd, data, size);
}

int sysnet_interface_release(VPNInterface *i)
{
    if (i->fd >= 0) {
        close(i->fd);
    }
    i->fd = INVALID_FD;

    return 0;
}
