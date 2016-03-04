#include "ip_packet.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

size_t ip_extract_size(const uint8_t *data, size_t size)
{
    if (size < sizeof(struct iphdr))
        return 0;

    const struct iphdr *ip_header = (struct iphdr*) data;
    return ntohs(ip_header->tot_len);
}

int ip_extract_dst(const void *data, size_t size, IP *ip)
{
    if (size < sizeof(struct iphdr))
        return -1;

    const struct iphdr *ip_header = (struct iphdr*) data;
    ip_init(ip, ip_header->version == 6);
    memcpy((void*) &ip->ip4.uint32, (void*) &ip_header->daddr, sizeof(ip_header->daddr));
    return 0;
}

int ip_extract_src(const void *data, size_t size, IP *ip)
{
    if (size < sizeof(struct iphdr))
        return -1;

    const struct iphdr *ip_header = (struct iphdr*) data;
    ip_init(ip, ip_header->version == 6);
    memcpy((void*) &ip->ip4.uint32, (void*) &ip_header->saddr, sizeof(ip_header->saddr));
    return 0;
}

bool ip_is_multicast(const IP *ip)
{
    if (ip->family != AF_INET) {
        return 0;
    }
    else {
        static const uint32_t multicast_mask = 0xE0000000;
        return ((multicast_mask & ntohl(ip->ip4.uint32)) == multicast_mask);
    }
}

bool ip_is_broadcast(const IP *ip, const struct VPNAddress *addresses)
{
    if (ip->family != AF_INET) {
        return 0;
    }
    else {

        static const uint32_t broadcast_mask = 0xFFFFFFFF;
        uint32_t inv_subnet_mask = 0;
        int i;
        for (i = 0; i < sizeof(ip->ip4)*8 - (addresses->prefix); i++) {
            inv_subnet_mask |= (1 << i);
        }
        return ((broadcast_mask & ntohl(ip->ip4.uint32)) == broadcast_mask) || (ntohl(ip->ip4.uint32)) == (ntohl(addresses->subnet.ip4.uint32) | inv_subnet_mask);
    }
}

static uint16_t ip_checksum(const void* vdata, size_t length) {
    // Cast the data pointer to one that can be indexed.
    const uint8_t* data= (uint8_t*) vdata;

    // Initialise the accumulator.
    uint32_t acc=0xffff;

    // Handle complete 16-bit blocks.
    for (size_t i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,sizeof(word));
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length & 0x1) {
        uint16_t word = 0;
        memcpy(&word, data+length-1, 1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

static bool ip_compose_icmp_message(uint8_t type, uint8_t code, uint32_t val, struct icmphdr *req)
{
    bzero(req, sizeof(*req));
    req->type = type;
    req->code = code;
    req->checksum = 0;
    req->un.gateway = val;
    req->checksum=ip_checksum(req, sizeof(*req));
    return true;
}

uint8_t *ip_compose_icmp_unreacheable_message(const IP *src, const IP *dst, size_t *size)
{
    assert(src);
    assert(dst);
    assert(size);

    *size = sizeof(struct iphdr) + sizeof(struct icmphdr);

    struct iphdr ip_header;
    bzero(&ip_header, sizeof(ip_header));

    ip_header.version = 4;
    ip_header.ihl = sizeof(ip_header) / 4;  /// < is the number of 32-bit words in the header
    ip_header.protocol = IPPROTO_ICMP;
    ip_header.ttl = 64;
    ip_header.tot_len = htons(*size); ///< this 16-bit field defines the entire packet (fragment) size, including header and data, in bytes
    ip_header.daddr = dst->ip4.uint32;
    ip_header.saddr = src->ip4.uint32;
    ip_header.check = ip_checksum(&ip_header, sizeof(ip_header));

    struct icmphdr icmp_message;
    ip_compose_icmp_message(3, 1, 0, &icmp_message);
    uint8_t *out_packet = calloc(1, *size);

    memcpy(out_packet, &ip_header, sizeof(ip_header));
    memcpy(out_packet + sizeof(ip_header), &icmp_message, sizeof(icmp_message));
    return out_packet;
}
