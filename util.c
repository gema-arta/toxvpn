#include <tox/tox.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

void tox_trace(const Tox *tox, const char* formator, ...)
{
    FILE *file = stderr;

    if (tox != NULL) {
        uint8_t address[TOX_ADDRESS_SIZE];
        tox_self_get_address(tox, address);
        fprintf(file, "[%0X] ", (uint32_t) *address);
    }

    va_list al;
    va_start(al, formator);
    vfprintf(file, formator, al);
    fprintf(file, "\n");
}


uint8_t *hex_string_to_bin_alloc(const char *hex_string)
{
    // byte is represented by exactly 2 hex digits, so lenth of binary string
    // is half of that of the hex one. only hex string with even length
    // valid. the more proper implementation would be to check if strlen(hex_string)
    // is odd and return error code if it is. we assume strlen is even. if it's not
    // then the last byte just won't be written in 'ret'.
    size_t i, len = strlen(hex_string) / 2;
    uint8_t *ret = (uint8_t*) malloc(len);
    const char *pos = hex_string;

    for (i = 0; i < len; ++i, pos += 2)
        sscanf(pos, "%2hhx", &ret[i]);

    return ret;
}


char *bin_to_hex_str(const uint8_t *bin, size_t size, char *dst, size_t dst_size)
{
    int i;
    for (i = 0; i < size && i*2 < dst_size; i++)
    {
        sprintf(dst + i * 2, "%02X", (uint32_t) *(bin+i));
    }

    return dst;
}

char *bin_to_hex_str_alloc(const uint8_t *bin, size_t size)
{
    const size_t dst_size = size * 2 + 1;
    char *dst = calloc(sizeof(char), dst_size); //2 chars per byte + 1 byte for trailing '\0'
    bin_to_hex_str(bin, size, dst, dst_size);
    return dst;
}


const char *get_transport_name(TOX_CONNECTION connection_status)
{
    switch (connection_status) {
        case TOX_CONNECTION_NONE:
        return "none";
    case TOX_CONNECTION_UDP:
        return "UDP";
    case TOX_CONNECTION_TCP:
        return "TCP";
    default:
        return "unknown";
    }
}
