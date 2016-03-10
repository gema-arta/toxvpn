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


uint8_t *hex_string_to_bin(const char *hex_string)
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

char *bin_to_hex_str(const uint8_t *bin, size_t size)
{
    char *result_str = calloc(sizeof(char), size * 2 + 1); //2 chars per byte + 1 byte for trailing '\0'
    int i;
    for (i = 0; i < size; i++)
    {
        sprintf(result_str + i * 2, "%02X", (uint32_t) *(bin+i));
    }
    return result_str;
}
