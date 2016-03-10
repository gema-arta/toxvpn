#ifndef UTIL_H
#define UTIL_H



#ifdef __cplusplus
extern "C" {
#endif

void tox_trace(const Tox *tox, const char* formator, ...);
uint8_t *hex_string_to_bin(const char *hex_string);
char *bin_to_hex_str(const uint8_t *bin, size_t size);

#ifdef __cplusplus
}
#endif

#endif // UTIL_H
