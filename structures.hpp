#ifndef STRUCTURES_H
#define STRUCTURES_H

#define SECRET_SIZE 32
#define DEFAULT_SUBNET "10.0.100.0/24"

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#include <vector>
#include <string>
#include <ctime>
#include <tox/tox.h>
#include <climits>
#include <unistd.h>
#include <cassert>

#include "resources.hpp"
#include "util.hpp"
#include "mmap.hpp"
#include "base58.hpp"
#include "util.h"
#include <sodium/randombytes.h>

using namespace std;

static const char *help_message = \
    "-h\t\tshow help\n" \
    "-s <secret>\t use passed hex secret\n" \
    "-p <proxy>\t use socks|http://hostname:port> proxy server\n" \
    "-n <subnetwork/prefix length>\n" \
    "-c <address>:<secret>\t connect to server using tox address\n" \
    "-f <file>\tload/save settings from/to file\n";



enum OptionFlags {
    SERVER_PK_SET       =   32,
    CLIENT_MODE_SET     =   64,
    PROXY_SET           =   128,
    SETTINGS_FILE_SET   =   256,
};


typedef uint8_t byte;


template <typename T>
class Array: public vector<T> {
public:
    using vector<T>::resize;
    using vector<T>::empty;
    using vector<T>::size;

    enum Encoding { ENCODING_BASE58 };

    Array()
    {

    }

    Array(const size_t count)
    {
        resize(count);
    }

    Array(const T *src, size_t count)
    {
        assign(src, count);
    }

    Array(const string &src, const Encoding encoding = ENCODING_BASE58);

    T* operator ()()
    {
        if (empty()) {
            return nullptr;
        } else {
            return &this->at(0);
        }
    }

    const T* operator ()() const
    {
        if (empty()) {
            return nullptr;
        } else {
            return &this->at(0);
        }
    }

    void assign(const T *src, size_t count)
    {
        resize(count);
        memcpy(&this->at(0), src, count * sizeof(T));
    }

    void fill_random()
    {
        randombytes((unsigned char*) &this->at(0), sizeof(T) * this->size());
    }

    void fill_zero()
    {
        memset((void*) &this->at(0), 0x0, sizeof(T) * this->size());
    }

    string to_str() const
    {
        return empty() ? "" : string((const char*) &this->at(0), this->size() * sizeof(T));
    }

    string to_hex() const
    {
        if (this->empty()) {
            return "";
        }

        char *hex_str = bin_to_hex_str_alloc((const uint8_t*) &this->at(0), this->size() * sizeof(T));
        string hex(hex_str);
        free(hex_str);
        return hex;
    }

    string to_base58() const {
        if (this->empty()) {
            return "";
        }

        const uint8_t *start = (const uint8_t*) &this->at(0);
        const uint8_t *end = start + size() * sizeof(T);
        return EncodeBase58(start, end);
    }
};

template<>
Array<byte>::Array(const string &src, const Encoding encoding)
{
    if (encoding == ENCODING_BASE58) {
        DecodeBase58(src, *this);
    }
    else {
        throw "not supported";
    }
}


template <typename T>
Array<T>::Array(const string &src, const Encoding encoding)
{
    throw "not supported";
}


typedef Array<byte> ByteArray;

struct DHTNode {
    string host;
    uint16_t port = 0;
    ByteArray pk;

    DHTNode(const char *init_str)
    {
        char *arg_dup = strdup(init_str);
        static const char *delim= ":";
        char *token = strtok(arg_dup, delim);

        if (!token) {
            free(arg_dup);
            return;
        }

        host = token;

        token = strtok(NULL, delim);
        if (!token) {
            free(arg_dup);
            return;
        }

        port = atoi(token);

        token = strtok(NULL, delim);
        if (!token) {
            free(arg_dup);
            return;
        }

        if (strlen(token)/2 != TOX_PUBLIC_KEY_SIZE) {
            fprintf(stderr, "invlalid public key size: %lu\n", strlen(token)/2);
        }

        uint8_t *pk = hex_string_to_bin_alloc(token);
        this->pk.assign(pk, TOX_PUBLIC_KEY_SIZE);
        free(pk);

        free(arg_dup);
    }
};


typedef vector<DHTNode> DHTNodesList;


struct ApplicationContext
{
protected:
    DHTNodesList nodes;

public:
    ApplicationContext()
    {
        srand(time(NULL));
        parse_subnet(Util::string_format("10.%d.%d.0/24", rand() % 256, rand() % 256).c_str());

        secret.resize(SECRET_SIZE);
        secret.fill_random();
    }

    char *subnet;
    uint16_t prefixlen;
    ByteArray secret;
    ByteArray self_address = ByteArray(TOX_ADDRESS_SIZE);
    ByteArray server_address = ByteArray(TOX_ADDRESS_SIZE);
    uint32_t toxvpn_id;
    char *settings_path_pattern;
    int options_mask;
    ToxVPNContext *vpn_context = nullptr;
    bool running = true;
    MemoryMappedFile members_table_mmap = Util::string_format("%s.%d", routing_table_path.c_str(), getpid());

    struct {
        char *host;
        uint16_t port;
        TOX_PROXY_TYPE type;
    } proxy;

    void print_usage(int argc, char **argv) const
    {
        fprintf(stderr, "usage: %s options", argv[0]);
        fprintf(stderr, help_message);
    }

    int check_arguments() const
    {
        if (options_mask & CLIENT_MODE_SET)
        {
            const int client_mask = CLIENT_MODE_SET | SERVER_PK_SET;
            return ((options_mask  & client_mask) == client_mask);
        }
        else
        {
            const int server_mask = 0;
            return ((options_mask & server_mask) == server_mask);
        }
    }

    bool parse_subnet(const char *addr)
    {
        char *stringp = strdup(addr);
        char *token =  strtok(stringp, "/");
        if (token != NULL) {
            subnet = strdup(token);
        }
        else {
            free(stringp);
            return false;
        }

        token = strtok(NULL, "/");
        if (token != NULL) {
            prefixlen = atoi(token);
        }
        else {
            prefixlen = 24;
        }

        free(stringp);
        return true;
    }

    int parse_proxy(const char *arg)
    {
        char *arg_dup = strdup(arg);
        static const char *delim= ":/";
        char *token = strtok(arg_dup, delim);

        if (!token) {
            goto getout;
        }
        this->proxy.type = strcmp(token, "socks") == 0 ? TOX_PROXY_TYPE_SOCKS5 : TOX_PROXY_TYPE_HTTP;

        if (!token) {
            goto getout;
        }

        this->proxy.host = strdup(token);

        token = strtok(NULL, delim);
        if (!token) {
            goto getout;
        }
        this->proxy.port = atoi(token);

    getout:
        free(arg_dup);
        return token == NULL ? -1 : 0;
    }

    int parse_arguments(int argc, char **argv)
    {
        ApplicationContext *app_context = this;

        uint8_t *converted;
        int c;
        while ((c = getopt (argc, argv, "hn:p:s:c:b:f:")) != -1) {
            switch (c)
            {
            case 'p':
                if (!parse_proxy(optarg)) {
                    app_context->options_mask |= PROXY_SET;
                }
                else {
                    fprintf(stderr, "invalid proxy server\n");
                    return -2;
                }
                break;
            case 'n':
                if (!parse_subnet(optarg)) {
                    fprintf(stderr, "can't parse subnet address/prefix %s %hu\n", app_context->subnet, app_context->prefixlen);
                    return -2;
                }
                break;

            case 's':
                app_context->secret = ByteArray(optarg, ByteArray::ENCODING_BASE58);
                break;
            case 'f':
                app_context->settings_path_pattern = optarg;
                app_context->options_mask |= SETTINGS_FILE_SET;
                break;
            case 'c':
            {
                if (strlen(optarg)/2 < TOX_ADDRESS_SIZE)
                {
                    fprintf(stderr, "Invalid server node address size: %lu\n", strlen(optarg)/2);
                    return -2;
                }

                static const char* delim = ":";
                char* arg_dup = strdup(optarg);
                char* token = strtok(arg_dup, delim);

                assert(token);
                app_context->server_address = ByteArray(token, ByteArray::ENCODING_BASE58);
                app_context->options_mask |= (SERVER_PK_SET | CLIENT_MODE_SET);

                token = strtok(NULL, delim);
                if (token) {
                    secret = ByteArray(token, ByteArray::ENCODING_BASE58);
                }

                free(arg_dup);
                free(converted);

                break;
            }
            case 'h':
                return 1;
            case '?':
                return 1;
            default:
               return -1;
            }
        }

        if (!check_arguments())
        {
            fprintf(stderr, "Not all arguments supplied correctly: %X\n", app_context->options_mask);
            return 2;
        }
        else
        {
            return 0;
        }
    }

    size_t add_dht_nodes(vector<const char*> list) {
        for (auto node_info: list) {
            nodes.push_back(DHTNode(node_info));
        }
        return nodes.size();
    }

    const DHTNode& get_next_dht_node() {
        return nodes[rand() % nodes.size()];
    }

    static const char* get_host_name() {
        static char hostname[TOX_MAX_NAME_LENGTH];
        memset(hostname, 0x0, sizeof(hostname));

        if (!gethostname(hostname, sizeof(hostname))) {
            return hostname;
        } else {
            return nullptr;
        }

    }
};


#endif // STRUCTURES_H
