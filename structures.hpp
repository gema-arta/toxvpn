#ifndef STRUCTURES_H
#define STRUCTURES_H

#define SECRET_SIZE 32
#define DEFAULT_SUBNET "10.0.100.0/24"

#include <vector>
#include <string>
#include <ctime>
#include <tox/tox.h>


using namespace std;

static const char *help_message = \
    "-h\t\tshow help\n" \
    "-s <secret>\t use passed hex secret\n" \
    "-p <proxy>\t use socks|http://hostname:port> proxy server\n" \
    "-n <subnetwork/prefix length>\n" \
    "-c <address>:<secret>\t connect to server using tox address\n" \
    "-f <file>\tload/save settings from/to file\n";



enum OptionFlags {
    SUBNET_SET          =   1,
    SECRET_SET          =   4,
    NAME_SET            =   8,
    ADDRESS_SET         =   16,
    SERVER_ADDRESS_SET  =   32,
    CLIENT_MODE_SET     =   64,
    PROXY_SET           =   128,
    SETTINGS_FILE_SET   =   256,
};


typedef uint8_t byte;

class ByteArray: public vector<byte> {
public:

    ByteArray() {

    }

    ByteArray(const byte *src, size_t size) {
        assign(src, size);
    }

    byte *operator ()() {
        if (empty()) {
            return nullptr;
        } else {
            return &this->at(0);
        }
    }

    const byte *operator ()() const {
        if (empty()) {
            return nullptr;
        } else {
            return &this->at(0);
        }
    }

    void assign(const byte *src, size_t size) {
        resize(size);
        memcpy(&this->at(0), src, size);
    }
};

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

        uint8_t *pk = hex_string_to_bin(token);
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
        parse_subnet(DEFAULT_SUBNET);
    }

    char *subnet;
    uint16_t prefixlen;

    uint8_t secret[SECRET_SIZE];

    const uint8_t *name;
    size_t name_size;

    uint8_t self_address[TOX_ADDRESS_SIZE];
    uint8_t server_address[TOX_ADDRESS_SIZE];

    uint32_t toxvpn_id;
    char *settings_path_pattern;

    struct {
        char *host;
        uint16_t port;
        TOX_PROXY_TYPE type;
    } proxy;

    int options_mask;

    ToxVPNContext *vpn_context = nullptr;

    bool running = true;

    string get_secret_representation() const
    {
        size_t first_zero_byte_pos = (size_t) -1;
        for (size_t i = 0; i < sizeof(secret); i++) {
            if (secret[i] == 0) {
                if (first_zero_byte_pos == (size_t) -1) {
                    first_zero_byte_pos = i;
                }
            }
            else {
                first_zero_byte_pos = (size_t) -1;
            }
        }

        if (first_zero_byte_pos != (size_t) -1) {
          char* secret_str = bin_to_hex_str(secret, first_zero_byte_pos);
          string result(secret_str);
          free(secret_str);
          return result;
        }

        return string();
    }

    void print_usage(int argc, char **argv) const
    {
        fprintf(stderr, "usage: %s options", argv[0]);
        fprintf(stderr, help_message);
    }


    int check_arguments() const
    {
        if (options_mask & CLIENT_MODE_SET)
        {
            const int client_mask = CLIENT_MODE_SET | SERVER_ADDRESS_SET;
            return ((options_mask  & client_mask) == client_mask);
        }
        else
        {
            const int server_mask = 0;
            return ((options_mask & server_mask) == server_mask);
        }
    }

    int parse_subnet(const char *addr)
    {
        char *stringp = strdup(addr);
        char *token =  strtok(stringp, "/");
        if (token != NULL) {
            subnet = strdup(token);
        }
        else {
            free(stringp);
            return 1;
        }

        token = strtok(NULL, "/");
        if (token != NULL) {
            prefixlen = atoi(token);
        }
        else {
            prefixlen = 24;
        }

        free(stringp);
        return 0;
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
                    app_context->options_mask |= SUBNET_SET;
                }
                else {
                    fprintf(stderr, "can't parse subnet address/prefix %s %hu\n", app_context->subnet, app_context->prefixlen);
                    return -2;
                }
                break;

            case 's':
                bzero(app_context->secret, sizeof app_context->secret);
                converted = hex_string_to_bin(optarg);
                memcpy(app_context->secret, converted, min(sizeof(app_context->secret), strlen(optarg)/2));
                free(converted);
                app_context->options_mask |= SECRET_SET;
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
                converted = hex_string_to_bin(token);
                memcpy(app_context->server_address, converted, sizeof(app_context->server_address));
                app_context->options_mask |= (SERVER_ADDRESS_SET | CLIENT_MODE_SET);

                token = strtok(NULL, delim);
                if (token) {
                    options_mask |= SECRET_SET;
                    uint8_t *secret_data = hex_string_to_bin(token);
                    memcpy(secret, secret_data, strlen(token) / 2);
                    free(secret_data);
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
};


#endif // STRUCTURES_H
