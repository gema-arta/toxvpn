#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#define _POSIX_C_SOURCE 200900

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>

#include <iostream>
#include <cstdarg>

#include "toxvpn.h"
#include "util.h"


#define DEFAULT_BOOTSTRAP_NODE 	"144.76.60.215:33445:04119E835DF3E78BACF0F84235B300546AF8B936F035185E2A8E9E0A67C8924F"
#define DEFAULT_SUBNET "10.0.100.0/24"


inline void trace(const char* formator, ...) {
    FILE *file = stderr;
    va_list al;
    va_start(al, formator);
    vfprintf(file, formator, al);
    fprintf(file, "\n");
}

#define min(x, y) (x < y ? x : y)

#define SECRET_SIZE 32

static const char *help_message = \
    "-h\t\tshow help\n" \
    "-s <secret>\t use passed hex secret\n" \
    "-p <proxy>\t use socks|http://hostname:port> proxy server\n" \
    "-n <subnetwork/prefix length>\n" \
    "-b <IP:port:tox_address>\tuse bootstap node\n" \
    "-c <address>:<secret>\t connect to server using tox address\n" \
    "-f <file>\tload/save settings from/to file\n";

enum OptionFlags {
    SUBNET_SET          =   1,
    BOOTSTRAP_NODE_SET  =   2,
    SECRET_SET          =   4,
    NAME_SET            =   8,
    ADDRESS_SET         =   16,
    SERVER_ADDRESS_SET  =   32,
    CLIENT_MODE_SET     =   64,
    PROXY_SET           =   128,
    SETTINGS_FILE_SET   =   256,
};

struct ApplicationContext{

    ApplicationContext()
    {
        bzero(this, sizeof(*this));
        parse_bootstrap_node(DEFAULT_BOOTSTRAP_NODE);
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

    struct {
        char *host;
        uint16_t port;
        uint8_t *pk;
    } dht_bootstrap_node;

    int options_mask;

    ToxVPNContext *vpn_context = nullptr;

    bool running = true;

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

    int parse_bootstrap_node(const char *arg)
    {
        char *arg_dup = strdup(arg);
        static const char *delim= ":";
        char *token = strtok(arg_dup, delim);

        if (!token) {
            goto getout;
        }
        dht_bootstrap_node.host = strdup(token);

        token = strtok(NULL, delim);
        if (!token) {
            goto getout;
        }
        dht_bootstrap_node.port = atoi(token);

        token = strtok(NULL, delim);
        if (!token) {
            goto getout;
        }
        if (strlen(token)/2 != TOX_PUBLIC_KEY_SIZE) {
            fprintf(stderr, "invlalid public key size: %lu\n", strlen(token)/2);
            goto getout;
        }
        dht_bootstrap_node.pk = hex_string_to_bin(token);

    getout:
        free(arg_dup);
        return token == NULL ? -1 : 0;
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
            case 'b':
                if (parse_bootstrap_node(optarg)) {
                    fprintf(stderr, "can't parse bootstrap node address\n");
                    return -2;
                }
                else {
                    app_context->options_mask |= BOOTSTRAP_NODE_SET;
                }

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
                if (strlen(optarg)/2 != TOX_ADDRESS_SIZE)
                {
                    fprintf(stderr, "Invalid server node address size: %lu\n", strlen(optarg)/2);
                    return -2;
                }

                converted = hex_string_to_bin(optarg);
                memcpy(app_context->server_address, converted, sizeof(app_context->server_address));
                free(converted);
                app_context->options_mask |= (SERVER_ADDRESS_SET | CLIENT_MODE_SET);
                break;
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


} app_context;



void singnal_handler(int signal_code)
{
    switch (signal_code) {
    case SIGINT:
    case SIGTERM:
        app_context.running = false;
        break;
    default:
        trace("received unexpected signal %d", signal_code);
        break;
    }
}


static void on_fiend_connection_status_cnaged(Tox *tox, uint32_t friend_id, TOX_CONNECTION connection_status, void *user_data)
{
    assert(user_data);
    struct ApplicationContext *options = (struct ApplicationContext *) user_data;

    if (!(options->options_mask & CLIENT_MODE_SET)) {
        if (connection_status != TOX_CONNECTION_NONE) {
            if (toxvpn_request_membership(options->vpn_context, options->toxvpn_id, friend_id, TOXVPN_MEMBERSHIP_ACCEPT) == TOX_ERR_FRIEND_CUSTOM_PACKET_OK) {
                tox_trace(tox, "toxvpn invite has been sent to friend %u", friend_id);
            }
            else {
                tox_trace(tox, "can't send membership request to friend %d", friend_id);
            }
        }
    }
}

static void on_accept_friend_request(Tox *tox, const uint8_t *pk, const uint8_t *data, size_t length, void *userdata)
{
    char *secret_str = bin_to_hex_str(data, length);
    tox_trace(tox, "received Tox friend request from %lX with attached secret \"%s\"", *((uint64_t*) pk), secret_str);

    if (length == sizeof(app_context.secret) && memcmp(app_context.secret, data, sizeof app_context.secret) == 0) {
        TOX_ERR_FRIEND_ADD error;
        uint32_t friendnumber = tox_friend_add_norequest(tox, pk, &error);
        char *pk_str = bin_to_hex_str(pk, TOX_PUBLIC_KEY_SIZE);
        tox_trace(tox, "Approved friend %u with PK %s", friendnumber, pk_str);
        free(pk_str);
    }
    else
    {
        tox_trace(tox, "Secrets doesn't match");
    }

    free(secret_str);
}

static void on_membership_request(ToxVPNContext *context, int32_t toxvpn_id, int32_t friendnumber, uint8_t flags, void *userdata)
{
//    ApplicationContext *options = static_cast<ApplicationContext *>(userdata);
    tox_trace(context->tox, "received request - toxvpn_id: %X, friendnumber: %d, flags: %X", toxvpn_id, friendnumber, flags);
    toxvpn_response_membership(context, toxvpn_id, friendnumber, TOXVPN_MEMBERSHIP_ACCEPT);
}

static void on_membership_response(ToxVPNContext *context, int32_t toxvpn_id, int32_t friendnumber, uint8_t flags, void *userdata)
{
    tox_trace(context->tox, "Received membership response - toxvpn_id: %d, friendnumber: %d, flags: %X", toxvpn_id, friendnumber, flags);
}


size_t file_get_size(FILE *file)
{
    const size_t pos = ftell(file);
    fseek(file, 0, SEEK_END);
    const size_t size = ftell(file);
    fseek(file, pos, SEEK_SET);
    return size;
}

static const char* settings_get_toxcore_config_path(const char *path)
{
    static char settings_path[256];
    sprintf(settings_path, "%s.toxcore", path);
    return settings_path;
}

static const char* settings_get_toxvpn_config_path(const char *path)
{
    static char settings_path[256];
    sprintf(settings_path, "%s.toxvpn", path);
    return settings_path;
}

Tox* create_tox_context(struct ApplicationContext *options)
{
    size_t settings_size = 0;
    uint8_t *settings_data = NULL;

    struct Tox_Options *tox_options = tox_options_new(NULL);
    tox_options_default(tox_options);

    if (options->options_mask & SETTINGS_FILE_SET) {
        assert(strlen(options->settings_path_pattern) > 0);

        FILE *file = fopen(settings_get_toxcore_config_path(options->settings_path_pattern), "rb+");
        if (file != NULL) {
            settings_size = file_get_size(file);
            settings_data = new uint8_t[settings_size];

            if (fread(settings_data, 1, settings_size, file) != settings_size) {
                free(settings_data);
                settings_data = NULL;
                settings_size = 0;
            }

            fclose(file);
        }
    }

    if (options->options_mask & PROXY_SET) {
        tox_trace(NULL, "proxy settings - host: %s, port: %hu, type: %d", options->proxy.host, (uint16_t) options->proxy.port, options->proxy.type);
        tox_options->proxy_host = options->proxy.host;
        tox_options->proxy_port = options->proxy.port;
        tox_options->proxy_type = options->proxy.type;
    }


    tox_options->savedata_type = (settings_data == 0 && settings_size == 0) ? TOX_SAVEDATA_TYPE_NONE : TOX_SAVEDATA_TYPE_TOX_SAVE;
    tox_options->savedata_data = settings_data;
    tox_options->savedata_length = settings_size;

    TOX_ERR_NEW error;
    Tox *tox = tox_new(tox_options, &error);

    if (tox == nullptr) {
        trace("can't create toxcore context: %d", int(error));
        return nullptr;
    }

    free(settings_data);

    tox_callback_friend_request(tox, on_accept_friend_request, options);
    tox_callback_friend_connection_status(tox, on_fiend_connection_status_cnaged, options);
    tox_self_get_address(tox, options->self_address);

    return tox;
}

ToxVPNContext* create_vpn_context(Tox *tox, ApplicationContext *context)
{
    ToxVPNContext *vpn_context = toxvpn_create_context(tox);
    assert(vpn_context);

    context->vpn_context = vpn_context;

    toxvpn_callback_membership_request(context->vpn_context, on_membership_request, context);
    toxvpn_callback_membership_response(context->vpn_context, on_membership_response, context);

    if (context->options_mask & SETTINGS_FILE_SET) {
        assert(strlen(context->settings_path_pattern) > 0);

        FILE *file = fopen(settings_get_toxvpn_config_path(context->settings_path_pattern), "rb+");
        if (file != NULL) {
            size_t settings_size = file_get_size(file);
            uint8_t *settings_data = new uint8_t[settings_size];
            toxvpn_settings_load(vpn_context, settings_data, settings_size);
            fclose(file);
            free(settings_data);
        }
    }

    return vpn_context;
}

bool settings_save(const ApplicationContext *context, const char *filename)
{
    FILE *file = fopen(settings_get_toxcore_config_path(filename), "wb");
    if (!file) {
        return false;
    }

    size_t size = tox_get_savedata_size(context->vpn_context->tox);
    uint8_t *savedata = new uint8_t[size];
    tox_get_savedata(context->vpn_context->tox, savedata);

    const bool status = fwrite(savedata, size, 1, file) != size;
    free(savedata);
    fclose(file);

    file = fopen(settings_get_toxvpn_config_path(filename), "w");
    if (!file) {
        return false;
    }

    char *toxpvn_json_settings = toxvpn_settings_dump(context->vpn_context);
    fprintf(file, "%s", toxpvn_json_settings);
    free(toxpvn_json_settings);


    return status;
}


int main(int argc, char *argv[])
{
    signal(SIGINT, singnal_handler);
    signal(SIGTERM, singnal_handler);

    if (app_context.parse_arguments(argc, argv) != 0)
    {
        app_context.print_usage(argc, argv);
        return 0;
    }

    Tox *tox = create_tox_context(&app_context);
    assert(tox);
    if (app_context.options_mask & NAME_SET) {
        tox_self_set_name(tox, app_context.name, app_context.name_size, NULL);
    }

    ToxVPNContext *vpn_context = create_vpn_context(tox, &app_context);


    char *address_str = bin_to_hex_str(app_context.self_address, sizeof(app_context.self_address));
    char *secret_str = bin_to_hex_str(app_context.secret, sizeof(app_context.secret));
    trace("connect address %s:%s", address_str, secret_str);

    free(address_str);
    free(secret_str);

    app_context.options_mask |= ADDRESS_SET;

    if (app_context.options_mask & BOOTSTRAP_NODE_SET) {
        assert(app_context.dht_bootstrap_node.pk);
        TOX_ERR_BOOTSTRAP error;
        char *bs_node_address_str = bin_to_hex_str(app_context.dht_bootstrap_node.pk, TOX_PUBLIC_KEY_SIZE);
        tox_trace(tox, "dht bootstrap node is %s:%hu, tox address: %s", app_context.dht_bootstrap_node.host, app_context.dht_bootstrap_node.port, bs_node_address_str);
        if (!tox_bootstrap(tox, app_context.dht_bootstrap_node.host, app_context.dht_bootstrap_node.port, app_context.dht_bootstrap_node.pk, &error)) {
            tox_trace(tox, "can't use bootstap node: %d", error);
        }
        free(bs_node_address_str);
    }

    if (!(app_context.options_mask & CLIENT_MODE_SET)) { //server node logic here
        app_context.toxvpn_id = toxvpn_new(vpn_context, app_context.subnet, app_context.prefixlen);
        if (app_context.toxvpn_id == UINT32_MAX)
        {
            tox_trace(tox, "can't create toxvpn interface");
            return -20;
        }
    } else {
        TOX_ERR_FRIEND_ADD error;
        if (tox_friend_add(tox, app_context.server_address, app_context.secret, sizeof(app_context.secret), &error) == UINT32_MAX) {
            if (error != TOX_ERR_FRIEND_ADD_ALREADY_SENT) {
                tox_trace(tox, "Can't add a server node: %d", error);
                return -30;
            }
        }

        char *server_address_str = bin_to_hex_str(app_context.server_address, sizeof(app_context.server_address));
        tox_trace(tox, "added node %s", server_address_str);
        free(server_address_str);
    }

    bool connected_to_dht = 0;
    int approved = 0;

    while (app_context.running) {
        tox_iterate(tox);
        toxvpn_events_loop(vpn_context);

        if (!connected_to_dht) {
            connected_to_dht = tox_self_get_connection_status(tox) != TOX_CONNECTION_NONE;
            if (connected_to_dht) {
                tox_trace(tox, "connected to dht node");
            }
        }

        if (app_context.options_mask & CLIENT_MODE_SET) { //client node logic here
            if (!approved && tox_friend_get_connection_status(tox, 0, NULL) != TOX_CONNECTION_NONE) {
                approved = 1;
                tox_trace(tox, "Friend %d connected", 0);
            }
        }

        usleep(300);
    }

    if (app_context.options_mask & SETTINGS_FILE_SET) {
        if (settings_save(&app_context, app_context.settings_path_pattern)) {
            tox_trace(tox, "Settings has been saved to \"%s\"", app_context.settings_path_pattern);
        }
        else {
            tox_trace(tox, "Can't save settings to \"%s\": %s", app_context.settings_path_pattern, strerror(errno));
        }
    }

    tox_kill(tox);

    return 0;
}
