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

#include <string>
#include <cstdarg>
#include <ctime>
#include <tox/tox.h>

#include "toxvpn.h"
#include "util.h"
#include "resources.hpp"
#include "structures.hpp"

inline void trace(const char* formator, ...) {
    FILE *file = stderr;
    va_list al;
    va_start(al, formator);
    vfprintf(file, formator, al);
    fprintf(file, "\n");
}

#define min(x, y) (x < y ? x : y)

static ApplicationContext app_context;

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


namespace Callbacks {
void connection_status_changed(Tox *tox, TOX_CONNECTION connection_status, void *user_data) {
    if (connection_status != TOX_CONNECTION_NONE) {
        tox_trace(tox, "connected to dht - connection type: %d", connection_status);
    }
    else {
        tox_trace(tox, "disconnected from dht node");
    }
}


void on_fiend_connection_status_cnaged(Tox *tox, uint32_t friend_id, TOX_CONNECTION connection_status, void *user_data)
{
    assert(user_data);
    struct ApplicationContext *options = (struct ApplicationContext *) user_data;

    if (connection_status != TOX_CONNECTION_NONE) {
        if (toxvpn_request_membership(options->vpn_context, options->toxvpn_id, friend_id, TOXVPN_MEMBERSHIP_ACCEPT) == TOX_ERR_FRIEND_CUSTOM_PACKET_OK) {
            tox_trace(tox, "connection with friend %u is established", friend_id);
        }
        else {
            tox_trace(tox, "connection with friend %u was broken", friend_id);
        }
    }
}

void on_accept_friend_request(Tox *tox, const uint8_t *pk, const uint8_t *data, size_t length, void *userdata)
{
    char *secret_str = bin_to_hex_str(data, length);
    tox_trace(tox, "received Tox friend request from %lX with attached secret \"%s\"", *((uint64_t*) pk), secret_str);

    //TODO: replace by secure memcpy (timing atack)
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

void on_membership_request(ToxVPNContext *context, int32_t toxvpn_id, int32_t friendnumber, uint8_t flags, void *userdata)
{
//    ApplicationContext *options = static_cast<ApplicationContext *>(userdata);
    tox_trace(context->tox, "Received request - toxvpn_id: %X, friendnumber: %d, flags: %X", toxvpn_id, friendnumber, flags);
    toxvpn_response_membership(context, toxvpn_id, friendnumber, TOXVPN_MEMBERSHIP_ACCEPT);
}

void on_membership_response(ToxVPNContext *context, int32_t toxvpn_id, int32_t friendnumber, uint8_t flags, void *userdata)
{
    tox_trace(context->tox, "Received membership response - toxvpn_id: %d, friendnumber: %d, flags: %X", toxvpn_id, friendnumber, flags);
}

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

    tox_callback_friend_request(tox, Callbacks::on_accept_friend_request, options);
    tox_callback_friend_connection_status(tox, Callbacks::on_fiend_connection_status_cnaged, options);
    tox_self_get_address(tox, options->self_address);
    tox_callback_self_connection_status(tox, Callbacks::connection_status_changed, NULL);
    return tox;
}

ToxVPNContext* create_vpn_context(Tox *tox, ApplicationContext *context)
{
    ToxVPNContext *vpn_context = toxvpn_create_context(tox);
    assert(vpn_context);

    context->vpn_context = vpn_context;

    toxvpn_callback_membership_request(context->vpn_context, Callbacks::on_membership_request, context);
    toxvpn_callback_membership_response(context->vpn_context, Callbacks::on_membership_response, context);

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

    app_context.add_dht_nodes(dht_nodes);

    Tox *tox = create_tox_context(&app_context);
    assert(tox);
    if (app_context.options_mask & NAME_SET) {
        tox_self_set_name(tox, app_context.name, app_context.name_size, NULL);
    }

    ToxVPNContext *vpn_context = create_vpn_context(tox, &app_context);

    {
        char *address_str = bin_to_hex_str(app_context.self_address, sizeof(app_context.self_address));
        trace("connect address %s:%s", address_str, app_context.get_secret_representation().c_str());
        free(address_str);
    }

    app_context.options_mask |= ADDRESS_SET;

    if (!(app_context.options_mask & CLIENT_MODE_SET)) { //server node logic here
        app_context.toxvpn_id = toxvpn_new(vpn_context, app_context.subnet, app_context.prefixlen);
        if (app_context.toxvpn_id == UINT32_MAX)
        {
            tox_trace(tox, "Can't create toxvpn interface");
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
        tox_trace(tox, "Added node %s", server_address_str);
        free(server_address_str);
    }


    time_t dht_try_ts = 0;

    while (app_context.running) {
        if (tox_self_get_connection_status(tox) == TOX_CONNECTION_NONE && time(NULL) - dht_try_ts > 10 /* try new dht node each x seconds */) {
            TOX_ERR_BOOTSTRAP error;

            const DHTNode& node = app_context.get_next_dht_node();
            tox_trace(tox, "Bootstraping from \"%s:%d\" DHT node", node.host.c_str(), (int) node.port);

            if (!tox_bootstrap(tox, node.host.c_str(), node.port, node.pk(), &error)) {
                tox_trace(tox, "DHT node bootstrap failed: %d", error);
            }

            dht_try_ts = time(NULL);
        }

        tox_iterate(tox);
        toxvpn_events_loop(vpn_context);
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
