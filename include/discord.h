/*
 * discord.h - A complete Discord Bot API implementation
 *
 * Author  : Philip R. Simonson (aka 5n4k3)
 * Started : 10/02/2025
 * Finished: 10/22/2025
 * 
 ***********************************************************************
 * Usage:
 *   #define DISCORD_IMPLEMENTATION
 *   #include "discord.h"
 * 
 * Dependencies:
 *   - libcurl (for HTTPS requests)
 *   - cJSON (for JSON parsing)
 *   - libwebsockets (for WebSocket connection)
 * 
 * Compile with:
 *   Windows: gcc -o bot bot.c -lcurl -lcjson -lwebsockets -lws2_32
 *   Linux:   gcc -o bot bot.c -lcurl -lcjson -lwebsockets -lpthread
 *   macOS:   gcc -o bot bot.c -lcurl -lcjson -lwebsockets -lpthread
 * 
 * License: MIT License
 * Copyright 2025 Philip R. Simonson
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef DISCORD_H
#define DISCORD_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #ifdef _MSC_VER
    #pragma comment(lib, "ws2_32.lib")
    #endif
    typedef HANDLE discord_thread_t;
    typedef CRITICAL_SECTION discord_mutex_t;
#else
    #include <unistd.h>
    #include <pthread.h>
    typedef pthread_t discord_thread_t;
    typedef pthread_mutex_t discord_mutex_t;
#endif

#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <libwebsockets.h>

/* ============================================================================
 * Constants and Macros
 * ============================================================================ */

#define DISCORD_API_VERSION "10"
#define DISCORD_API_BASE "https://discord.com/api/v" DISCORD_API_VERSION
#define DISCORD_GATEWAY_VERSION "10"
#define DISCORD_GATEWAY_ENCODING "json"
#define DISCORD_MAX_MESSAGE_SIZE 2000
#define DISCORD_MAX_EMBED_SIZE 6000
#define DISCORD_RATE_LIMIT_BUFFER 100

/* Gateway Opcodes */
#define DISCORD_OP_DISPATCH              0
#define DISCORD_OP_HEARTBEAT             1
#define DISCORD_OP_IDENTIFY              2
#define DISCORD_OP_PRESENCE_UPDATE       3
#define DISCORD_OP_VOICE_STATE_UPDATE    4
#define DISCORD_OP_RESUME                6
#define DISCORD_OP_RECONNECT             7
#define DISCORD_OP_REQUEST_GUILD_MEMBERS 8
#define DISCORD_OP_INVALID_SESSION       9
#define DISCORD_OP_HELLO                 10
#define DISCORD_OP_HEARTBEAT_ACK         11

/* Common permission bit constants (64-bit). See Discord docs for full list. */
#define DISCORD_PERM_VIEW_CHANNEL        (1ULL << 10)    /* 1024 */
#define DISCORD_PERM_SEND_MESSAGES       (1ULL << 11)    /* 2048 */
#define DISCORD_PERM_SEND_MESSAGES_IN_THREADS (1ULL << 38)
#define DISCORD_PERM_CREATE_PUBLIC_THREADS   (1ULL << 39)
#define DISCORD_PERM_CREATE_PRIVATE_THREADS  (1ULL << 40)

/* Gateway Intents */
#define DISCORD_INTENT_GUILDS                        (1 << 0)
#define DISCORD_INTENT_GUILD_MEMBERS                 (1 << 1)
#define DISCORD_INTENT_GUILD_BANS                    (1 << 2)
#define DISCORD_INTENT_GUILD_EMOJIS                  (1 << 3)
#define DISCORD_INTENT_GUILD_INTEGRATIONS            (1 << 4)
#define DISCORD_INTENT_GUILD_WEBHOOKS                (1 << 5)
#define DISCORD_INTENT_GUILD_INVITES                 (1 << 6)
#define DISCORD_INTENT_GUILD_VOICE_STATES            (1 << 7)
#define DISCORD_INTENT_GUILD_PRESENCES               (1 << 8)
#define DISCORD_INTENT_GUILD_MESSAGES                (1 << 9)
#define DISCORD_INTENT_GUILD_MESSAGE_REACTIONS       (1 << 10)
#define DISCORD_INTENT_GUILD_MESSAGE_TYPING          (1 << 11)
#define DISCORD_INTENT_DIRECT_MESSAGES               (1 << 12)
#define DISCORD_INTENT_DIRECT_MESSAGE_REACTIONS      (1 << 13)
#define DISCORD_INTENT_DIRECT_MESSAGE_TYPING         (1 << 14)
#define DISCORD_INTENT_MESSAGE_CONTENT               (1 << 15)
#define DISCORD_INTENT_GUILD_SCHEDULED_EVENTS        (1 << 16)
#define DISCORD_INTENT_AUTO_MODERATION_CONFIGURATION (1 << 20)
#define DISCORD_INTENT_AUTO_MODERATION_EXECUTION     (1 << 21)

#define DISCORD_INTENT_ALL_UNPRIVILEGED (DISCORD_INTENT_GUILDS | \
                                         DISCORD_INTENT_GUILD_BANS | \
                                         DISCORD_INTENT_GUILD_EMOJIS | \
                                         DISCORD_INTENT_GUILD_INTEGRATIONS | \
                                         DISCORD_INTENT_GUILD_WEBHOOKS | \
                                         DISCORD_INTENT_GUILD_INVITES | \
                                         DISCORD_INTENT_GUILD_VOICE_STATES | \
                                         DISCORD_INTENT_GUILD_MESSAGES | \
                                         DISCORD_INTENT_GUILD_MESSAGE_REACTIONS | \
                                         DISCORD_INTENT_GUILD_MESSAGE_TYPING | \
                                         DISCORD_INTENT_DIRECT_MESSAGES | \
                                         DISCORD_INTENT_DIRECT_MESSAGE_REACTIONS | \
                                         DISCORD_INTENT_DIRECT_MESSAGE_TYPING | \
                                         DISCORD_INTENT_GUILD_SCHEDULED_EVENTS | \
                                         DISCORD_INTENT_AUTO_MODERATION_CONFIGURATION | \
                                         DISCORD_INTENT_AUTO_MODERATION_EXECUTION)

/* ============================================================================
 * Type Definitions
 * ============================================================================ */

typedef struct discord_client discord_client_t;
typedef struct discord_message discord_message_t;
typedef struct discord_user discord_user_t;
typedef struct discord_channel discord_channel_t;
typedef struct discord_guild_ban discord_guild_ban_t;
typedef struct discord_guild discord_guild_t;
typedef struct discord_member discord_member_t;
typedef struct discord_embed discord_embed_t;
typedef struct discord_embed_field discord_embed_field_t;
typedef struct discord_embed_footer discord_embed_footer_t;
typedef struct discord_embed_author discord_embed_author_t;

/* User structure */
struct discord_user {
    char *id;
    char *username;
    char *discriminator;
    char *avatar;
    bool bot;
    bool system;
};

/* Channel structure */
struct discord_channel {
    char *id;
    int type;
    char *guild_id;
    char *name;
    char *topic;
    int position;
};

/* Guild ban structure */
struct discord_guild_ban {
    discord_user_t *user;
    char *reason;
};

/* Guild/Server structure */
struct discord_guild {
    char *id;
    char *name;
    char *icon;
    char *owner_id;
    int member_count;
};

/* Guild Member structure */
struct discord_member {
    discord_user_t *user;
    char *nick;
    char **roles;
    int role_count;
    char *joined_at;
};

/* Embed field */
struct discord_embed_field {
    char *name;
    char *value;
    bool inline_field;
};

/* Embed footer */
struct discord_embed_footer {
    char *text;
    char *icon_url;
};

/* Embed author */
struct discord_embed_author {
    char *name;
    char *url;
    char *icon_url;
};

/* Embed structure */
struct discord_embed {
    char *title;
    char *description;
    char *url;
    int color;
    char *timestamp;
    discord_embed_footer_t *footer;
    discord_embed_author_t *author;
    discord_embed_field_t *fields;
    int field_count;
    char *thumbnail_url;
    char *image_url;
};

/* Message structure */
struct discord_message {
    char *id;
    char *channel_id;
    char *guild_id;
    discord_user_t *author;
    discord_member_t *member;
    char *content;
    char *timestamp;
    bool tts;
    bool mention_everyone;
    discord_user_t **mentions;
    int mention_count;
    discord_embed_t **embeds;
    int embed_count;
};

/* Event callback types */
typedef void (*discord_on_ready_cb)(discord_client_t *client, discord_user_t *user);
typedef void (*discord_on_message_cb)(discord_client_t *client, discord_message_t *message);
typedef void (*discord_on_message_delete_cb)(discord_client_t *client, const char *message_id, const char *channel_id);
typedef void (*discord_on_guild_create_cb)(discord_client_t *client, discord_guild_t *guild);

/* HTTP response structure */
typedef struct {
    char *data;
    size_t size;
} discord_http_response_t;

/* Gateway connection state */
typedef enum {
    DISCORD_STATE_DISCONNECTED,
    DISCORD_STATE_CONNECTING,
    DISCORD_STATE_CONNECTED,
    DISCORD_STATE_RECONNECTING,
    DISCORD_STATE_CLOSING
} discord_state_t;

/* WebSocket buffer */
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} discord_ws_buffer_t;

/* Client structure */
struct discord_client {
    char *token;
    char *gateway_url;
    char *session_id;
    int sequence;
    int intents;
    
    /* WebSocket connection */
    struct lws_context *ws_context;
    struct lws *ws_connection;
    discord_ws_buffer_t rx_buffer;
    discord_ws_buffer_t tx_buffer;
    
    /* State */
    discord_state_t state;
    bool running;
    int heartbeat_interval;
    time_t last_heartbeat;
    bool heartbeat_acked;
    bool identified;
    
    /* Threading */
    discord_thread_t gateway_thread;
    discord_thread_t heartbeat_thread;
    discord_mutex_t mutex;
    
    /* Bot user info */
    discord_user_t *user;
    
    /* Event callbacks */
    discord_on_ready_cb on_ready;
    discord_on_message_cb on_message;
    discord_on_message_delete_cb on_message_delete;
    discord_on_guild_create_cb on_guild_create;
    
    /* User data */
    void *userdata;
};

/* ============================================================================
 * Function Declarations
 * ============================================================================ */

/* Client management */
discord_client_t *discord_client_create(const char *token, int intents);
void discord_client_destroy(discord_client_t *client);
int discord_client_run(discord_client_t *client);
void discord_client_stop(discord_client_t *client);

/* Event handlers */
void discord_set_on_ready(discord_client_t *client, discord_on_ready_cb callback);
void discord_set_on_message(discord_client_t *client, discord_on_message_cb callback);
void discord_set_on_message_delete(discord_client_t *client, discord_on_message_delete_cb callback);
void discord_set_on_guild_create(discord_client_t *client, discord_on_guild_create_cb callback);

/* DM operations */
discord_channel_t *discord_create_dm(discord_client_t *client, const char *recipient_id);

/* Message operations */
discord_message_t *discord_create_message(discord_client_t *client, const char *channel_id, const char *content);
discord_message_t *discord_create_message_embed(discord_client_t *client, const char *channel_id, discord_embed_t *embed);
int discord_delete_message(discord_client_t *client, const char *channel_id, const char *message_id);
int discord_edit_message(discord_client_t *client, const char *channel_id, const char *message_id, const char *content);

/* Channel operations */
discord_channel_t *discord_get_channel(discord_client_t *client, const char *channel_id);
int discord_send_typing(discord_client_t *client, const char *channel_id);

/* Guild operations */
discord_guild_t *discord_get_guild(discord_client_t *client, const char *guild_id);

/* Embed builder */
discord_embed_t *discord_embed_create(void);
void discord_embed_destroy(discord_embed_t *embed);
void discord_embed_set_title(discord_embed_t *embed, const char *title);
void discord_embed_set_description(discord_embed_t *embed, const char *description);
void discord_embed_set_url(discord_embed_t *embed, const char *url);
void discord_embed_set_color(discord_embed_t *embed, int color);
void discord_embed_set_timestamp(discord_embed_t *embed, const char *timestamp);
void discord_embed_set_footer(discord_embed_t *embed, const char *text, const char *icon_url);
void discord_embed_set_author(discord_embed_t *embed, const char *name, const char *url, const char *icon_url);
void discord_embed_add_field(discord_embed_t *embed, const char *name, const char *value, bool inline_field);
void discord_embed_set_thumbnail(discord_embed_t *embed, const char *url);
void discord_embed_set_image(discord_embed_t *embed, const char *url);

/* Moderation operations */
int discord_kick_member(discord_client_t *client, const char *guild_id, const char *user_id, const char *reason);
int discord_ban_member(discord_client_t *client, const char *guild_id, const char *user_id, int delete_message_seconds, const char *reason);
int discord_unban_member(discord_client_t *client, const char *guild_id, const char *user_id, const char *reason);

/* Bans list */
discord_guild_ban_t **discord_get_guild_bans(discord_client_t *client, const char *guild_id, int *out_count);
void discord_guild_ban_destroy(discord_guild_ban_t *ban);
void discord_guild_ban_list_destroy(discord_guild_ban_t **bans, int count);

/* Timeout (a.k.a. communication_disabled_until) */
int discord_timeout_member(discord_client_t *client, const char *guild_id, const char *user_id, int duration_seconds, const char *reason);
int discord_remove_timeout(discord_client_t *client, const char *guild_id, const char *user_id, const char *reason);

/* Roles */
int discord_add_member_role(discord_client_t *client, const char *guild_id, const char *user_id, const char *role_id, const char *reason);
int discord_remove_member_role(discord_client_t *client, const char *guild_id, const char *user_id, const char *role_id, const char *reason);

/* Server voice state */
int discord_set_voice_mute(discord_client_t *client, const char *guild_id, const char *user_id, bool mute, const char *reason);
int discord_set_voice_deaf(discord_client_t *client, const char *guild_id, const char *user_id, bool deaf, const char *reason);

/* ===================== Roles ===================== */
int discord_create_role(discord_client_t *client, const char *guild_id,
                        const char *name, const char *permissions, int color,
                        bool hoist, bool mentionable, const char *reason,
                        char **out_role_id);
int discord_modify_role(discord_client_t *client, const char *guild_id, const char *role_id,
                        const char *name, const char *permissions, int color,
                        bool hoist_set, bool hoist, bool mentionable_set, bool mentionable,
                        const char *reason);
int discord_delete_role(discord_client_t *client, const char *guild_id, const char *role_id, const char *reason);

/* ===================== Channel Permission Overwrites ===================== */
int discord_channel_set_permission_overwrite(discord_client_t *client, const char *channel_id,
                                             const char *overwrite_id, int type, uint64_t allow, uint64_t deny,
                                             const char *reason);
int discord_channel_delete_permission_overwrite(discord_client_t *client, const char *channel_id,
                                                const char *overwrite_id, const char *reason);

/* Convenience: lock/unlock text channels for @everyone */
int discord_lock_text_channel(discord_client_t *client, const char *guild_id, const char *channel_id, const char *reason);
int discord_unlock_text_channel(discord_client_t *client, const char *guild_id, const char *channel_id, const char *reason);

/* ===================== Prune & Soft-ban ===================== */
int discord_get_prune_count(discord_client_t *client, const char *guild_id, int days,
                            const char **include_role_ids, int include_roles_count, int *out_count);
int discord_begin_prune(discord_client_t *client, const char *guild_id, int days,
                        const char **include_role_ids, int include_roles_count,
                        bool compute_prune_count, const char *reason, int *out_count);
int discord_softban_member(discord_client_t *client, const char *guild_id, const char *user_id,
                           int delete_message_seconds, const char *reason);

/* ===================== Thread moderation ===================== */
int discord_thread_set_locked(discord_client_t *client, const char *thread_id, bool locked, const char *reason);
int discord_thread_set_archived(discord_client_t *client, const char *thread_id, bool archived, const char *reason);
int discord_thread_set_auto_archive_duration(discord_client_t *client, const char *thread_id, int minutes, const char *reason);
int discord_thread_join(discord_client_t *client, const char *thread_id);
int discord_thread_leave(discord_client_t *client, const char *thread_id);
int discord_thread_add_member(discord_client_t *client, const char *thread_id, const char *user_id);
int discord_thread_remove_member(discord_client_t *client, const char *thread_id, const char *user_id);

/* Memory cleanup */
void discord_message_destroy(discord_message_t *message);
void discord_user_destroy(discord_user_t *user);
void discord_channel_destroy(discord_channel_t *channel);
void discord_guild_destroy(discord_guild_t *guild);
void discord_member_destroy(discord_member_t *member);

/* Utility functions */
char *discord_timestamp_offset_seconds(int seconds);
char *discord_timestamp_now(void);

#endif /* DISCORD_H */

/* ============================================================================
 * Implementation
 * ============================================================================ */

#ifdef DISCORD_IMPLEMENTATION

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/* String duplication helper */
static char *discord_strdup(const char *str) {
    if (!str) return NULL;
    size_t len = strlen(str);
    char *dup = (char *)malloc(len + 1);
    if (dup) {
        memcpy(dup, str, len + 1);
    }
    return dup;
}

/* URL encoding helper (uses a short-lived CURL handle) */
static char *discord_url_encode(const char *text) {
    if (!text) return NULL;
    CURL *c = curl_easy_init();
    if (!c) return NULL;
    char *enc = curl_easy_escape(c, text, 0);
    char *out = enc ? discord_strdup(enc) : NULL;
    if (enc) curl_free(enc);
    curl_easy_cleanup(c);
    return out;
}

/* HTTP response callback for libcurl */
static size_t discord_http_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    discord_http_response_t *response = (discord_http_response_t *)userp;
    
    char *ptr = (char *)realloc(response->data, response->size + realsize + 1);
    if (!ptr) {
        fprintf(stderr, "discord.h: Out of memory\n");
        return 0;
    }
    
    response->data = ptr;
    memcpy(&(response->data[response->size]), contents, realsize);
    response->size += realsize;
    response->data[response->size] = 0;
    
    return realsize;
}

/* Make HTTP request with optional audit log reason header */
static discord_http_response_t *discord_http_request_ex(discord_client_t *client,
                                                        const char *method,
                                                        const char *endpoint,
                                                        const char *body,
                                                        const char *audit_reason) {
    CURL *curl;
    CURLcode res;
    discord_http_response_t *response = (discord_http_response_t *)calloc(1, sizeof(discord_http_response_t));

    if (!response) return NULL;

    curl = curl_easy_init();
    if (!curl) {
        free(response);
        return NULL;
    }

    char url[512];
    snprintf(url, sizeof(url), "%s%s", DISCORD_API_BASE, endpoint);

    struct curl_slist *headers = NULL;
    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bot %s", client->token);
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "User-Agent: DiscordBot (discord.h, 1.0)");

    /* X-Audit-Log-Reason must be URL-encoded */
    if (audit_reason && audit_reason[0] != '\0') {
        char *encoded = curl_easy_escape(curl, audit_reason, 0);
        if (encoded) {
            char reason_header[1024];
            snprintf(reason_header, sizeof(reason_header), "X-Audit-Log-Reason: %s", encoded);
            headers = curl_slist_append(headers, reason_header);
            curl_free(encoded);
        }
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discord_http_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "DiscordBot (discord.h, 1.0)");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

#ifdef _WIN32
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
    const char *ca_paths[] = {
        "curl-ca-bundle.crt",
        "cacert.pem",
        NULL
    };
    for (int i = 0; ca_paths[i] != NULL; i++) {
        FILE *f = fopen(ca_paths[i], "r");
        if (f) {
            fclose(f);
            curl_easy_setopt(curl, CURLOPT_CAINFO, ca_paths[i]);
            break;
        }
    }
#endif

    if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (body) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    } else if (strcmp(method, "PATCH") == 0) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
        if (body) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    } else if (strcmp(method, "DELETE") == 0) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
        if (body) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    } else if (strcmp(method, "PUT") == 0) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        if (body) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    } else if (strcmp(method, "GET") == 0) {
        /* Default GET */
    }

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "discord.h: HTTP request (ex) failed: %s\n", curl_easy_strerror(res));
        free(response->data);
        free(response);
        response = NULL;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return response;
}

/* Make HTTP request */
static discord_http_response_t *discord_http_request(discord_client_t *client, 
                                                      const char *method, 
                                                      const char *endpoint, 
                                                      const char *body) {
    return discord_http_request_ex(client, method, endpoint, body, NULL);
}

/* Free HTTP response */
static void discord_http_response_free(discord_http_response_t *response) {
    if (response) {
        free(response->data);
        free(response);
    }
}

/* Parse user from JSON */
static discord_user_t *discord_parse_user(cJSON *json) {
    if (!json) return NULL;
    
    discord_user_t *user = (discord_user_t *)calloc(1, sizeof(discord_user_t));
    if (!user) return NULL;
    
    cJSON *item;
    
    item = cJSON_GetObjectItem(json, "id");
    if (item && cJSON_IsString(item)) {
        user->id = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "username");
    if (item && cJSON_IsString(item)) {
        user->username = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "discriminator");
    if (item && cJSON_IsString(item)) {
        user->discriminator = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "avatar");
    if (item && cJSON_IsString(item)) {
        user->avatar = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "bot");
    if (item && cJSON_IsBool(item)) {
        user->bot = cJSON_IsTrue(item);
    }
    
    item = cJSON_GetObjectItem(json, "system");
    if (item && cJSON_IsBool(item)) {
        user->system = cJSON_IsTrue(item);
    }
    
    return user;
}

/* Parse member from JSON */
static discord_member_t *discord_parse_member(cJSON *json) {
    if (!json) return NULL;
    
    discord_member_t *member = (discord_member_t *)calloc(1, sizeof(discord_member_t));
    if (!member) return NULL;
    
    cJSON *item;
    
    item = cJSON_GetObjectItem(json, "user");
    if (item) {
        member->user = discord_parse_user(item);
    }
    
    item = cJSON_GetObjectItem(json, "nick");
    if (item && cJSON_IsString(item)) {
        member->nick = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "roles");
    if (item && cJSON_IsArray(item)) {
        member->role_count = cJSON_GetArraySize(item);
        if (member->role_count > 0) {
            member->roles = (char **)calloc(member->role_count, sizeof(char *));
            for (int i = 0; i < member->role_count; i++) {
                cJSON *role = cJSON_GetArrayItem(item, i);
                if (role && cJSON_IsString(role)) {
                    member->roles[i] = discord_strdup(role->valuestring);
                }
            }
        }
    }
    
    item = cJSON_GetObjectItem(json, "joined_at");
    if (item && cJSON_IsString(item)) {
        member->joined_at = discord_strdup(item->valuestring);
    }
    
    return member;
}

/* Parse embed from JSON */
static discord_embed_t *discord_parse_embed(cJSON *json) {
    if (!json) return NULL;
    
    discord_embed_t *embed = (discord_embed_t *)calloc(1, sizeof(discord_embed_t));
    if (!embed) return NULL;
    
    cJSON *item;
    
    item = cJSON_GetObjectItem(json, "title");
    if (item && cJSON_IsString(item)) {
        embed->title = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "description");
    if (item && cJSON_IsString(item)) {
        embed->description = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "url");
    if (item && cJSON_IsString(item)) {
        embed->url = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "color");
    if (item && cJSON_IsNumber(item)) {
        embed->color = item->valueint;
    }
    
    item = cJSON_GetObjectItem(json, "timestamp");
    if (item && cJSON_IsString(item)) {
        embed->timestamp = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "footer");
    if (item) {
        embed->footer = (discord_embed_footer_t *)calloc(1, sizeof(discord_embed_footer_t));
        if (embed->footer) {
            cJSON *text = cJSON_GetObjectItem(item, "text");
            if (text && cJSON_IsString(text)) {
                embed->footer->text = discord_strdup(text->valuestring);
            }
            cJSON *icon_url = cJSON_GetObjectItem(item, "icon_url");
            if (icon_url && cJSON_IsString(icon_url)) {
                embed->footer->icon_url = discord_strdup(icon_url->valuestring);
            }
        }
    }
    
    item = cJSON_GetObjectItem(json, "author");
    if (item) {
        embed->author = (discord_embed_author_t *)calloc(1, sizeof(discord_embed_author_t));
        if (embed->author) {
            cJSON *name = cJSON_GetObjectItem(item, "name");
            if (name && cJSON_IsString(name)) {
                embed->author->name = discord_strdup(name->valuestring);
            }
            cJSON *url = cJSON_GetObjectItem(item, "url");
            if (url && cJSON_IsString(url)) {
                embed->author->url = discord_strdup(url->valuestring);
            }
            cJSON *icon_url = cJSON_GetObjectItem(item, "icon_url");
            if (icon_url && cJSON_IsString(icon_url)) {
                embed->author->icon_url = discord_strdup(icon_url->valuestring);
            }
        }
    }
    
    return embed;
}

/* Parse message from JSON */
static discord_message_t *discord_parse_message(cJSON *json) {
    if (!json) return NULL;
    
    discord_message_t *message = (discord_message_t *)calloc(1, sizeof(discord_message_t));
    if (!message) return NULL;
    
    cJSON *item;
    
    item = cJSON_GetObjectItem(json, "id");
    if (item && cJSON_IsString(item)) {
        message->id = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "channel_id");
    if (item && cJSON_IsString(item)) {
        message->channel_id = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "guild_id");
    if (item && cJSON_IsString(item)) {
        message->guild_id = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "author");
    if (item) {
        message->author = discord_parse_user(item);
    }
    
    item = cJSON_GetObjectItem(json, "member");
    if (item) {
        message->member = discord_parse_member(item);
    }
    
    item = cJSON_GetObjectItem(json, "content");
    if (item && cJSON_IsString(item)) {
        message->content = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "timestamp");
    if (item && cJSON_IsString(item)) {
        message->timestamp = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "tts");
    if (item && cJSON_IsBool(item)) {
        message->tts = cJSON_IsTrue(item);
    }
    
    item = cJSON_GetObjectItem(json, "mention_everyone");
    if (item && cJSON_IsBool(item)) {
        message->mention_everyone = cJSON_IsTrue(item);
    }
    
    item = cJSON_GetObjectItem(json, "mentions");
    if (item && cJSON_IsArray(item)) {
        message->mention_count = cJSON_GetArraySize(item);
        if (message->mention_count > 0) {
            message->mentions = (discord_user_t **)calloc(message->mention_count, sizeof(discord_user_t *));
            for (int i = 0; i < message->mention_count; i++) {
                cJSON *mention = cJSON_GetArrayItem(item, i);
                message->mentions[i] = discord_parse_user(mention);
            }
        }
    }
    
    item = cJSON_GetObjectItem(json, "embeds");
    if (item && cJSON_IsArray(item)) {
        message->embed_count = cJSON_GetArraySize(item);
        if (message->embed_count > 0) {
            message->embeds = (discord_embed_t **)calloc(message->embed_count, sizeof(discord_embed_t *));
            for (int i = 0; i < message->embed_count; i++) {
                cJSON *embed_json = cJSON_GetArrayItem(item, i);
                message->embeds[i] = discord_parse_embed(embed_json);
            }
        }
    }
    
    return message;
}

/* Parse channel from JSON */
static discord_channel_t *discord_parse_channel(cJSON *json) {
    if (!json) return NULL;
    
    discord_channel_t *channel = (discord_channel_t *)calloc(1, sizeof(discord_channel_t));
    if (!channel) return NULL;
    
    cJSON *item;
    
    item = cJSON_GetObjectItem(json, "id");
    if (item && cJSON_IsString(item)) {
        channel->id = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "type");
    if (item && cJSON_IsNumber(item)) {
        channel->type = item->valueint;
    }
    
    item = cJSON_GetObjectItem(json, "guild_id");
    if (item && cJSON_IsString(item)) {
        channel->guild_id = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "name");
    if (item && cJSON_IsString(item)) {
        channel->name = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "topic");
    if (item && cJSON_IsString(item)) {
        channel->topic = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "position");
    if (item && cJSON_IsNumber(item)) {
        channel->position = item->valueint;
    }
    
    return channel;
}

/* Parse guild from JSON */
static discord_guild_t *discord_parse_guild(cJSON *json) {
    if (!json) return NULL;
    
    discord_guild_t *guild = (discord_guild_t *)calloc(1, sizeof(discord_guild_t));
    if (!guild) return NULL;
    
    cJSON *item;
    
    item = cJSON_GetObjectItem(json, "id");
    if (item && cJSON_IsString(item)) {
        guild->id = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "name");
    if (item && cJSON_IsString(item)) {
        guild->name = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "icon");
    if (item && cJSON_IsString(item)) {
        guild->icon = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "owner_id");
    if (item && cJSON_IsString(item)) {
        guild->owner_id = discord_strdup(item->valuestring);
    }
    
    item = cJSON_GetObjectItem(json, "member_count");
    if (item && cJSON_IsNumber(item)) {
        guild->member_count = item->valueint;
    }
    
    return guild;
}

/* ============================================================================
 * WebSocket / Gateway Functions with libwebsockets
 * ============================================================================ */

/* Initialize platform-specific networking */
static int discord_net_init(void) {
#ifdef _WIN32
    WSADATA wsa_data;
    return WSAStartup(MAKEWORD(2, 2), &wsa_data);
#else
    return 0;
#endif
}

/* Cleanup platform-specific networking */
static void discord_net_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

/* Thread mutex functions */
static void discord_mutex_init(discord_mutex_t *mutex) {
#ifdef _WIN32
    InitializeCriticalSection(mutex);
#else
    pthread_mutex_init(mutex, NULL);
#endif
}

static void discord_mutex_destroy(discord_mutex_t *mutex) {
#ifdef _WIN32
    DeleteCriticalSection(mutex);
#else
    pthread_mutex_destroy(mutex);
#endif
}

static void discord_mutex_lock(discord_mutex_t *mutex) {
#ifdef _WIN32
    EnterCriticalSection(mutex);
#else
    pthread_mutex_lock(mutex);
#endif
}

static void discord_mutex_unlock(discord_mutex_t *mutex) {
#ifdef _WIN32
    LeaveCriticalSection(mutex);
#else
    pthread_mutex_unlock(mutex);
#endif
}

/* Thread creation */
static int discord_thread_create(discord_thread_t *thread, void *(*func)(void *), void *arg) {
#ifdef _WIN32
    *thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)func, arg, 0, NULL);
    return (*thread == NULL) ? -1 : 0;
#else
    return pthread_create(thread, NULL, func, arg);
#endif
}

static void discord_os_thread_join(discord_thread_t thread) {
#ifdef _WIN32
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
#else
    pthread_join(thread, NULL);
#endif
}

/* Sleep function */
static void discord_sleep_ms(int milliseconds) {
#ifdef _WIN32
    Sleep(milliseconds);
#else
    usleep(milliseconds * 1000);
#endif
}

/* Buffer management */
static void discord_buffer_init(discord_ws_buffer_t *buffer) {
    buffer->data = NULL;
    buffer->size = 0;
    buffer->capacity = 0;
}

static void discord_buffer_free(discord_ws_buffer_t *buffer) {
    if (buffer->data) {
        free(buffer->data);
        buffer->data = NULL;
    }
    buffer->size = 0;
    buffer->capacity = 0;
}

static int discord_buffer_append(discord_ws_buffer_t *buffer, const char *data, size_t len) {
    if (buffer->size + len > buffer->capacity) {
        size_t new_capacity = buffer->capacity == 0 ? 4096 : buffer->capacity * 2;
        while (new_capacity < buffer->size + len) {
            new_capacity *= 2;
        }
        
        char *new_data = (char *)realloc(buffer->data, new_capacity);
        if (!new_data) {
            return -1;
        }
        
        buffer->data = new_data;
        buffer->capacity = new_capacity;
    }
    
    memcpy(buffer->data + buffer->size, data, len);
    buffer->size += len;
    
    return 0;
}

static void discord_buffer_clear(discord_ws_buffer_t *buffer) {
    buffer->size = 0;
}

/* Get gateway URL */
static char *discord_get_gateway_url(discord_client_t *client) {
    discord_http_response_t *response = discord_http_request(client, "GET", "/gateway/bot", NULL);
    
    if (!response || !response->data) {
        return NULL;
    }
    
    cJSON *json = cJSON_Parse(response->data);
    char *url = NULL;
    
    if (json) {
        cJSON *url_item = cJSON_GetObjectItem(json, "url");
        if (url_item && cJSON_IsString(url_item)) {
            url = discord_strdup(url_item->valuestring);
        }
        cJSON_Delete(json);
    }
    
    discord_http_response_free(response);
    return url;
}

/* Send identify payload */
static int discord_send_identify(discord_client_t *client) {
    cJSON *identify = cJSON_CreateObject();
    cJSON_AddNumberToObject(identify, "op", DISCORD_OP_IDENTIFY);
    
    cJSON *d = cJSON_CreateObject();
    cJSON_AddStringToObject(d, "token", client->token);
    cJSON_AddNumberToObject(d, "intents", client->intents);
    
    cJSON *properties = cJSON_CreateObject();
    cJSON_AddStringToObject(properties, "os", 
#ifdef _WIN32
        "windows"
#elif defined(__APPLE__)
        "macos"
#else
        "linux"
#endif
    );
    cJSON_AddStringToObject(properties, "browser", "discord.h");
    cJSON_AddStringToObject(properties, "device", "discord.h");
    cJSON_AddItemToObject(d, "properties", properties);
    
    cJSON_AddItemToObject(identify, "d", d);
    
    char *payload = cJSON_PrintUnformatted(identify);
    cJSON_Delete(identify);
    
    if (!payload) {
        return -1;
    }
    
    /* Queue the message to be sent */
    discord_mutex_lock(&client->mutex);
    int result = discord_buffer_append(&client->tx_buffer, payload, strlen(payload));
    discord_mutex_unlock(&client->mutex);
    
    free(payload);
    
    if (result == 0) {
        /* Request callback to send data */
        lws_callback_on_writable(client->ws_connection);
    }
    
    return result;
}

/* Send heartbeat */
static int discord_send_heartbeat(discord_client_t *client) {
    cJSON *heartbeat = cJSON_CreateObject();
    cJSON_AddNumberToObject(heartbeat, "op", DISCORD_OP_HEARTBEAT);
    
    if (client->sequence > 0) {
        cJSON_AddNumberToObject(heartbeat, "d", client->sequence);
    } else {
        cJSON_AddNullToObject(heartbeat, "d");
    }
    
    char *payload = cJSON_PrintUnformatted(heartbeat);
    cJSON_Delete(heartbeat);
    
    if (!payload) {
        return -1;
    }
    
    /* Queue the message to be sent */
    discord_mutex_lock(&client->mutex);
    int result = discord_buffer_append(&client->tx_buffer, payload, strlen(payload));
    discord_mutex_unlock(&client->mutex);
    
    free(payload);
    
    if (result == 0) {
        client->last_heartbeat = time(NULL);
        client->heartbeat_acked = false;
        lws_callback_on_writable(client->ws_connection);
    }
    
    return result;
}

/* Handle gateway event */
static void discord_handle_event(discord_client_t *client, const char *payload) {
    cJSON *json = cJSON_Parse(payload);
    if (!json) {
        fprintf(stderr, "discord.h: Failed to parse JSON payload\n");
        return;
    }
    
    cJSON *op_item = cJSON_GetObjectItem(json, "op");
    if (!op_item || !cJSON_IsNumber(op_item)) {
        cJSON_Delete(json);
        return;
    }
    
    int op = op_item->valueint;
    cJSON *d = cJSON_GetObjectItem(json, "d");
    cJSON *t = cJSON_GetObjectItem(json, "t");
    cJSON *s = cJSON_GetObjectItem(json, "s");
    
    /* Update sequence number */
    if (s && cJSON_IsNumber(s)) {
        client->sequence = s->valueint;
    }
    
    switch (op) {
        case DISCORD_OP_HELLO: {
            /* Extract heartbeat interval */
            if (d) {
                cJSON *interval = cJSON_GetObjectItem(d, "heartbeat_interval");
                if (interval && cJSON_IsNumber(interval)) {
                    client->heartbeat_interval = interval->valueint;
                    printf("discord.h: Heartbeat interval: %d ms\n", client->heartbeat_interval);
                }
            }
            
            /* Send identify */
            discord_send_identify(client);
            break;
        }
        
        case DISCORD_OP_HEARTBEAT_ACK: {
            client->heartbeat_acked = true;
            break;
        }
        
        case DISCORD_OP_DISPATCH: {
            if (!t || !cJSON_IsString(t) || !d) {
                break;
            }
            
            const char *event_name = t->valuestring;
            
            if (strcmp(event_name, "READY") == 0) {
                /* Extract session ID */
                cJSON *session_id = cJSON_GetObjectItem(d, "session_id");
                if (session_id && cJSON_IsString(session_id)) {
                    free(client->session_id);
                    client->session_id = discord_strdup(session_id->valuestring);
                }
                
                /* Extract user info */
                cJSON *user_json = cJSON_GetObjectItem(d, "user");
                if (user_json) {
                    client->user = discord_parse_user(user_json);
                }
                
                client->state = DISCORD_STATE_CONNECTED;
                client->identified = true;
                
                printf("discord.h: Successfully connected and identified\n");
                
                /* Call ready callback */
                if (client->on_ready && client->user) {
                    client->on_ready(client, client->user);
                }
            }
            else if (strcmp(event_name, "MESSAGE_CREATE") == 0) {
                discord_message_t *message = discord_parse_message(d);
                if (message && client->on_message) {
                    client->on_message(client, message);
                }
                discord_message_destroy(message);
            }
            else if (strcmp(event_name, "MESSAGE_DELETE") == 0) {
                cJSON *id = cJSON_GetObjectItem(d, "id");
                cJSON *channel_id = cJSON_GetObjectItem(d, "channel_id");
                
                if (id && channel_id && cJSON_IsString(id) && cJSON_IsString(channel_id)) {
                    if (client->on_message_delete) {
                        client->on_message_delete(client, id->valuestring, channel_id->valuestring);
                    }
                }
            }
            else if (strcmp(event_name, "GUILD_CREATE") == 0) {
                discord_guild_t *guild = discord_parse_guild(d);
                if (guild && client->on_guild_create) {
                    client->on_guild_create(client, guild);
                }
                discord_guild_destroy(guild);
            }
            break;
        }
        
        case DISCORD_OP_RECONNECT: {
            printf("discord.h: Server requested reconnect\n");
            client->state = DISCORD_STATE_RECONNECTING;
            break;
        }
        
        case DISCORD_OP_INVALID_SESSION: {
            printf("discord.h: Invalid session, re-identifying...\n");
            /* Reconnect after delay */
            discord_sleep_ms(5000);
            discord_send_identify(client);
            break;
        }
    }
    
    cJSON_Delete(json);
}

/* libwebsockets callback */
static int discord_ws_callback(struct lws *wsi, enum lws_callback_reasons reason,
                               void *user, void *in, size_t len) {
    discord_client_t *client = (discord_client_t *)lws_context_user(lws_get_context(wsi));
    
    if (!client) {
        return 0;
    }
    
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            printf("discord.h: WebSocket connection established\n");
            client->state = DISCORD_STATE_CONNECTING;
            break;
            
        case LWS_CALLBACK_CLIENT_RECEIVE:
            /* Append received data to buffer */
            discord_mutex_lock(&client->mutex);
            discord_buffer_append(&client->rx_buffer, (const char *)in, len);
            
            /* Check if this is the final fragment */
            if (lws_is_final_fragment(wsi)) {
                /* Null-terminate the buffer */
                discord_buffer_append(&client->rx_buffer, "\0", 1);
                
                /* Process the complete message */
                discord_handle_event(client, client->rx_buffer.data);
                
                /* Clear the buffer for next message */
                discord_buffer_clear(&client->rx_buffer);
            }
            discord_mutex_unlock(&client->mutex);
            break;
            
        case LWS_CALLBACK_CLIENT_WRITEABLE:
            discord_mutex_lock(&client->mutex);
            if (client->tx_buffer.size > 0) {
                /* Prepare buffer with LWS_PRE bytes before the payload */
                size_t total_size = LWS_PRE + client->tx_buffer.size;
                unsigned char *buf = (unsigned char *)malloc(total_size);
                
                if (buf) {
                    memcpy(buf + LWS_PRE, client->tx_buffer.data, client->tx_buffer.size);
                    
                    int written = lws_write(wsi, buf + LWS_PRE, client->tx_buffer.size, LWS_WRITE_TEXT);
                    
                    if (written < 0) {
                        fprintf(stderr, "discord.h: Failed to write to WebSocket\n");
                    } else {
                        /* Clear the buffer after successful send */
                        discord_buffer_clear(&client->tx_buffer);
                    }
                    
                    free(buf);
                }
            }
            discord_mutex_unlock(&client->mutex);
            break;
            
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            fprintf(stderr, "discord.h: WebSocket connection error: %s\n", 
                    in ? (char *)in : "unknown");
            client->state = DISCORD_STATE_RECONNECTING;
            break;
            
        case LWS_CALLBACK_CLIENT_CLOSED:
            printf("discord.h: WebSocket connection closed\n");
            if (client->running) {
                client->state = DISCORD_STATE_RECONNECTING;
            }
            break;
            
        default:
            break;
    }
    
    return 0;
}

/* WebSocket protocols */
static struct lws_protocols protocols[] = {
    {
        "discord-gateway",
        discord_ws_callback,
        0,
        65536,
        0, NULL, 0
    },
    { NULL, NULL, 0, 0, 0, NULL, 0 }
};

/* Connect to Discord gateway using libwebsockets */
static int discord_ws_connect(discord_client_t *client, const char *gateway_url) {
    struct lws_context_creation_info info;
    struct lws_client_connect_info ccinfo;
    
    memset(&info, 0, sizeof(info));
    memset(&ccinfo, 0, sizeof(ccinfo));
    
    /* Parse gateway URL */
    char host[256] = {0};
    char path[256] = {0};
    int port = 443;
    int use_ssl = 1;
    
    /* Parse URL (expecting wss://gateway.discord.gg) */
    if (strncmp(gateway_url, "wss://", 6) == 0) {
        const char *url_start = gateway_url + 6;
        const char *path_start = strchr(url_start, '/');
        
        if (path_start) {
            size_t host_len = path_start - url_start;
            if (host_len < sizeof(host)) {
                strncpy(host, url_start, host_len);
                host[host_len] = '\0';
            }
            snprintf(path, sizeof(path), "%s/?v=%s&encoding=%s", 
                    path_start, DISCORD_GATEWAY_VERSION, DISCORD_GATEWAY_ENCODING);
        } else {
            strncpy(host, url_start, sizeof(host) - 1);
            snprintf(path, sizeof(path), "/?v=%s&encoding=%s", 
                    DISCORD_GATEWAY_VERSION, DISCORD_GATEWAY_ENCODING);
        }
    } else {
        fprintf(stderr, "discord.h: Invalid gateway URL format\n");
        return -1;
    }
    
    printf("discord.h: Connecting to %s%s\n", host, path);
    
    /* Create libwebsockets context */
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.user = client;
    
    client->ws_context = lws_create_context(&info);
    if (!client->ws_context) {
        fprintf(stderr, "discord.h: Failed to create libwebsockets context\n");
        return -1;
    }
    
    /* Setup connection info */
    ccinfo.context = client->ws_context;
    ccinfo.address = host;
    ccinfo.port = port;
    ccinfo.path = path;
    ccinfo.host = host;
    ccinfo.origin = host;
    ccinfo.protocol = protocols[0].name;
    ccinfo.ssl_connection = use_ssl ? LCCSCF_USE_SSL | 
                                      LCCSCF_ALLOW_SELFSIGNED | 
                                      LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK : 0;
    
    /* Connect */
    client->ws_connection = lws_client_connect_via_info(&ccinfo);
    if (!client->ws_connection) {
        fprintf(stderr, "discord.h: Failed to connect to gateway\n");
        lws_context_destroy(client->ws_context);
        client->ws_context = NULL;
        return -1;
    }
    
    return 0;
}

/* Heartbeat thread */
static void *discord_heartbeat_thread(void *arg) {
    discord_client_t *client = (discord_client_t *)arg;
    
    /* Wait for heartbeat interval to be set */
    while (client->running && client->heartbeat_interval == 0) {
        discord_sleep_ms(100);
    }
    
    while (client->running && client->state == DISCORD_STATE_CONNECTED) {
        if (client->heartbeat_interval > 0) {
            discord_sleep_ms(client->heartbeat_interval);
            
            /* Check if last heartbeat was acknowledged */
            if (!client->heartbeat_acked && client->last_heartbeat > 0) {
                fprintf(stderr, "discord.h: Heartbeat not acknowledged, reconnecting...\n");
                client->state = DISCORD_STATE_RECONNECTING;
                break;
            }
            
            /* Send heartbeat */
            discord_mutex_lock(&client->mutex);
            discord_send_heartbeat(client);
            discord_mutex_unlock(&client->mutex);
        }
    }
    
    return NULL;
}

/* Gateway thread */
static void *discord_gateway_thread(void *arg) {
    discord_client_t *client = (discord_client_t *)arg;
    
    while (client->running) {
        /* Service the WebSocket connection */
        if (client->ws_context) {
            lws_service(client->ws_context, 50);
        }
        
        /* Handle reconnection */
        if (client->state == DISCORD_STATE_RECONNECTING && client->running) {
            fprintf(stderr, "discord.h: Attempting to reconnect...\n");
            
            /* Clean up existing connection */
            if (client->ws_context) {
                lws_context_destroy(client->ws_context);
                client->ws_context = NULL;
                client->ws_connection = NULL;
            }
            
            discord_sleep_ms(5000);
            
            /* Attempt reconnection */
            if (discord_ws_connect(client, client->gateway_url) == 0) {
                client->state = DISCORD_STATE_CONNECTING;
                client->identified = false;
            }
        }
    }
    
    return NULL;
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

/* Create Discord client */
discord_client_t *discord_client_create(const char *token, int intents) {
    if (!token) {
        fprintf(stderr, "discord.h: Token cannot be NULL\n");
        return NULL;
    }
    
    /* Initialize networking */
    if (discord_net_init() != 0) {
        fprintf(stderr, "discord.h: Failed to initialize networking\n");
        return NULL;
    }
    
    /* Initialize libcurl */
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    discord_client_t *client = (discord_client_t *)calloc(1, sizeof(discord_client_t));
    if (!client) {
        return NULL;
    }
    
    client->token = discord_strdup(token);
    client->intents = intents;
    client->state = DISCORD_STATE_DISCONNECTED;
    client->running = false;
    client->sequence = 0;
    client->heartbeat_acked = true;
    client->identified = false;
    
    discord_buffer_init(&client->rx_buffer);
    discord_buffer_init(&client->tx_buffer);
    discord_mutex_init(&client->mutex);
    
    return client;
}

/* Destroy Discord client */
void discord_client_destroy(discord_client_t *client) {
    if (!client) return;
    
    if (client->running) {
        discord_client_stop(client);
    }
    
    free(client->token);
    free(client->gateway_url);
    free(client->session_id);
    
    if (client->user) {
        discord_user_destroy(client->user);
    }
    
    discord_buffer_free(&client->rx_buffer);
    discord_buffer_free(&client->tx_buffer);
    discord_mutex_destroy(&client->mutex);
    
    free(client);
    
    curl_global_cleanup();
    discord_net_cleanup();
}

/* Run Discord client */
int discord_client_run(discord_client_t *client) {
    if (!client) return -1;
    
    /* Get gateway URL */
    client->gateway_url = discord_get_gateway_url(client);
    if (!client->gateway_url) {
        fprintf(stderr, "discord.h: Failed to get gateway URL\n");
        return -1;
    }
    
    printf("discord.h: Connecting to gateway: %s\n", client->gateway_url);
    
    /* Connect to gateway */
    if (discord_ws_connect(client, client->gateway_url) != 0) {
        fprintf(stderr, "discord.h: Failed to connect to gateway\n");
        return -1;
    }
    
    client->state = DISCORD_STATE_CONNECTING;
    client->running = true;
    
    /* Start gateway thread */
    if (discord_thread_create(&client->gateway_thread, discord_gateway_thread, client) != 0) {
        fprintf(stderr, "discord.h: Failed to create gateway thread\n");
        client->running = false;
        return -1;
    }
    
    /* Wait for connection to be established */
    while (client->running && client->state != DISCORD_STATE_CONNECTED) {
        discord_sleep_ms(100);
    }
    
    if (!client->running) {
        return -1;
    }
    
    /* Start heartbeat thread */
    if (discord_thread_create(&client->heartbeat_thread, discord_heartbeat_thread, client) != 0) {
        fprintf(stderr, "discord.h: Failed to create heartbeat thread\n");
        client->running = false;
        return -1;
    }
    
    printf("discord.h: Connected successfully\n");
    
    /* Wait for threads to finish */
    discord_os_thread_join(client->gateway_thread);
    discord_os_thread_join(client->heartbeat_thread);
    
    return 0;
}

/* Stop Discord client */
void discord_client_stop(discord_client_t *client) {
    if (!client) return;
    
    client->running = false;
    client->state = DISCORD_STATE_CLOSING;
    
    if (client->ws_context) {
        lws_context_destroy(client->ws_context);
        client->ws_context = NULL;
        client->ws_connection = NULL;
    }
}

/* ============================================================================
 * Event Handler Setters
 * ============================================================================ */

void discord_set_on_ready(discord_client_t *client, discord_on_ready_cb callback) {
    if (client) {
        client->on_ready = callback;
    }
}

void discord_set_on_message(discord_client_t *client, discord_on_message_cb callback) {
    if (client) {
        client->on_message = callback;
    }
}

void discord_set_on_message_delete(discord_client_t *client, discord_on_message_delete_cb callback) {
    if (client) {
        client->on_message_delete = callback;
    }
}

void discord_set_on_guild_create(discord_client_t *client, discord_on_guild_create_cb callback) {
    if (client) {
        client->on_guild_create = callback;
    }
}

/* ============================================================================
 * DM Operations
 * ============================================================================ */

/* Create DM channel with a user */
discord_channel_t *discord_create_dm(discord_client_t *client, const char *recipient_id) {
    if (!client || !recipient_id) {
        return NULL;
    }
    
    /* Create JSON payload with recipient_id */
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "recipient_id", recipient_id);
    
    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    
    if (!body) {
        return NULL;
    }
    
    /* POST to /users/@me/channels */
    discord_http_response_t *response = discord_http_request(client, "POST", "/users/@me/channels", body);
    free(body);
    
    if (!response || !response->data) {
        return NULL;
    }
    
    /* Parse the returned channel object */
    cJSON *response_json = cJSON_Parse(response->data);
    discord_channel_t *channel = NULL;
    
    if (response_json) {
        channel = discord_parse_channel(response_json);
        cJSON_Delete(response_json);
    }
    
    discord_http_response_free(response);
    return channel;
}

/* ============================================================================
 * Message Operations
 * ============================================================================ */

/* Create message */
discord_message_t *discord_create_message(discord_client_t *client, const char *channel_id, const char *content) {
    if (!client || !channel_id || !content) {
        return NULL;
    }
    
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "content", content);
    
    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/messages", channel_id);
    
    discord_http_response_t *response = discord_http_request(client, "POST", endpoint, body);
    free(body);
    
    if (!response || !response->data) {
        return NULL;
    }
    
    cJSON *response_json = cJSON_Parse(response->data);
    discord_message_t *message = NULL;
    
    if (response_json) {
        message = discord_parse_message(response_json);
        cJSON_Delete(response_json);
    }
    
    discord_http_response_free(response);
    return message;
}

/* Create message with embed */
discord_message_t *discord_create_message_embed(discord_client_t *client, const char *channel_id, discord_embed_t *embed) {
    if (!client || !channel_id || !embed) {
        return NULL;
    }
    
    cJSON *json = cJSON_CreateObject();
    cJSON *embeds_array = cJSON_CreateArray();
    cJSON *embed_json = cJSON_CreateObject();
    
    if (embed->title) {
        cJSON_AddStringToObject(embed_json, "title", embed->title);
    }
    if (embed->description) {
        cJSON_AddStringToObject(embed_json, "description", embed->description);
    }
    if (embed->url) {
        cJSON_AddStringToObject(embed_json, "url", embed->url);
    }
    if (embed->color > 0) {
        cJSON_AddNumberToObject(embed_json, "color", embed->color);
    }
    if (embed->timestamp) {
        cJSON_AddStringToObject(embed_json, "timestamp", embed->timestamp);
    }
    
    if (embed->footer) {
        cJSON *footer_json = cJSON_CreateObject();
        if (embed->footer->text) {
            cJSON_AddStringToObject(footer_json, "text", embed->footer->text);
        }
        if (embed->footer->icon_url) {
            cJSON_AddStringToObject(footer_json, "icon_url", embed->footer->icon_url);
        }
        cJSON_AddItemToObject(embed_json, "footer", footer_json);
    }
    
    if (embed->author) {
        cJSON *author_json = cJSON_CreateObject();
        if (embed->author->name) {
            cJSON_AddStringToObject(author_json, "name", embed->author->name);
        }
        if (embed->author->url) {
            cJSON_AddStringToObject(author_json, "url", embed->author->url);
        }
        if (embed->author->icon_url) {
            cJSON_AddStringToObject(author_json, "icon_url", embed->author->icon_url);
        }
        cJSON_AddItemToObject(embed_json, "author", author_json);
    }
    
    if (embed->fields && embed->field_count > 0) {
        cJSON *fields_array = cJSON_CreateArray();
        for (int i = 0; i < embed->field_count; i++) {
            cJSON *field_json = cJSON_CreateObject();
            cJSON_AddStringToObject(field_json, "name", embed->fields[i].name);
            cJSON_AddStringToObject(field_json, "value", embed->fields[i].value);
            cJSON_AddBoolToObject(field_json, "inline", embed->fields[i].inline_field);
            cJSON_AddItemToArray(fields_array, field_json);
        }
        cJSON_AddItemToObject(embed_json, "fields", fields_array);
    }
    
    if (embed->thumbnail_url) {
        cJSON *thumbnail_json = cJSON_CreateObject();
        cJSON_AddStringToObject(thumbnail_json, "url", embed->thumbnail_url);
        cJSON_AddItemToObject(embed_json, "thumbnail", thumbnail_json);
    }
    
    if (embed->image_url) {
        cJSON *image_json = cJSON_CreateObject();
        cJSON_AddStringToObject(image_json, "url", embed->image_url);
        cJSON_AddItemToObject(embed_json, "image", image_json);
    }
    
    cJSON_AddItemToArray(embeds_array, embed_json);
    cJSON_AddItemToObject(json, "embeds", embeds_array);
    
    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/messages", channel_id);
    
    discord_http_response_t *response = discord_http_request(client, "POST", endpoint, body);
    free(body);
    
    if (!response || !response->data) {
        return NULL;
    }
    
    cJSON *response_json = cJSON_Parse(response->data);
    discord_message_t *message = NULL;
    
    if (response_json) {
        message = discord_parse_message(response_json);
        cJSON_Delete(response_json);
    }
    
    discord_http_response_free(response);
    return message;
}

/* Delete message */
int discord_delete_message(discord_client_t *client, const char *channel_id, const char *message_id) {
    if (!client || !channel_id || !message_id) {
        return -1;
    }
    
    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/messages/%s", channel_id, message_id);
    
    discord_http_response_t *response = discord_http_request(client, "DELETE", endpoint, NULL);
    
    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    
    return result;
}

/* Edit message */
int discord_edit_message(discord_client_t *client, const char *channel_id, const char *message_id, const char *content) {
    if (!client || !channel_id || !message_id || !content) {
        return -1;
    }
    
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "content", content);
    
    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    
    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/messages/%s", channel_id, message_id);
    
    discord_http_response_t *response = discord_http_request(client, "PATCH", endpoint, body);
    free(body);
    
    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    
    return result;
}

/* ============================================================================
 * Channel Operations
 * ============================================================================ */

/* Get channel */
discord_channel_t *discord_get_channel(discord_client_t *client, const char *channel_id) {
    if (!client || !channel_id) {
        return NULL;
    }
    
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s", channel_id);
    
    discord_http_response_t *response = discord_http_request(client, "GET", endpoint, NULL);
    
    if (!response || !response->data) {
        return NULL;
    }
    
    cJSON *json = cJSON_Parse(response->data);
    discord_channel_t *channel = NULL;
    
    if (json) {
        channel = discord_parse_channel(json);
        cJSON_Delete(json);
    }
    
    discord_http_response_free(response);
    return channel;
}

/* Send typing indicator */
int discord_send_typing(discord_client_t *client, const char *channel_id) {
    if (!client || !channel_id) {
        return -1;
    }
    
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/typing", channel_id);
    
    discord_http_response_t *response = discord_http_request(client, "POST", endpoint, NULL);
    
    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    
    return result;
}

/* ============================================================================
 * Guild Operations
 * ============================================================================ */

/* Get guild */
discord_guild_t *discord_get_guild(discord_client_t *client, const char *guild_id) {
    if (!client || !guild_id) {
        return NULL;
    }
    
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s", guild_id);
    
    discord_http_response_t *response = discord_http_request(client, "GET", endpoint, NULL);
    
    if (!response || !response->data) {
        return NULL;
    }
    
    cJSON *json = cJSON_Parse(response->data);
    discord_guild_t *guild = NULL;
    
    if (json) {
        guild = discord_parse_guild(json);
        cJSON_Delete(json);
    }
    
    discord_http_response_free(response);
    return guild;
}

/* ============================================================================
 * Embed Builder Functions
 * ============================================================================ */

/* Create embed */
discord_embed_t *discord_embed_create(void) {
    discord_embed_t *embed = (discord_embed_t *)calloc(1, sizeof(discord_embed_t));
    return embed;
}

/* Destroy embed */
void discord_embed_destroy(discord_embed_t *embed) {
    if (!embed) return;
    
    free(embed->title);
    free(embed->description);
    free(embed->url);
    free(embed->timestamp);
    free(embed->thumbnail_url);
    free(embed->image_url);
    
    if (embed->footer) {
        free(embed->footer->text);
        free(embed->footer->icon_url);
        free(embed->footer);
    }
    
    if (embed->author) {
        free(embed->author->name);
        free(embed->author->url);
        free(embed->author->icon_url);
        free(embed->author);
    }
    
    if (embed->fields) {
        for (int i = 0; i < embed->field_count; i++) {
            free(embed->fields[i].name);
            free(embed->fields[i].value);
        }
        free(embed->fields);
    }
    
    free(embed);
}

/* Set embed title */
void discord_embed_set_title(discord_embed_t *embed, const char *title) {
    if (!embed) return;
    free(embed->title);
    embed->title = discord_strdup(title);
}

/* Set embed description */
void discord_embed_set_description(discord_embed_t *embed, const char *description) {
    if (!embed) return;
    free(embed->description);
    embed->description = discord_strdup(description);
}

/* Set embed URL */
void discord_embed_set_url(discord_embed_t *embed, const char *url) {
    if (!embed) return;
    free(embed->url);
    embed->url = discord_strdup(url);
}

/* Set embed color */
void discord_embed_set_color(discord_embed_t *embed, int color) {
    if (!embed) return;
    embed->color = color;
}

/* Set embed timestamp */
void discord_embed_set_timestamp(discord_embed_t *embed, const char *timestamp) {
    if (!embed) return;
    free(embed->timestamp);
    embed->timestamp = discord_strdup(timestamp);
}

/* Set embed footer */
void discord_embed_set_footer(discord_embed_t *embed, const char *text, const char *icon_url) {
    if (!embed) return;
    
    if (!embed->footer) {
        embed->footer = (discord_embed_footer_t *)calloc(1, sizeof(discord_embed_footer_t));
    }
    
    if (embed->footer) {
        free(embed->footer->text);
        free(embed->footer->icon_url);
        embed->footer->text = discord_strdup(text);
        embed->footer->icon_url = discord_strdup(icon_url);
    }
}

/* Set embed author */
void discord_embed_set_author(discord_embed_t *embed, const char *name, const char *url, const char *icon_url) {
    if (!embed) return;
    
    if (!embed->author) {
        embed->author = (discord_embed_author_t *)calloc(1, sizeof(discord_embed_author_t));
    }
    
    if (embed->author) {
        free(embed->author->name);
        free(embed->author->url);
        free(embed->author->icon_url);
        embed->author->name = discord_strdup(name);
        embed->author->url = discord_strdup(url);
        embed->author->icon_url = discord_strdup(icon_url);
    }
}

/* Add embed field */
void discord_embed_add_field(discord_embed_t *embed, const char *name, const char *value, bool inline_field) {
    if (!embed || !name || !value) return;
    
    discord_embed_field_t *new_fields = (discord_embed_field_t *)realloc(
        embed->fields, 
        (embed->field_count + 1) * sizeof(discord_embed_field_t)
    );
    
    if (!new_fields) return;
    
    embed->fields = new_fields;
    embed->fields[embed->field_count].name = discord_strdup(name);
    embed->fields[embed->field_count].value = discord_strdup(value);
    embed->fields[embed->field_count].inline_field = inline_field;
    embed->field_count++;
}

/* Set embed thumbnail */
void discord_embed_set_thumbnail(discord_embed_t *embed, const char *url) {
    if (!embed) return;
    free(embed->thumbnail_url);
    embed->thumbnail_url = discord_strdup(url);
}

/* Set embed image */
void discord_embed_set_image(discord_embed_t *embed, const char *url) {
    if (!embed) return;
    free(embed->image_url);
    embed->image_url = discord_strdup(url);
}

/* ============================================================================
 * Moderation Operations
 * ============================================================================ */

/* Kick a member: DELETE /guilds/{guild.id}/members/{user.id} */
int discord_kick_member(discord_client_t *client, const char *guild_id, const char *user_id, const char *reason) {
    if (!client || !guild_id || !user_id) return -1;

    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/members/%s", guild_id, user_id);

    discord_http_response_t *response = discord_http_request_ex(client, "DELETE", endpoint, NULL, reason);
    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    return result;
}

/* Ban a member: PUT /guilds/{guild.id}/bans/{user.id}
   Optionally delete recent messages (seconds up to 604800). */
int discord_ban_member(discord_client_t *client, const char *guild_id, const char *user_id, int delete_message_seconds, const char *reason) {
    if (!client || !guild_id || !user_id) return -1;

    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/bans/%s", guild_id, user_id);

    char *body = NULL;
    if (delete_message_seconds > 0) {
        cJSON *json = cJSON_CreateObject();
        cJSON_AddNumberToObject(json, "delete_message_seconds", delete_message_seconds);
        body = cJSON_PrintUnformatted(json);
        cJSON_Delete(json);
    }

    discord_http_response_t *response = discord_http_request_ex(client, "PUT", endpoint, body, reason);
    if (body) free(body);

    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    return result;
}

/* Unban a member: DELETE /guilds/{guild.id}/bans/{user.id} */
int discord_unban_member(discord_client_t *client, const char *guild_id, const char *user_id, const char *reason) {
    if (!client || !guild_id || !user_id) return -1;

    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/bans/%s", guild_id, user_id);

    discord_http_response_t *response = discord_http_request_ex(client, "DELETE", endpoint, NULL, reason);
    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    return result;
}

/* Timeout a member: PATCH /guilds/{guild.id}/members/{user.id}
   Body: { "communication_disabled_until": "<ISO8601>" } */
int discord_timeout_member(discord_client_t *client, const char *guild_id, const char *user_id, int duration_seconds, const char *reason) {
    if (!client || !guild_id || !user_id || duration_seconds <= 0) return -1;

    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/members/%s", guild_id, user_id);

    char *until = discord_timestamp_offset_seconds(duration_seconds);
    if (!until) return -1;

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "communication_disabled_until", until);
    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    free(until);

    if (!body) return -1;

    discord_http_response_t *response = discord_http_request_ex(client, "PATCH", endpoint, body, reason);
    free(body);

    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    return result;
}

/* Remove timeout: PATCH /guilds/{guild.id}/members/{user.id}
   Body: { "communication_disabled_until": null } */
int discord_remove_timeout(discord_client_t *client, const char *guild_id, const char *user_id, const char *reason) {
    if (!client || !guild_id || !user_id) return -1;

    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/members/%s", guild_id, user_id);

    cJSON *json = cJSON_CreateObject();
    cJSON_AddNullToObject(json, "communication_disabled_until");
    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    if (!body) return -1;

    discord_http_response_t *response = discord_http_request_ex(client, "PATCH", endpoint, body, reason);
    free(body);

    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    return result;
}

/* Add a role: PUT /guilds/{guild.id}/members/{user.id}/roles/{role.id} */
int discord_add_member_role(discord_client_t *client, const char *guild_id, const char *user_id, const char *role_id, const char *reason) {
    if (!client || !guild_id || !user_id || !role_id) return -1;

    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/members/%s/roles/%s", guild_id, user_id, role_id);

    discord_http_response_t *response = discord_http_request_ex(client, "PUT", endpoint, NULL, reason);
    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    return result;
}

/* Remove a role: DELETE /guilds/{guild.id}/members/{user.id}/roles/{role.id} */
int discord_remove_member_role(discord_client_t *client, const char *guild_id, const char *user_id, const char *role_id, const char *reason) {
    if (!client || !guild_id || !user_id || !role_id) return -1;

    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/members/%s/roles/%s", guild_id, user_id, role_id);

    discord_http_response_t *response = discord_http_request_ex(client, "DELETE", endpoint, NULL, reason);
    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    return result;
}

/* Server voice mute: PATCH /guilds/{guild.id}/members/{user.id}
   Body: { "mute": true/false }
   Note: Applies to voice; requires the bot to have permission and member to be in a voice channel. */
int discord_set_voice_mute(discord_client_t *client, const char *guild_id, const char *user_id, bool mute, const char *reason) {
    if (!client || !guild_id || !user_id) return -1;

    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/members/%s", guild_id, user_id);

    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "mute", mute);
    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    if (!body) return -1;

    discord_http_response_t *response = discord_http_request_ex(client, "PATCH", endpoint, body, reason);
    free(body);

    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    return result;
}

/* Server voice deaf: PATCH /guilds/{guild.id}/members/{user.id}
   Body: { "deaf": true/false } */
int discord_set_voice_deaf(discord_client_t *client, const char *guild_id, const char *user_id, bool deaf, const char *reason) {
    if (!client || !guild_id || !user_id) return -1;

    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/members/%s", guild_id, user_id);

    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "deaf", deaf);
    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    if (!body) return -1;

    discord_http_response_t *response = discord_http_request_ex(client, "PATCH", endpoint, body, reason);
    free(body);

    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    return result;
}

/* ============================================================================
 * Channel / Message Utilities
 * ============================================================================ */

/* Bulk delete 2..100 messages (must be <= 14 days old) */
int discord_bulk_delete_messages(discord_client_t *client, const char *channel_id, const char **message_ids, int count, const char *reason) {
    if (!client || !channel_id || !message_ids || count < 2 || count > 100) return -1;

    cJSON *json = cJSON_CreateObject();
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        if (!message_ids[i]) { cJSON_Delete(json); return -1; }
        cJSON_AddItemToArray(arr, cJSON_CreateString(message_ids[i]));
    }
    cJSON_AddItemToObject(json, "messages", arr);
    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (!body) return -1;

    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/messages/bulk-delete", channel_id);

    discord_http_response_t *response = discord_http_request_ex(client, "POST", endpoint, body, reason);
    free(body);

    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    return result;
}

/* Set channel slowmode (seconds, typically 0..21600) */
int discord_channel_set_slowmode(discord_client_t *client, const char *channel_id, int rate_limit_per_user, const char *reason) {
    if (!client || !channel_id || rate_limit_per_user < 0) return -1;

    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "rate_limit_per_user", rate_limit_per_user);
    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (!body) return -1;

    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s", channel_id);

    discord_http_response_t *response = discord_http_request_ex(client, "PATCH", endpoint, body, reason);
    free(body);

    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    return result;
}

/* Pin/unpin message */
int discord_pin_message(discord_client_t *client, const char *channel_id, const char *message_id, const char *reason) {
    if (!client || !channel_id || !message_id) return -1;
    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/pins/%s", channel_id, message_id);
    discord_http_response_t *response = discord_http_request_ex(client, "PUT", endpoint, NULL, reason);
    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    return result;
}

int discord_unpin_message(discord_client_t *client, const char *channel_id, const char *message_id, const char *reason) {
    if (!client || !channel_id || !message_id) return -1;
    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/pins/%s", channel_id, message_id);
    discord_http_response_t *response = discord_http_request_ex(client, "DELETE", endpoint, NULL, reason);
    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    return result;
}

/* ============================================================================
 * Reactions Management
 * ============================================================================ */

/* Delete all reactions from a message */
int discord_delete_all_reactions(discord_client_t *client, const char *channel_id, const char *message_id, const char *reason) {
    if (!client || !channel_id || !message_id) return -1;
    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/messages/%s/reactions", channel_id, message_id);
    discord_http_response_t *response = discord_http_request_ex(client, "DELETE", endpoint, NULL, reason);
    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    return result;
}

/* Delete all reactions for a specific emoji (emoji must be URL-encoded, e.g., %F0%9F%98%80 or name:id) */
int discord_delete_reactions_emoji(discord_client_t *client, const char *channel_id, const char *message_id, const char *emoji, const char *reason) {
    if (!client || !channel_id || !message_id || !emoji) return -1;
    char *emoji_enc = discord_url_encode(emoji);
    if (!emoji_enc) return -1;
    char endpoint[768];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/messages/%s/reactions/%s", channel_id, message_id, emoji_enc);
    free(emoji_enc);

    discord_http_response_t *response = discord_http_request_ex(client, "DELETE", endpoint, NULL, reason);
    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    return result;
}

/* Delete a specific user's reaction for an emoji */
int discord_delete_user_reaction(discord_client_t *client, const char *channel_id, const char *message_id, const char *emoji, const char *user_id, const char *reason) {
    if (!client || !channel_id || !message_id || !emoji || !user_id) return -1;
    char *emoji_enc = discord_url_encode(emoji);
    if (!emoji_enc) return -1;
    char endpoint[896];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/messages/%s/reactions/%s/%s", channel_id, message_id, emoji_enc, user_id);
    free(emoji_enc);

    discord_http_response_t *response = discord_http_request_ex(client, "DELETE", endpoint, NULL, reason);
    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    return result;
}

/* ============================================================================
 * Members / Bans Utilities
 * ============================================================================ */

/* Set member nickname (empty string "" clears nick) */
int discord_set_member_nick(discord_client_t *client, const char *guild_id, const char *user_id, const char *new_nick, const char *reason) {
    if (!client || !guild_id || !user_id || !new_nick) return -1;
    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/members/%s", guild_id, user_id);

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "nick", new_nick);
    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (!body) return -1;

    discord_http_response_t *response = discord_http_request_ex(client, "PATCH", endpoint, body, reason);
    free(body);

    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    return result;
}

/* Move a member to a voice channel (set channel_id to NULL to disconnect) */
int discord_move_member_voice(discord_client_t *client, const char *guild_id, const char *user_id, const char *channel_id, const char *reason) {
    if (!client || !guild_id || !user_id) return -1;
    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/members/%s", guild_id, user_id);

    cJSON *json = cJSON_CreateObject();
    if (channel_id) cJSON_AddStringToObject(json, "channel_id", channel_id);
    else cJSON_AddNullToObject(json, "channel_id");
    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (!body) return -1;

    discord_http_response_t *response = discord_http_request_ex(client, "PATCH", endpoint, body, reason);
    free(body);

    int result = (response != NULL) ? 0 : -1;
    discord_http_response_free(response);
    return result;
}

/* Fetch a guild member */
discord_member_t *discord_get_guild_member(discord_client_t *client, const char *guild_id, const char *user_id) {
    if (!client || !guild_id || !user_id) return NULL;

    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/members/%s", guild_id, user_id);

    discord_http_response_t *response = discord_http_request(client, "GET", endpoint, NULL);
    if (!response || !response->data) {
        discord_http_response_free(response);
        return NULL;
    }

    cJSON *json = cJSON_Parse(response->data);
    discord_member_t *member = NULL;
    if (json) {
        member = discord_parse_member(json);
        cJSON_Delete(json);
    }
    discord_http_response_free(response);
    return member;
}

/* Parse a single ban object: { "reason": "...", "user": { ... } } */
static discord_guild_ban_t *discord_parse_guild_ban(cJSON *json) {
    if (!json) return NULL;
    discord_guild_ban_t *ban = (discord_guild_ban_t *)calloc(1, sizeof(discord_guild_ban_t));
    if (!ban) return NULL;

    cJSON *reason = cJSON_GetObjectItem(json, "reason");
    if (reason && cJSON_IsString(reason)) ban->reason = discord_strdup(reason->valuestring);

    cJSON *user = cJSON_GetObjectItem(json, "user");
    if (user) ban->user = discord_parse_user(user);

    return ban;
}

/* Get guild bans list */
discord_guild_ban_t **discord_get_guild_bans(discord_client_t *client, const char *guild_id, int *out_count) {
    if (!client || !guild_id || !out_count) return NULL;
    *out_count = 0;

    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/bans", guild_id);

    discord_http_response_t *response = discord_http_request(client, "GET", endpoint, NULL);
    if (!response || !response->data) {
        discord_http_response_free(response);
        return NULL;
    }

    cJSON *json = cJSON_Parse(response->data);
    discord_guild_ban_t **list = NULL;

    if (json && cJSON_IsArray(json)) {
        int n = cJSON_GetArraySize(json);
        if (n > 0) {
            list = (discord_guild_ban_t **)calloc(n, sizeof(discord_guild_ban_t *));
            for (int i = 0; i < n; i++) {
                cJSON *item = cJSON_GetArrayItem(json, i);
                list[i] = discord_parse_guild_ban(item);
            }
            *out_count = n;
        }
    }

    if (json) cJSON_Delete(json);
    discord_http_response_free(response);
    return list;
}

/* Cleanup for ban objects */
void discord_guild_ban_destroy(discord_guild_ban_t *ban) {
    if (!ban) return;
    if (ban->user) discord_user_destroy(ban->user);
    free(ban->reason);
    free(ban);
}

void discord_guild_ban_list_destroy(discord_guild_ban_t **bans, int count) {
    if (!bans) return;
    for (int i = 0; i < count; i++) {
        discord_guild_ban_destroy(bans[i]);
    }
    free(bans);
}

/* ============================================================================
 * Roles
 * ============================================================================ */

/* Create role. Returns created role_id via out_role_id if non-NULL. */
int discord_create_role(discord_client_t *client, const char *guild_id,
                        const char *name, const char *permissions, int color,
                        bool hoist, bool mentionable, const char *reason,
                        char **out_role_id) {
    if (!client || !guild_id || !name) return -1;

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "name", name);
    if (permissions) cJSON_AddStringToObject(json, "permissions", permissions); /* string of bitset */
    if (color >= 0) cJSON_AddNumberToObject(json, "color", color);
    cJSON_AddBoolToObject(json, "hoist", hoist);
    cJSON_AddBoolToObject(json, "mentionable", mentionable);

    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (!body) return -1;

    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/roles", guild_id);

    discord_http_response_t *resp = discord_http_request_ex(client, "POST", endpoint, body, reason);
    free(body);
    if (!resp) return -1;

    int result = 0;
    if (out_role_id) {
        cJSON *rj = cJSON_Parse(resp->data);
        if (rj) {
            cJSON *id = cJSON_GetObjectItem(rj, "id");
            if (id && cJSON_IsString(id)) {
                *out_role_id = discord_strdup(id->valuestring);
            } else {
                result = -1;
            }
            cJSON_Delete(rj);
        } else {
            result = -1;
        }
    }

    discord_http_response_free(resp);
    return result;
}

/* Modify role. You can selectively update fields:
   - If name/permissions is NULL, it's omitted.
   - color: pass <0 to omit.
   - hoist_set/mentionable_set control whether the boolean field is sent. */
int discord_modify_role(discord_client_t *client, const char *guild_id, const char *role_id,
                        const char *name, const char *permissions, int color,
                        bool hoist_set, bool hoist, bool mentionable_set, bool mentionable,
                        const char *reason) {
    if (!client || !guild_id || !role_id) return -1;

    cJSON *json = cJSON_CreateObject();
    if (name) cJSON_AddStringToObject(json, "name", name);
    if (permissions) cJSON_AddStringToObject(json, "permissions", permissions);
    if (color >= 0) cJSON_AddNumberToObject(json, "color", color);
    if (hoist_set) cJSON_AddBoolToObject(json, "hoist", hoist);
    if (mentionable_set) cJSON_AddBoolToObject(json, "mentionable", mentionable);

    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (!body) return -1;

    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/roles/%s", guild_id, role_id);

    discord_http_response_t *resp = discord_http_request_ex(client, "PATCH", endpoint, body, reason);
    free(body);
    int result = (resp != NULL) ? 0 : -1;
    discord_http_response_free(resp);
    return result;
}

/* Delete role */
int discord_delete_role(discord_client_t *client, const char *guild_id, const char *role_id, const char *reason) {
    if (!client || !guild_id || !role_id) return -1;

    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/roles/%s", guild_id, role_id);

    discord_http_response_t *resp = discord_http_request_ex(client, "DELETE", endpoint, NULL, reason);
    int result = (resp != NULL) ? 0 : -1;
    discord_http_response_free(resp);
    return result;
}

/* ============================================================================
 * Channel Permission Overwrites
 * ============================================================================ */

/* type: 0 = role, 1 = member; allow/deny are 64-bit bitfields passed as strings by API */
int discord_channel_set_permission_overwrite(discord_client_t *client, const char *channel_id,
                                             const char *overwrite_id, int type, uint64_t allow, uint64_t deny,
                                             const char *reason) {
    if (!client || !channel_id || !overwrite_id || (type != 0 && type != 1)) return -1;

    /* Convert allow/deny to decimal strings as required by Discord API */
    char allow_str[32], deny_str[32];
    snprintf(allow_str, sizeof(allow_str), "%llu", (unsigned long long)allow);
    snprintf(deny_str, sizeof(deny_str), "%llu", (unsigned long long)deny);

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "allow", allow_str);
    cJSON_AddStringToObject(json, "deny",  deny_str);
    cJSON_AddNumberToObject(json, "type", type);
    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (!body) return -1;

    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/permissions/%s", channel_id, overwrite_id);

    discord_http_response_t *resp = discord_http_request_ex(client, "PUT", endpoint, body, reason);
    free(body);
    int result = (resp != NULL) ? 0 : -1;
    discord_http_response_free(resp);
    return result;
}

int discord_channel_delete_permission_overwrite(discord_client_t *client, const char *channel_id,
                                                const char *overwrite_id, const char *reason) {
    if (!client || !channel_id || !overwrite_id) return -1;

    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/permissions/%s", channel_id, overwrite_id);

    discord_http_response_t *resp = discord_http_request_ex(client, "DELETE", endpoint, NULL, reason);
    int result = (resp != NULL) ? 0 : -1;
    discord_http_response_free(resp);
    return result;
}

/* Convenience: lock/unlock text channel for @everyone (role id == guild_id).
   NOTE: This overwrites existing @everyone overwrite and may clobber other flags.
   Prefer using discord_channel_set_permission_overwrite explicitly if you need to merge bits. */
int discord_lock_text_channel(discord_client_t *client, const char *guild_id, const char *channel_id, const char *reason) {
    if (!client || !guild_id || !channel_id) return -1;
    /* Deny SEND_MESSAGES and SEND_MESSAGES_IN_THREADS */
    uint64_t deny = DISCORD_PERM_SEND_MESSAGES | DISCORD_PERM_SEND_MESSAGES_IN_THREADS;
    return discord_channel_set_permission_overwrite(client, channel_id, guild_id, 0, 0ULL, deny, reason);
}

int discord_unlock_text_channel(discord_client_t *client, const char *guild_id, const char *channel_id, const char *reason) {
    if (!client || !guild_id || !channel_id) return -1;
    /* Removes the @everyone overwrite entirely (safer than guessing merged bits) */
    return discord_channel_delete_permission_overwrite(client, channel_id, guild_id, reason);
}

/* ============================================================================
 * Prune & Soft-ban
 * ============================================================================ */

/* GET prune count preview. include_role_ids is optional (can be NULL). */
int discord_get_prune_count(discord_client_t *client, const char *guild_id, int days,
                            const char **include_role_ids, int include_roles_count, int *out_count) {
    if (!client || !guild_id || days < 1 || !out_count) return -1;

    char endpoint[1024];
    if (include_role_ids && include_roles_count > 0) {
        /* Build comma-separated role list */
        char roles_buf[768] = {0};
        size_t pos = 0;
        for (int i = 0; i < include_roles_count; i++) {
            const char *rid = include_role_ids[i];
            if (!rid) continue;
            size_t rlen = strlen(rid);
            if (pos + rlen + 2 >= sizeof(roles_buf)) break;
            if (i > 0) roles_buf[pos++] = ',';
            memcpy(roles_buf + pos, rid, rlen);
            pos += rlen;
        }
        snprintf(endpoint, sizeof(endpoint), "/guilds/%s/prune?days=%d&include_roles=%s", guild_id, days, roles_buf);
    } else {
        snprintf(endpoint, sizeof(endpoint), "/guilds/%s/prune?days=%d", guild_id, days);
    }

    discord_http_response_t *resp = discord_http_request(client, "GET", endpoint, NULL);
    if (!resp || !resp->data) { discord_http_response_free(resp); return -1; }

    int result = -1;
    cJSON *j = cJSON_Parse(resp->data);
    if (j) {
        cJSON *pruned = cJSON_GetObjectItem(j, "pruned");
        if (pruned && cJSON_IsNumber(pruned)) {
            *out_count = pruned->valueint;
            result = 0;
        }
        cJSON_Delete(j);
    }
    discord_http_response_free(resp);
    return result;
}

/* POST begin prune, optionally returning count if compute_prune_count true */
int discord_begin_prune(discord_client_t *client, const char *guild_id, int days,
                        const char **include_role_ids, int include_roles_count,
                        bool compute_prune_count, const char *reason, int *out_count) {
    if (!client || !guild_id || days < 1) return -1;

    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "days", days);
    if (include_role_ids && include_roles_count > 0) {
        cJSON *arr = cJSON_CreateArray();
        for (int i = 0; i < include_roles_count; i++) {
            if (include_role_ids[i]) cJSON_AddItemToArray(arr, cJSON_CreateString(include_role_ids[i]));
        }
        cJSON_AddItemToObject(json, "include_roles", arr);
    }
    cJSON_AddBoolToObject(json, "compute_prune_count", compute_prune_count);

    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (!body) return -1;

    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/guilds/%s/prune", guild_id);

    discord_http_response_t *resp = discord_http_request_ex(client, "POST", endpoint, body, reason);
    free(body);
    if (!resp) return -1;

    int result = 0;
    if (compute_prune_count && out_count) {
        cJSON *j = cJSON_Parse(resp->data);
        if (j) {
            cJSON *pruned = cJSON_GetObjectItem(j, "pruned");
            if (pruned && cJSON_IsNumber(pruned)) {
                *out_count = pruned->valueint;
            } else {
                result = -1;
            }
            cJSON_Delete(j);
        } else {
            result = -1;
        }
    }

    discord_http_response_free(resp);
    return result;
}

/* Soft-ban: ban (deleting N seconds of messages) then unban to kick and purge messages */
int discord_softban_member(discord_client_t *client, const char *guild_id, const char *user_id,
                           int delete_message_seconds, const char *reason) {
    if (!client || !guild_id || !user_id) return -1;
    if (discord_ban_member(client, guild_id, user_id, delete_message_seconds, reason) != 0) return -1;
    return discord_unban_member(client, guild_id, user_id, "Softban unban");
}

/* ============================================================================
 * Thread Moderation
 * ============================================================================ */

static int discord_patch_thread_flags(discord_client_t *client, const char *thread_id,
                                      const char *key, cJSON *value, const char *reason) {
    if (!client || !thread_id || !key || !value) return -1;
    cJSON *json = cJSON_CreateObject();
    cJSON_AddItemToObject(json, key, value);
    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (!body) return -1;

    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s", thread_id);
    discord_http_response_t *resp = discord_http_request_ex(client, "PATCH", endpoint, body, reason);
    free(body);
    int result = (resp != NULL) ? 0 : -1;
    discord_http_response_free(resp);
    return result;
}

int discord_thread_set_locked(discord_client_t *client, const char *thread_id, bool locked, const char *reason) {
    return discord_patch_thread_flags(client, thread_id, "locked", cJSON_CreateBool(locked), reason);
}

int discord_thread_set_archived(discord_client_t *client, const char *thread_id, bool archived, const char *reason) {
    return discord_patch_thread_flags(client, thread_id, "archived", cJSON_CreateBool(archived), reason);
}

/* minutes: allowed values typically 60, 1440, 4320, 10080 (server config dependent) */
int discord_thread_set_auto_archive_duration(discord_client_t *client, const char *thread_id, int minutes, const char *reason) {
    cJSON *num = cJSON_CreateNumber(minutes);
    return discord_patch_thread_flags(client, thread_id, "auto_archive_duration", num, reason);
}

int discord_thread_join(discord_client_t *client, const char *thread_id) {
    if (!client || !thread_id) return -1;
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/thread-members/@me", thread_id);
    discord_http_response_t *resp = discord_http_request(client, "PUT", endpoint, NULL);
    int result = (resp != NULL) ? 0 : -1;
    discord_http_response_free(resp);
    return result;
}

int discord_thread_leave(discord_client_t *client, const char *thread_id) {
    if (!client || !thread_id) return -1;
    char endpoint[256];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/thread-members/@me", thread_id);
    discord_http_response_t *resp = discord_http_request(client, "DELETE", endpoint, NULL);
    int result = (resp != NULL) ? 0 : -1;
    discord_http_response_free(resp);
    return result;
}

int discord_thread_add_member(discord_client_t *client, const char *thread_id, const char *user_id) {
    if (!client || !thread_id || !user_id) return -1;
    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/thread-members/%s", thread_id, user_id);
    discord_http_response_t *resp = discord_http_request(client, "PUT", endpoint, NULL);
    int result = (resp != NULL) ? 0 : -1;
    discord_http_response_free(resp);
    return result;
}

int discord_thread_remove_member(discord_client_t *client, const char *thread_id, const char *user_id) {
    if (!client || !thread_id || !user_id) return -1;
    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "/channels/%s/thread-members/%s", thread_id, user_id);
    discord_http_response_t *resp = discord_http_request(client, "DELETE", endpoint, NULL);
    int result = (resp != NULL) ? 0 : -1;
    discord_http_response_free(resp);
    return result;
}

/* ============================================================================
 * Memory Cleanup Functions
 * ============================================================================ */

/* Destroy message */
void discord_message_destroy(discord_message_t *message) {
    if (!message) return;
    
    free(message->id);
    free(message->channel_id);
    free(message->guild_id);
    free(message->content);
    free(message->timestamp);
    
    if (message->author) {
        discord_user_destroy(message->author);
    }
    
    if (message->member) {
        discord_member_destroy(message->member);
    }
    
    if (message->mentions) {
        for (int i = 0; i < message->mention_count; i++) {
            discord_user_destroy(message->mentions[i]);
        }
        free(message->mentions);
    }
    
    if (message->embeds) {
        for (int i = 0; i < message->embed_count; i++) {
            discord_embed_destroy(message->embeds[i]);
        }
        free(message->embeds);
    }
    
    free(message);
}

/* Destroy user */
void discord_user_destroy(discord_user_t *user) {
    if (!user) return;
    
    free(user->id);
    free(user->username);
    free(user->discriminator);
    free(user->avatar);
    
    free(user);
}

/* Destroy channel */
void discord_channel_destroy(discord_channel_t *channel) {
    if (!channel) return;
    
    free(channel->id);
    free(channel->guild_id);
    free(channel->name);
    free(channel->topic);
    
    free(channel);
}

/* Destroy guild */
void discord_guild_destroy(discord_guild_t *guild) {
    if (!guild) return;
    
    free(guild->id);
    free(guild->name);
    free(guild->icon);
    free(guild->owner_id);
    
    free(guild);
}

/* Destroy member */
void discord_member_destroy(discord_member_t *member) {
    if (!member) return;
    
    if (member->user) {
        discord_user_destroy(member->user);
    }
    
    free(member->nick);
    free(member->joined_at);
    
    if (member->roles) {
        for (int i = 0; i < member->role_count; i++) {
            free(member->roles[i]);
        }
        free(member->roles);
    }
    
    free(member);
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/* Get ISO 8601 timestamp for now + offset seconds (UTC) */
char *discord_timestamp_offset_seconds(int seconds) {
    time_t now = time(NULL);
    now += seconds;
    struct tm *tm_info = gmtime(&now);

    char *timestamp = (char *)malloc(32);
    if (!timestamp) return NULL;

    /* Milliseconds fixed at .000; Discord accepts this format */
    strftime(timestamp, 32, "%Y-%m-%dT%H:%M:%S.000Z", tm_info);
    return timestamp;
}

/* Get current timestamp in ISO 8601 format */
char *discord_timestamp_now(void) {
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    
    char *timestamp = (char *)malloc(32);
    if (!timestamp) return NULL;
    
    strftime(timestamp, 32, "%Y-%m-%dT%H:%M:%S.000Z", tm_info);
    return timestamp;
}

#endif /* DISCORD_IMPLEMENTATION */
