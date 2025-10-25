// auth.c
// Build:
//   Windows: gcc -O2 -o auth_bot.exe auth.c -lcurl -lcjson -lwebsockets -lws2_32
//   Linux/macOS: gcc -O2 -o auth_bot auth.c -lcurl -lcjson -lwebsockets -lpthread
// Run:
//   Windows:
//     $env:BOT_TOKEN="YOUR_TOKEN"
//     .\auth_bot.exe
//   Linux:
//     export BOT_TOKEN="YOUR_TOKEN"
//     ./auth_bot

#define DISCORD_IMPLEMENTATION
#define JSON_IMPLEMENTATION

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>

#include "discord.h"
#include "json_builder.h"

// ====================== Config ======================
static const char *DB_PATH = "auth_db.json";      // database file
static const int LOGIN_GRACE_SECONDS = 5 * 60;    // 5 minutes
// Optional: you can set an AUTH CHANNEL ID to funnel public instructions
// static const char *AUTH_CHANNEL_ID = "123456789012345678";

// ====================== Utility: FNV-1a Hash ======================
// Simple FNV-1a 32-bit hash (for OTP) and 64-bit variant (for password hash demo)
static uint32_t fnv1a32(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}
static uint64_t fnv1a64(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 1099511628211ull;
    }
    return h;
}

static uint32_t otp_from_username_password(const char *username, const char *password) {
    // OTP = FNV1a32(username + ":" + password)
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s:%s", username ? username : "", password ? password : "");
    uint32_t v = fnv1a32(buf, strlen(buf));
    // allow full 0..UINT32_MAX range; you can special-case 0 if desired
    return v;
}
static uint64_t hash_password(const char *user_id, const char *password) {
    // demo-only password hash (FNV-1a over salt=user_id)
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s:%s", user_id ? user_id : "", password ? password : "");
    return fnv1a64(buf, strlen(buf));
}

// ====================== Auth DB Structures ======================
typedef struct {
    char *user_id;        // Discord user id
    char *guild_id;       // Last guild seen/used for enforcement
    char *username;       // Discord username snapshot
    uint64_t password_hash;
    uint32_t otp_code;
    bool logged_in;
    time_t deadline;      // >0 if must login before this epoch or be kicked
} AuthRecord;

typedef struct {
    AuthRecord *items;
    size_t count;
    size_t capacity;
} AuthDB;

// ====================== Globals ======================
typedef struct {
    discord_client_t *client;
    AuthDB db;
    bool db_loaded_ok;
    bool running;
#ifdef _WIN32
    CRITICAL_SECTION db_mutex;
#else
    pthread_mutex_t db_mutex;
#endif
} App;

static App g_app;

// ====================== Mutex wrappers ======================
static void app_mutex_init() {
#ifdef _WIN32
    InitializeCriticalSection(&g_app.db_mutex);
#else
    pthread_mutex_init(&g_app.db_mutex, NULL);
#endif
}
static void app_mutex_destroy() {
#ifdef _WIN32
    DeleteCriticalSection(&g_app.db_mutex);
#else
    pthread_mutex_destroy(&g_app.db_mutex);
#endif
}
static void app_lock() {
#ifdef _WIN32
    EnterCriticalSection(&g_app.db_mutex);
#else
    pthread_mutex_lock(&g_app.db_mutex);
#endif
}
static void app_unlock() {
#ifdef _WIN32
    LeaveCriticalSection(&g_app.db_mutex);
#else
    pthread_mutex_unlock(&g_app.db_mutex);
#endif
}

// ====================== DB Helpers ======================
static void authdb_init(AuthDB *db) {
    db->items = NULL;
    db->count = 0;
    db->capacity = 0;
}
static void authdb_free(AuthDB *db) {
    if (!db) return;
    for (size_t i = 0; i < db->count; ++i) {
        free(db->items[i].user_id);
        free(db->items[i].guild_id);
        free(db->items[i].username);
    }
    free(db->items);
    db->items = NULL;
    db->count = db->capacity = 0;
}
static AuthRecord *authdb_find(AuthDB *db, const char *user_id) {
    if (!db || !user_id) return NULL;
    for (size_t i = 0; i < db->count; ++i) {
        if (db->items[i].user_id && strcmp(db->items[i].user_id, user_id) == 0) {
            return &db->items[i];
        }
    }
    return NULL;
}
static AuthRecord *authdb_find_or_add(AuthDB *db, const char *user_id) {
    AuthRecord *rec = authdb_find(db, user_id);
    if (rec) return rec;
    if (db->count == db->capacity) {
        size_t newcap = db->capacity == 0 ? 16 : db->capacity * 2;
        AuthRecord *n = (AuthRecord *)realloc(db->items, newcap * sizeof(AuthRecord));
        if (!n) return NULL;
        db->items = n;
        db->capacity = newcap;
    }
    rec = &db->items[db->count++];
    memset(rec, 0, sizeof(*rec));
    rec->user_id = strdup(user_id);
    rec->logged_in = false;
    rec->deadline = 0;
    rec->password_hash = 0;
    rec->otp_code = 0;
    return rec;
}

// ====================== File IO (Load/Save with json_builder.h) ======================

static bool authdb_save(AuthDB *db, const char *path) {
    char *buf = (char *)malloc(1<<20); // 1MB buffer
    if (!buf) return false;

    json_builder_t jb;
    if (json_builder_init(&jb, buf, 1<<20) != JSON_ERROR_NONE) {
        free(buf);
        return false;
    }
    json_builder_enable_pretty_print(&jb, 2);

    if (json_builder_object_begin(&jb) != JSON_ERROR_NONE) {
        json_builder_free(&jb);
        free(buf);
        return false;
    }
    
    json_builder_key(&jb, "users");
    json_builder_array_begin(&jb);
    
    for (size_t i = 0; i < db->count; ++i) {
        AuthRecord *r = &db->items[i];
        json_builder_object_begin(&jb);

        json_builder_key(&jb, "user_id");
        json_builder_string(&jb, r->user_id ? r->user_id : "");
        
        json_builder_key(&jb, "guild_id");
        json_builder_string(&jb, r->guild_id ? r->guild_id : "");
        
        json_builder_key(&jb, "username");
        json_builder_string(&jb, r->username ? r->username : "");
        
        json_builder_key(&jb, "password_hash");
        char ph[32];
        snprintf(ph, sizeof(ph), "%llu", (unsigned long long)r->password_hash);
        json_builder_string(&jb, ph);
        
        json_builder_key(&jb, "otp_code");
        char oc[32];
        snprintf(oc, sizeof(oc), "%u", r->otp_code);
        json_builder_string(&jb, oc);
        
        json_builder_key(&jb, "logged_in");
        json_builder_bool(&jb, r->logged_in);
        
        json_builder_key(&jb, "deadline");
        char dl[32];
        snprintf(dl, sizeof(dl), "%lld", (long long)r->deadline);
        json_builder_string(&jb, dl);

        json_builder_object_end(&jb);
    }
    
    json_builder_array_end(&jb);
    json_builder_object_end(&jb);

    const char *json_str = json_builder_get_string(&jb);
    if (!json_str) {
        json_builder_free(&jb);
        free(buf);
        return false;
    }

    FILE *f = fopen(path, "wt");
    if (!f) {
        json_builder_free(&jb);
        free(buf);
        return false;
    }
    
    fprintf(f, "%s", json_str);
    fclose(f);

    json_builder_free(&jb);
    free(buf);
    
    return true;
}

static bool authdb_load(AuthDB *db, const char *path) {
    FILE *f = fopen(path, "rt");
    if (!f) {
        fprintf(stderr, "[auth] No database file at %s (OK for first run)\n", path);
        return true;
    }
    
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) {
        fprintf(stderr, "[auth] Empty database file\n");
        fclose(f);
        return true;
    }

    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return false;
    }
    
    size_t read_bytes = fread(buf, 1, (size_t)sz, f);
    buf[read_bytes] = 0;
    fclose(f);

    // First pass: count tokens
    json_parser_t parser;
    json_parser_init(&parser);
    int token_count = json_parse(&parser, buf, read_bytes, NULL, 0);
    
    if (token_count < 0) {
        fprintf(stderr, "[auth] JSON parse error: %d at position %u\n", token_count, parser.pos);
        if (parser.pos < read_bytes && parser.pos > 0) {
            size_t context_start = parser.pos > 20 ? parser.pos - 20 : 0;
            size_t context_len = (parser.pos - context_start + 20) < (read_bytes - context_start) ? 
                                 (parser.pos - context_start + 20) : (read_bytes - context_start);
            fprintf(stderr, "[auth] Context around position %u: ", parser.pos);
            for (size_t i = 0; i < context_len && (context_start + i) < read_bytes; i++) {
                char c = buf[context_start + i];
                if (i == (parser.pos - context_start)) fprintf(stderr, ">>>");
                if (c == '\n') fprintf(stderr, "\\n");
                else if (c == '\r') fprintf(stderr, "\\r");
                else if (c == '\t') fprintf(stderr, "\\t");
                else fprintf(stderr, "%c", c);
                if (i == (parser.pos - context_start)) fprintf(stderr, "<<<");
            }
            fprintf(stderr, "\n");
            fprintf(stderr, "[auth] Character at error position: 0x%02x ('%c')\n", 
                    (unsigned char)buf[parser.pos], 
                    isprint((unsigned char)buf[parser.pos]) ? buf[parser.pos] : '?');
        }
        free(buf);
        return false;
    }

    // Allocate tokens with some extra buffer (parser might need more on second pass)
    size_t token_alloc = (size_t)token_count + 10; // Add safety margin
    json_token_t *tokens = (json_token_t *)malloc(token_alloc * sizeof(json_token_t));
    if (!tokens) {
        fprintf(stderr, "[auth] Failed to allocate %zu tokens\n", token_alloc);
        free(buf);
        return false;
    }
    
    fprintf(stderr, "[auth] Allocated %zu tokens (counted %d)\n", token_alloc, token_count);

    // Second pass: parse
    json_parser_init(&parser);
    int n = json_parse(&parser, buf, read_bytes, tokens, (unsigned int)token_alloc);
    
    fprintf(stderr, "[auth] Second pass result: %d, parser pos: %u\n", n, parser.pos);
    
    if (n <= 0) {
        fprintf(stderr, "[auth] JSON parse failed on second pass: %d at position %u\n", n, parser.pos);
        if (parser.pos < read_bytes) {
            fprintf(stderr, "[auth] Character at error: 0x%02x ('%c')\n", 
                    (unsigned char)buf[parser.pos],
                    isprint((unsigned char)buf[parser.pos]) ? buf[parser.pos] : '?');
        }
        free(tokens);
        free(buf);
        return false;
    }

    fprintf(stderr, "[auth] Parsed %d tokens from JSON\n", n);

    // Validate root is object
    if (n < 1 || tokens[0].type != JSON_OBJECT) {
        fprintf(stderr, "[auth] Root is not an object (type=%d)\n", tokens[0].type);
        free(tokens);
        free(buf);
        return false;
    }

    // Find "users" key in root object
    // Object structure: obj_idx points to the object token
    // Following tokens are: key1, val1, key2, val2, ...
    int root_pairs = tokens[0].size;
    fprintf(stderr, "[auth] Root object has %d key-value pairs\n", root_pairs);
    
    int users_idx = -1;
    int i = 1; // Start after root object token
    
    for (int p = 0; p < root_pairs && i < n; ++p) {
        // Current token should be a key (string)
        if (tokens[i].type != JSON_STRING) {
            fprintf(stderr, "[auth] Expected string key at token %d\n", i);
            break;
        }
        
        // Check if this key is "users"
        int key_len = tokens[i].end - tokens[i].start;
        if (key_len == 5 && strncmp(buf + tokens[i].start, "users", 5) == 0) {
            // Next token is the value
            users_idx = i + 1;
            fprintf(stderr, "[auth] Found 'users' key at token %d, value at %d\n", i, users_idx);
            break;
        }
        
        // Skip to next key-value pair
        // Move past the key
        i++;
        // Skip the value (and its entire subtree)
        if (i >= n) break;
        
        // Skip value subtree
        int value_end = tokens[i].end;
        i++; // move past value token itself
        // Skip all tokens that are part of this value's subtree
        while (i < n && tokens[i].start < value_end) {
            i++;
        }
    }
    
    if (users_idx < 0 || users_idx >= n) {
        fprintf(stderr, "[auth] No 'users' key found\n");
        free(tokens);
        free(buf);
        return true; // Empty DB is OK
    }
    
    if (tokens[users_idx].type != JSON_ARRAY) {
        fprintf(stderr, "[auth] 'users' is not an array (type=%d)\n", tokens[users_idx].type);
        free(tokens);
        free(buf);
        return true;
    }

    int arr_size = tokens[users_idx].size;
    fprintf(stderr, "[auth] Loading %d users from array...\n", arr_size);
    
    if (arr_size == 0) {
        free(tokens);
        free(buf);
        return true;
    }

    // Process each user object in the array
    int elem_idx = users_idx + 1; // First element after array token
    int loaded = 0;

    for (int a = 0; a < arr_size && elem_idx < n; ++a) {
        if (tokens[elem_idx].type != JSON_OBJECT) {
            fprintf(stderr, "[auth] Array element %d is not an object (type=%d)\n", a, tokens[elem_idx].type);
            // Skip this element
            int elem_end = tokens[elem_idx].end;
            elem_idx++;
            while (elem_idx < n && tokens[elem_idx].start < elem_end) {
                elem_idx++;
            }
            continue;
        }

        int obj_idx = elem_idx;
        int obj_pairs = tokens[obj_idx].size;
        
        // Parse user object fields
        char user_id[64] = {0};
        char guild_id[64] = {0};
        char username[128] = {0};
        char password_hash_str[64] = {0};
        char otp_code_str[64] = {0};
        char logged_in_str[16] = {0};
        char deadline_str[64] = {0};

        int field_idx = obj_idx + 1;
        for (int fp = 0; fp < obj_pairs && field_idx < n; ++fp) {
            // Get key name
            if (tokens[field_idx].type != JSON_STRING) break;
            
            int key_len = tokens[field_idx].end - tokens[field_idx].start;
            const char *key_start = buf + tokens[field_idx].start;
            int val_idx = field_idx + 1;
            
            if (val_idx >= n) break;
            
            // Extract value into appropriate field
            int val_len = tokens[val_idx].end - tokens[val_idx].start;
            
            if (key_len == 7 && strncmp(key_start, "user_id", 7) == 0) {
                if (val_len < (int)sizeof(user_id)) {
                    memcpy(user_id, buf + tokens[val_idx].start, val_len);
                    user_id[val_len] = 0;
                }
            } else if (key_len == 8 && strncmp(key_start, "guild_id", 8) == 0) {
                if (val_len < (int)sizeof(guild_id)) {
                    memcpy(guild_id, buf + tokens[val_idx].start, val_len);
                    guild_id[val_len] = 0;
                }
            } else if (key_len == 8 && strncmp(key_start, "username", 8) == 0) {
                if (val_len < (int)sizeof(username)) {
                    memcpy(username, buf + tokens[val_idx].start, val_len);
                    username[val_len] = 0;
                }
            } else if (key_len == 13 && strncmp(key_start, "password_hash", 13) == 0) {
                if (val_len < (int)sizeof(password_hash_str)) {
                    memcpy(password_hash_str, buf + tokens[val_idx].start, val_len);
                    password_hash_str[val_len] = 0;
                }
            } else if (key_len == 8 && strncmp(key_start, "otp_code", 8) == 0) {
                if (val_len < (int)sizeof(otp_code_str)) {
                    memcpy(otp_code_str, buf + tokens[val_idx].start, val_len);
                    otp_code_str[val_len] = 0;
                }
            } else if (key_len == 9 && strncmp(key_start, "logged_in", 9) == 0) {
                if (val_len < (int)sizeof(logged_in_str)) {
                    memcpy(logged_in_str, buf + tokens[val_idx].start, val_len);
                    logged_in_str[val_len] = 0;
                }
            } else if (key_len == 8 && strncmp(key_start, "deadline", 8) == 0) {
                if (val_len < (int)sizeof(deadline_str)) {
                    memcpy(deadline_str, buf + tokens[val_idx].start, val_len);
                    deadline_str[val_len] = 0;
                }
            }
            
            // Move to next key-value pair
            field_idx = val_idx + 1;
            int val_end = tokens[val_idx].end;
            while (field_idx < n && tokens[field_idx].start < val_end) {
                field_idx++;
            }
        }

        // Create record if we have a user_id
        if (user_id[0] != '\0') {
            AuthRecord *r = authdb_find_or_add(db, user_id);
            if (r) {
                if (guild_id[0] != '\0') {
                    free(r->guild_id);
                    r->guild_id = strdup(guild_id);
                }
                if (username[0] != '\0') {
                    free(r->username);
                    r->username = strdup(username);
                }
                
                r->password_hash = strtoull(password_hash_str, NULL, 10);
                r->otp_code = (uint32_t)strtoul(otp_code_str, NULL, 10);
                r->logged_in = (strcmp(logged_in_str, "true") == 0);
                r->deadline = (time_t)strtoll(deadline_str, NULL, 10);
                
                loaded++;
            }
        }

        // Move to next array element
        elem_idx = field_idx;
    }

    fprintf(stderr, "[auth] Successfully loaded %d users from %s\n", loaded, path);

    free(tokens);
    free(buf);
    return true;
}

// ====================== Business Logic ======================
static void ensure_deadline(AuthRecord *r) {
    if (!r) return;
    if (r->deadline == 0) {
        r->deadline = time(NULL) + LOGIN_GRACE_SECONDS;
    }
}

static void clear_deadline(AuthRecord *r) {
    if (!r) return;
    r->deadline = 0;
}

// When an unauthenticated message arrives in a guild: delete it and guide user
static void handle_unauthenticated_message(discord_client_t *client, discord_message_t *msg, AuthRecord *r) {
    // Start 5-min countdown if not already started
    ensure_deadline(r);

    // Delete offending message if we can
    if (msg->channel_id && msg->id) {
        discord_delete_message(client, msg->channel_id, msg->id);
    }

    // Reply in the same channel to instruct (avoid posting OTP/password publicly)
    char info[512];
    snprintf(info, sizeof(info),
        "Hi <@%s>, you must authenticate.\n"
        "1) DM me: !register <password> (first time only)\n"
        "2) DM me: !login <otp>\n"
        "Get your OTP via !otp (in DM). You have 5 minutes from your first message.",
        r->user_id
    );
    if (msg->channel_id) {
        discord_channel_t *channel = discord_create_dm(client, msg->author->id);
        discord_create_message(client, channel->id, info);
        discord_channel_destroy(channel);
    }
}

// ====================== Kicker Thread ======================
#ifdef _WIN32
static DWORD WINAPI kicker_thread_proc(LPVOID arg)
#else
static void *kicker_thread_proc(void *arg)
#endif
{
    (void)arg;
    while (g_app.running) {
        time_t now = time(NULL);

        app_lock();
        for (size_t i = 0; i < g_app.db.count; ++i) {
            AuthRecord *r = &g_app.db.items[i];
            if (!r->logged_in && r->deadline > 0 && now >= r->deadline) {
                // Need to kick if we have a guild_id
                if (r->guild_id && r->user_id) {
                    fprintf(stderr, "[auth] Kicking user %s from guild %s (deadline expired)\n", r->user_id, r->guild_id);
                    discord_kick_member(g_app.client, r->guild_id, r->user_id, "Failed to authenticate within 5 minutes");
                }
                // Reset deadline to avoid repeated kicks
                r->deadline = 0;
            }
        }
        if (g_app.db_loaded_ok) {
            (void)authdb_save(&g_app.db, DB_PATH);
        }
        app_unlock();

#ifdef _WIN32
        Sleep(5000);
#else
        usleep(5000 * 1000);
#endif
    }
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

// ====================== Command Handling ======================
static void cmd_register(discord_client_t *client, discord_message_t *message, const char *password) {
    if (!message->author || !message->author->id) return;
    if (!password || !*password) {
        if (message->channel_id) {
            discord_channel_t *channel = discord_create_dm(client, message->author->id);
            discord_create_message(client, channel->id, "Usage: !register <password>");
            discord_channel_destroy(channel);
        }
        return;
    }
    const char *user_id = message->author->id;
    const char *username = message->author->username ? message->author->username : "user";

    app_lock();
    AuthRecord *rec = authdb_find_or_add(&g_app.db, user_id);
    if (rec) {
        free(rec->username); rec->username = strdup(username);
        rec->password_hash = hash_password(user_id, password);
        rec->otp_code = otp_from_username_password(username, password);
        rec->logged_in = false; // need to explicitly login after register
        clear_deadline(rec);    // no deadline until they speak or we enforce immediately

        authdb_save(&g_app.db, DB_PATH);
    }
    app_unlock();

    char out[256];
    snprintf(out, sizeof(out), "Registered. Your OTP is: %u\nUse: !login %u", rec ? rec->otp_code : 0, rec ? rec->otp_code : 0);
    if (message->channel_id) {
        discord_channel_t *channel = discord_create_dm(client, message->author->id);
        discord_create_message(client, channel->id, out);
        discord_channel_destroy(channel);
    }
}

static void cmd_otp(discord_client_t *client, discord_message_t *message) {
    if (!message->author || !message->author->id) return;
    const char *user_id = message->author->id;

    app_lock();
    AuthRecord *rec = authdb_find(&g_app.db, user_id);
    app_unlock();

    if (!rec || rec->otp_code == 0) {
        if (message->channel_id) {
            discord_channel_t *channel = discord_create_dm(client, message->author->id);
            discord_create_message(client, channel->id, "No OTP set. Use !register <password> first.");
            discord_channel_destroy(channel);
        }
        return;
    }
    char out[128];
    snprintf(out, sizeof(out), "Your OTP is: %u", rec->otp_code);
    if (message->channel_id) {
        discord_channel_t *channel = discord_create_dm(client, message->author->id);
        discord_create_message(client, channel->id, out);
        discord_channel_destroy(channel);
    }
}

static void cmd_login(discord_client_t *client, discord_message_t *message, const char *otp_str) {
    if (!message->author || !message->author->id) return;
    const char *user_id = message->author->id;

    if (!otp_str || !*otp_str) {
        if (message->channel_id) {
            discord_channel_t *channel = discord_create_dm(client, message->author->id);
            discord_create_message(client, channel->id, "Usage: !login <otp>");
            discord_channel_destroy(channel);
        }
        return;
    }
    uint32_t provided = (uint32_t)strtoul(otp_str, NULL, 10);

    app_lock();
    AuthRecord *rec = authdb_find(&g_app.db, user_id);
    if (!rec || rec->otp_code == 0) {
        app_unlock();
        if (message->channel_id) {
            discord_channel_t *channel = discord_create_dm(client, message->author->id);
            discord_create_message(client, channel->id, "No OTP set. Use !register <password> first.");
            discord_channel_destroy(channel);
        }
        return;
    }
    if (provided == rec->otp_code) {
        rec->logged_in = true;
        clear_deadline(rec);
        authdb_save(&g_app.db, DB_PATH);
        app_unlock();

        if (message->channel_id) {
            discord_channel_t *channel = discord_create_dm(client, message->author->id);
            discord_create_message(client, channel->id, "Login successful. You may chat in the server.");
            discord_channel_destroy(channel);
        }
    } else {
        app_unlock();
        if (message->channel_id) {
            discord_channel_t *channel = discord_create_dm(client, message->author->id);
            discord_create_message(client, channel->id, "Invalid OTP.");
            discord_channel_destroy(channel);
        }
        discord_kick_member(client, message->guild_id, message->author->id, "Failed to authenticate!");
    }
}

static void cmd_logout(discord_client_t *client, discord_message_t *message) {
    if (!message->author || !message->author->id) return;
    const char *user_id = message->author->id;

    app_lock();
    AuthRecord *rec = authdb_find(&g_app.db, user_id);
    if (rec) {
        rec->logged_in = false;
        clear_deadline(rec);
        authdb_save(&g_app.db, DB_PATH);
    }
    app_unlock();

    if (message->channel_id) {
        discord_channel_t *channel = discord_create_dm(client, message->author->id);
        discord_create_message(client, channel->id, "Logged out. You must !login again before speaking.");
        discord_channel_destroy(channel);
    }
}

// ====================== Event Handlers ======================
static void on_ready(discord_client_t *client, discord_user_t *bot_user) {
    printf("Bot ready as %s#%s (%s)\n", bot_user->username, bot_user->discriminator, bot_user->id);
}

// This bot uses messages to enforce login. If a user posts in a guild without being logged in,
// we delete and instruct, and start a 5-minute deadline to login.
static void on_message(discord_client_t *client, discord_message_t *message) {
    if (!message || !message->author) return;

    // Ignore bot's own messages
    if (client->user && client->user->id && strcmp(client->user->id, message->author->id) == 0) return;

    const char *user_id = message->author->id;
    const char *guild_id = message->guild_id; // NULL for DM
    const char *content = message->content ? message->content : "";

    // If in a guild and user is not logged in, enforce
    if (guild_id) {
        bool is_logged_in = false;
        app_lock();
        AuthRecord *r = authdb_find(&g_app.db, user_id);
        if (r) is_logged_in = r->logged_in;
        app_unlock();

        // If not logged in, enforce
        if (!is_logged_in) {
            app_lock();
            AuthRecord *r2 = authdb_find_or_add(&g_app.db, user_id);
            app_unlock();
            handle_unauthenticated_message(client, message, r2);
        }
    } else {
        // Parse commands (works in DM)
        if (content[0] == '!') {
            if (strncmp(content, "!register ", 10) == 0) {
                const char *password = content + 10;
                cmd_register(client, message, password);
                return;
            }
            if (strcmp(content, "!otp") == 0) {
                cmd_otp(client, message);
                return;
            }
            if (strncmp(content, "!login ", 7) == 0) {
                const char *otp = content + 7;
                cmd_login(client, message, otp);
                return;
            }
            if (strcmp(content, "!logout") == 0) {
                cmd_logout(client, message);
                return;
            }
            if (strcmp(content, "!help") == 0) {
                if (message->channel_id) {
                    discord_embed_t *embed = discord_embed_create();
                    discord_embed_set_title(embed, "Bot Commands");
                    discord_embed_set_description(embed, "Here are the available commands:");
                    discord_embed_set_color(embed, 0x3498db); /* Blue */
                    discord_embed_add_field(embed, "!register <password>", "Register yourself on the authentication bot", false);
                    discord_embed_add_field(embed, "!otp", "Show your one-time code", false);
                    discord_embed_add_field(embed, "!login <otp>", "Login for this session", false);
                    discord_embed_add_field(embed, "!logout", "Logout of this session", false);
                    discord_embed_add_field(embed, "!help", "Show this help message", false);
                    
                    discord_channel_t *channel = discord_create_dm(client, message->author->id);
                    discord_create_message_embed(client, channel->id, embed);
                    discord_channel_destroy(channel);
                    discord_embed_destroy(embed);
                }
                return;
            }
        }

        // In DM and not a command
        if (message->channel_id) {
            discord_channel_t *channel = discord_create_dm(client, message->author->id);
            discord_create_message(client, channel->id, "Invalid command.\nType '!help' to see available commands.");
            discord_channel_destroy(channel);
        }
    }
}

void sig_handler(int sig) {
    if (g_app.client) {
        discord_client_stop(g_app.client);
    }
}

// ====================== Main ======================
int main(void) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    memset(&g_app, 0, sizeof(g_app));
    app_mutex_init();
    authdb_init(&g_app.db);

    g_app.db_loaded_ok = authdb_load(&g_app.db, DB_PATH);
    if (!g_app.db_loaded_ok) {
        fprintf(stderr, "Failed to load DB. Refusing to start autosave to avoid wiping the file.\n");
    }

    const char *token = getenv("BOT_TOKEN");
    if (!token) {
        fprintf(stderr, "Please set BOT_TOKEN environment variable.\n");
        return 1;
    }

    int intents = DISCORD_INTENT_GUILDS |
                  DISCORD_INTENT_GUILD_MESSAGES |
                  DISCORD_INTENT_DIRECT_MESSAGES |
                  DISCORD_INTENT_MESSAGE_CONTENT |
                  DISCORD_INTENT_GUILD_MEMBERS;

    discord_client_t *client = discord_client_create(token, intents);
    if (!client) {
        fprintf(stderr, "Failed to create Discord client.\n");
        return 1;
    }
    g_app.client = client;

    discord_set_on_ready(client, on_ready);
    discord_set_on_message(client, on_message);

    g_app.running = true;

    // Start kicker thread
#ifdef _WIN32
    HANDLE th = CreateThread(NULL, 0, kicker_thread_proc, NULL, 0, NULL);
#else
    pthread_t th;
    pthread_create(&th, NULL, kicker_thread_proc, NULL);
#endif

    // Run client (blocking until threads exit)
    int rc = discord_client_run(client);

    g_app.running = false;

#ifdef _WIN32
    WaitForSingleObject(th, INFINITE);
    CloseHandle(th);
#else
    pthread_join(th, NULL);
#endif

    authdb_save(&g_app.db, DB_PATH);
    authdb_free(&g_app.db);
    app_mutex_destroy();

    discord_client_destroy(client);
    return rc;
}
