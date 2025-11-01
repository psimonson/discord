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

#define _DEFAULT_SOURCE
#define DISCORD_IMPLEMENTATION

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>

#include "discord.h"
#include "cjson/cJSON.h"

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

// ====================== File IO (Load/Save with cJSON) ======================

static bool authdb_save(AuthDB *db, const char *path) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return false;

    cJSON *users_array = cJSON_CreateArray();
    if (!users_array) {
        cJSON_Delete(root);
        return false;
    }
    
    cJSON_AddItemToObject(root, "users", users_array);
    
    for (size_t i = 0; i < db->count; ++i) {
        AuthRecord *r = &db->items[i];
        cJSON *user_obj = cJSON_CreateObject();
        if (!user_obj) continue;
        
        cJSON_AddStringToObject(user_obj, "user_id", r->user_id ? r->user_id : "");
        cJSON_AddStringToObject(user_obj, "guild_id", r->guild_id ? r->guild_id : "");
        cJSON_AddStringToObject(user_obj, "username", r->username ? r->username : "");
        
        char ph[32];
        snprintf(ph, sizeof(ph), "%llu", (unsigned long long)r->password_hash);
        cJSON_AddStringToObject(user_obj, "password_hash", ph);
        
        char oc[32];
        snprintf(oc, sizeof(oc), "%u", r->otp_code);
        cJSON_AddStringToObject(user_obj, "otp_code", oc);
        
        cJSON_AddBoolToObject(user_obj, "logged_in", r->logged_in);
        
        char dl[32];
        snprintf(dl, sizeof(dl), "%lld", (long long)r->deadline);
        cJSON_AddStringToObject(user_obj, "deadline", dl);
        
        cJSON_AddItemToArray(users_array, user_obj);
    }

    char *json_str = cJSON_Print(root);
    if (!json_str) {
        cJSON_Delete(root);
        return false;
    }

    FILE *f = fopen(path, "wt");
    if (!f) {
        free(json_str);
        cJSON_Delete(root);
        return false;
    }
    
    fprintf(f, "%s", json_str);
    fclose(f);

    free(json_str);
    cJSON_Delete(root);
    
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

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    
    if (!root) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr) {
            fprintf(stderr, "[auth] JSON parse error before: %s\n", error_ptr);
        }
        return false;
    }

    cJSON *users_array = cJSON_GetObjectItemCaseSensitive(root, "users");
    if (!users_array || !cJSON_IsArray(users_array)) {
        fprintf(stderr, "[auth] No 'users' array found\n");
        cJSON_Delete(root);
        return true; // Empty DB is OK
    }

    int arr_size = cJSON_GetArraySize(users_array);
    fprintf(stderr, "[auth] Loading %d users from array...\n", arr_size);
    
    int loaded = 0;
    cJSON *user_obj = NULL;
    cJSON_ArrayForEach(user_obj, users_array) {
        if (!cJSON_IsObject(user_obj)) continue;
        
        cJSON *user_id_item = cJSON_GetObjectItemCaseSensitive(user_obj, "user_id");
        if (!user_id_item || !cJSON_IsString(user_id_item)) continue;
        
        const char *user_id = user_id_item->valuestring;
        if (!user_id || !user_id[0]) continue;
        
        AuthRecord *r = authdb_find_or_add(db, user_id);
        if (!r) continue;
        
        cJSON *guild_id_item = cJSON_GetObjectItemCaseSensitive(user_obj, "guild_id");
        if (guild_id_item && cJSON_IsString(guild_id_item) && guild_id_item->valuestring[0]) {
            free(r->guild_id);
            r->guild_id = strdup(guild_id_item->valuestring);
        }
        
        cJSON *username_item = cJSON_GetObjectItemCaseSensitive(user_obj, "username");
        if (username_item && cJSON_IsString(username_item) && username_item->valuestring[0]) {
            free(r->username);
            r->username = strdup(username_item->valuestring);
        }
        
        cJSON *password_hash_item = cJSON_GetObjectItemCaseSensitive(user_obj, "password_hash");
        if (password_hash_item && cJSON_IsString(password_hash_item)) {
            r->password_hash = strtoull(password_hash_item->valuestring, NULL, 10);
        }
        
        cJSON *otp_code_item = cJSON_GetObjectItemCaseSensitive(user_obj, "otp_code");
        if (otp_code_item && cJSON_IsString(otp_code_item)) {
            r->otp_code = (uint32_t)strtoul(otp_code_item->valuestring, NULL, 10);
        }
        
        cJSON *logged_in_item = cJSON_GetObjectItemCaseSensitive(user_obj, "logged_in");
        if (logged_in_item && cJSON_IsBool(logged_in_item)) {
            r->logged_in = cJSON_IsTrue(logged_in_item);
        }
        
        cJSON *deadline_item = cJSON_GetObjectItemCaseSensitive(user_obj, "deadline");
        if (deadline_item && cJSON_IsString(deadline_item)) {
            r->deadline = (time_t)strtoll(deadline_item->valuestring, NULL, 10);
        }
        
        loaded++;
    }

    fprintf(stderr, "[auth] Successfully loaded %d users from %s\n", loaded, path);

    cJSON_Delete(root);
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
        discord_message_t *message = discord_create_message(client, msg->channel_id, info);
        discord_message_destroy(message);
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
            discord_message_t *msg = discord_create_message(client, message->channel_id, "Usage: !register <password>");
            discord_message_destroy(msg);
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
        discord_message_t *msg = discord_create_message(client, channel->id, out);
        discord_message_destroy(msg);
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
            discord_message_t *msg = discord_create_message(client, message->channel_id, "No OTP set. Use !register <password> first.");
            discord_message_destroy(msg);
        }
        return;
    }
    char out[128];
    snprintf(out, sizeof(out), "Your OTP is: %u", rec->otp_code);
    if (message->channel_id) {
        discord_channel_t *channel = discord_create_dm(client, message->author->id);
        discord_message_t *msg = discord_create_message(client, channel->id, out);
        discord_message_destroy(msg);
        discord_channel_destroy(channel);
    }
}

static void cmd_login(discord_client_t *client, discord_message_t *message, const char *otp_str) {
    if (!message->author || !message->author->id) return;
    const char *user_id = message->author->id;

    if (!otp_str || !*otp_str) {
        if (message->channel_id) {
            discord_message_t *msg = discord_create_message(client, message->channel_id, "Usage: !login <otp>");
            discord_message_destroy(msg);
        }
        return;
    }
    uint32_t provided = (uint32_t)strtoul(otp_str, NULL, 10);

    app_lock();
    AuthRecord *rec = authdb_find(&g_app.db, user_id);
    if (!rec || rec->otp_code == 0) {
        app_unlock();
        if (message->channel_id) {
            discord_message_t *msg = discord_create_message(client, message->channel_id, "No OTP set. Use !register <password> first.");
            discord_message_destroy(msg);
        }
        return;
    }
    if (provided == rec->otp_code) {
        rec->logged_in = true;
        clear_deadline(rec);
        authdb_save(&g_app.db, DB_PATH);
        app_unlock();

        if (message->channel_id) {
            discord_message_t *msg = discord_create_message(client, message->channel_id, "Login successful. You may chat in the server.");
            discord_message_destroy(msg);
        }
    } else {
        app_unlock();
        if (message->channel_id) {
            discord_channel_t *channel = discord_create_dm(client, message->author->id);
            discord_message_t *msg = discord_create_message(client, channel->id, "Invalid OTP.");
            discord_message_destroy(msg);
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
        discord_message_t *msg = discord_create_message(client, message->channel_id, "Logged out. You must !login again before speaking.");
        discord_message_destroy(msg);
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

    // Parse commands (works in DM)
    if (content[0] == '!') {
        if (strcmp(content, "!otp") == 0) {
            cmd_otp(client, message);
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
                discord_embed_add_field(embed, "!register <password>", "(DM ONLY) Register yourself on the authentication bot", false);
                discord_embed_add_field(embed, "!otp", "Show your one-time code", false);
                discord_embed_add_field(embed, "!login <otp>", "(DM ONLY) Login for this session", false);
                discord_embed_add_field(embed, "!logout", "Logout of this session", false);
                discord_embed_add_field(embed, "!help", "Show this help message", false);
                discord_create_message_embed(client, message->channel_id, embed);
                discord_embed_destroy(embed);
            }
            return;
        }
    }
    
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
	if (content[0] == '!') {
            if (strncmp(content, "!register ", 10) == 0) {
	        const char *password = content + 10;
	        cmd_register(client, message, password);
		return;
	    }
	    if (strncmp(content, "!login ", 7) == 0) {
		const char *otp = content + 7;
		cmd_login(client, message, otp);
		return;
	    }
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
    discord_thread_t th = CreateThread(NULL, 0, kicker_thread_proc, NULL, 0, NULL);
#else
    discord_thread_t th;
    pthread_create(&th, NULL, kicker_thread_proc, NULL);
#endif

    // Run client (blocking until threads exit)
    int rc = discord_client_run(client);

    g_app.running = false;

    discord_os_thread_join(th);

    printf("Logging out all users in database... ");
    for (size_t i = 0; i < g_app.db.count; i++) {
        AuthRecord *r = &g_app.db.items[i];
        if (r->logged_in) {
            r->logged_in = false;
            clear_deadline(r);
        }
    }
    authdb_save(&g_app.db, DB_PATH);
    authdb_free(&g_app.db);
    app_mutex_destroy();
    printf("Done.\n");
    discord_client_destroy(client);
    return rc;
}
