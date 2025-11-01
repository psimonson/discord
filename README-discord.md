# discord.h

A complete, single-header Discord Bot API implementation in C with full moderation capabilities.

## Features

- **Single-header library** - Just include one file to get started
- **Full Discord Gateway support** - Real-time event handling via WebSockets
- **Comprehensive moderation tools** - Kick, ban, timeout, roles, permissions, and more
- **Rich message support** - Embeds, reactions, bulk operations
- **Thread management** - Lock, archive, and manage thread members
- **Cross-platform** - Works on Windows, Linux, and macOS

## Quick Start

### Installation

1. Download `discord.h`
2. Install dependencies:
   - **libcurl** - For HTTPS requests
   - **cJSON** - For JSON parsing
   - **libwebsockets** - For WebSocket connections

#### Debian/Ubuntu
```bash
sudo apt-get install libcurl4-openssl-dev libcjson-dev libwebsockets-dev
```

#### macOS
```bash
brew install curl cjson libwebsockets
```

#### Windows
Download pre-built libraries or build from source. See the [libcurl](https://curl.se/), [cJSON](https://github.com/DaveGamble/cJSON), and [libwebsockets](https://libwebsockets.org/) documentation.

### Basic Example

```c
#define DISCORD_IMPLEMENTATION
#include "discord.h"

void on_ready(discord_client_t *client, discord_user_t *user) {
    printf("Bot ready! Logged in as %s\n", user->username);
}

void on_message(discord_client_t *client, discord_message_t *message) {
    if (strcmp(message->content, "!ping") == 0) {
        discord_create_message(client, message->channel_id, "Pong!");
    }
}

int main(void) {
    discord_client_t *client = discord_client_create(
        "YOUR_BOT_TOKEN",
        DISCORD_INTENT_GUILDS | DISCORD_INTENT_GUILD_MESSAGES | DISCORD_INTENT_MESSAGE_CONTENT
    );
    
    discord_set_on_ready(client, on_ready);
    discord_set_on_message(client, on_message);
    
    discord_client_run(client);
    discord_client_destroy(client);
    
    return 0;
}
```

### Compilation

```bash
# Linux/macOS
gcc -o bot bot.c -lcurl -lcjson -lwebsockets -lpthread

# Windows
gcc -o bot bot.c -lcurl -lcjson -lwebsockets -lws2_32
```

## Core Features

### Message Operations

```c
// Send a message
discord_create_message(client, channel_id, "Hello, world!");

// Send an embed
discord_embed_t *embed = discord_embed_create();
discord_embed_set_title(embed, "Title");
discord_embed_set_description(embed, "Description");
discord_embed_set_color(embed, 0x00FF00);
discord_create_message_embed(client, channel_id, embed);
discord_embed_destroy(embed);

// Edit a message
discord_edit_message(client, channel_id, message_id, "Updated content");

// Delete a message
discord_delete_message(client, channel_id, message_id);

// Bulk delete messages (2-100 messages)
const char *message_ids[] = {"id1", "id2", "id3"};
discord_bulk_delete_messages(client, channel_id, message_ids, 3, "Cleanup");
```

### Moderation

```c
// Kick a member
discord_kick_member(client, guild_id, user_id, "Reason");

// Ban a member (delete last 7 days of messages)
discord_ban_member(client, guild_id, user_id, 604800, "Reason");

// Unban a member
discord_unban_member(client, guild_id, user_id, "Appeal accepted");

// Timeout a member (1 hour)
discord_timeout_member(client, guild_id, user_id, 3600, "Calm down");

// Remove timeout
discord_remove_timeout(client, guild_id, user_id, NULL);

// Soft-ban (kick + delete messages)
discord_softban_member(client, guild_id, user_id, 86400, "Spam");
```

### Role Management

```c
// Add a role to a member
discord_add_member_role(client, guild_id, user_id, role_id, "Promotion");

// Remove a role from a member
discord_remove_member_role(client, guild_id, user_id, role_id, "Demotion");

// Create a new role
char *new_role_id = NULL;
discord_create_role(client, guild_id, "Moderator", "8", 0xFF0000, 
                   true, true, "New mod team", &new_role_id);
free(new_role_id);

// Modify an existing role
discord_modify_role(client, guild_id, role_id, "Super Moderator", 
                   NULL, 0x00FF00, true, true, false, false, NULL);

// Delete a role
discord_delete_role(client, guild_id, role_id, "No longer needed");
```

### Channel Permissions

```c
// Lock a text channel (prevent @everyone from sending messages)
discord_lock_text_channel(client, guild_id, channel_id, "Emergency lockdown");

// Unlock a text channel
discord_unlock_text_channel(client, guild_id, channel_id, "All clear");

// Set custom permission overwrite
discord_channel_set_permission_overwrite(
    client, channel_id, role_id, 0,  // 0 = role, 1 = member
    DISCORD_PERM_VIEW_CHANNEL | DISCORD_PERM_SEND_MESSAGES,  // allow
    0ULL,  // deny
    "Custom permissions"
);

// Set slowmode (in seconds)
discord_channel_set_slowmode(client, channel_id, 10, "Reduce spam");
```

### Thread Management

```c
// Lock a thread
discord_thread_set_locked(client, thread_id, true, "Discussion concluded");

// Archive a thread
discord_thread_set_archived(client, thread_id, true, "Archiving old thread");

// Set auto-archive duration (in minutes: 60, 1440, 4320, 10080)
discord_thread_set_auto_archive_duration(client, thread_id, 1440, NULL);

// Join/leave a thread
discord_thread_join(client, thread_id);
discord_thread_leave(client, thread_id);

// Add/remove members
discord_thread_add_member(client, thread_id, user_id);
discord_thread_remove_member(client, thread_id, user_id);
```

### Voice Management

```c
// Server mute a member
discord_set_voice_mute(client, guild_id, user_id, true, "Disruptive");

// Server deafen a member
discord_set_voice_deaf(client, guild_id, user_id, true, "Timeout");

// Move member to another voice channel
discord_move_member_voice(client, guild_id, user_id, channel_id, "Relocating");

// Disconnect from voice (pass NULL as channel_id)
discord_move_member_voice(client, guild_id, user_id, NULL, "Disconnecting");
```

### Reactions

```c
// Delete all reactions from a message
discord_delete_all_reactions(client, channel_id, message_id, "Cleanup");

// Delete all reactions for a specific emoji
discord_delete_reactions_emoji(client, channel_id, message_id, "👍", NULL);

// Delete a specific user's reaction
discord_delete_user_reaction(client, channel_id, message_id, "👍", user_id, NULL);
```

### Advanced Moderation

```c
// Get prune count (preview)
int count;
discord_get_prune_count(client, guild_id, 30, NULL, 0, &count);
printf("Would prune %d members\n", count);

// Begin prune (kick inactive members)
discord_begin_prune(client, guild_id, 30, NULL, 0, true, "Cleanup", &count);

// Get guild bans
int ban_count;
discord_guild_ban_t **bans = discord_get_guild_bans(client, guild_id, &ban_count);
for (int i = 0; i < ban_count; i++) {
    printf("Banned: %s - Reason: %s\n", 
           bans[i]->user->username, 
           bans[i]->reason ? bans[i]->reason : "No reason");
}
discord_guild_ban_list_destroy(bans, ban_count);
```

## Gateway Intents

Configure which events your bot receives:

```c
// Basic intents (no privileged intents required)
int intents = DISCORD_INTENT_GUILDS | 
              DISCORD_INTENT_GUILD_MESSAGES;

// All unprivileged intents
int intents = DISCORD_INTENT_ALL_UNPRIVILEGED;

// Privileged intents (requires enabling in Discord Developer Portal)
int intents = DISCORD_INTENT_GUILD_MEMBERS |      // Member updates
              DISCORD_INTENT_GUILD_PRESENCES |     // Presence updates
              DISCORD_INTENT_MESSAGE_CONTENT;      // Message content
```

## Event Callbacks

```c
void on_ready(discord_client_t *client, discord_user_t *user);
void on_message(discord_client_t *client, discord_message_t *message);
void on_message_delete(discord_client_t *client, const char *message_id, const char *channel_id);
void on_guild_create(discord_client_t *client, discord_guild_t *guild);
```

## Embeds

Create rich embeds with full formatting:

```c
discord_embed_t *embed = discord_embed_create();

// Basic info
discord_embed_set_title(embed, "Announcement");
discord_embed_set_description(embed, "This is a description");
discord_embed_set_url(embed, "https://example.com");
discord_embed_set_color(embed, 0x00FF00);  // Green

// Footer and author
discord_embed_set_footer(embed, "Footer text", "https://icon.url");
discord_embed_set_author(embed, "Author", "https://url", "https://icon.url");

// Fields
discord_embed_add_field(embed, "Field 1", "Value 1", true);   // Inline
discord_embed_add_field(embed, "Field 2", "Value 2", false);  // Not inline

// Media
discord_embed_set_thumbnail(embed, "https://thumbnail.url");
discord_embed_set_image(embed, "https://image.url");

// Timestamp
char *timestamp = discord_timestamp_now();
discord_embed_set_timestamp(embed, timestamp);
free(timestamp);

// Send
discord_create_message_embed(client, channel_id, embed);
discord_embed_destroy(embed);
```

## Error Handling

All functions return `0` on success or `-1` on failure. Check return values:

```c
if (discord_ban_member(client, guild_id, user_id, 0, "Spam") != 0) {
    fprintf(stderr, "Failed to ban member\n");
}
```

## Memory Management

Always clean up resources when done:

```c
discord_message_destroy(message);
discord_user_destroy(user);
discord_channel_destroy(channel);
discord_guild_destroy(guild);
discord_member_destroy(member);
discord_embed_destroy(embed);
```

## Thread Safety

The library handles internal thread synchronization. However, avoid calling functions from multiple threads simultaneously without external synchronization.

## License

MIT License - See the header file for full license text.

## Contributing

This is a single-header library. Contributions should maintain the single-file architecture and follow the existing code style.

## Resources

- [Discord API Documentation](https://discord.com/developers/docs)
- [Discord Developer Portal](https://discord.com/developers/applications)
- [Get Your Bot Token](https://discord.com/developers/applications)

## Support

For issues, questions, or feature requests, please refer to the Discord API documentation or community resources.