// hello2.c
// Build:
//   Windows: gcc -O2 -o hello_bot2.exe hello2.c -lcurl -lcjson -lwebsockets -lws2_32
//   Linux/macOS: gcc -O2 -o hello_bot2 hello2.c -lcurl -lcjson -lwebsockets -lpthread
// Run:
//   Windows:
//     $env:BOT_TOKEN="YOUR_TOKEN"
//     .\hello_bot2.exe
//   Linux:
//     export BOT_TOKEN="YOUR_TOKEN"
//     ./hello_bot2

#define DISCORD_IMPLEMENTATION
#include "discord.h"

#include <stdio.h>
#include <string.h>
#include <signal.h>

discord_client_t *g_client = NULL;

void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down...\n", sig);
    if (g_client) {
        discord_client_stop(g_client);
    }
}

void on_ready(discord_client_t *client, discord_user_t *user) {
    printf("Bot is ready! Logged in as %s#%s\n", user->username, user->discriminator);
}

void on_message(discord_client_t *client, discord_message_t *message) {
    /* Ignore messages from bots */
    if (message->author && message->author->bot) {
        return;
    }
    
    printf("[%s] %s: %s\n", 
           message->channel_id, 
           message->author ? message->author->username : "Unknown",
           message->content);
    
    /* Respond to !ping command */
    if (strcmp(message->content, "!ping") == 0) {
        discord_create_message(client, message->channel_id, "Pong! 🏓");
    }
    
    /* Respond to !embed command */
    else if (strcmp(message->content, "!embed") == 0) {
        discord_embed_t *embed = discord_embed_create();
        discord_embed_set_title(embed, "Example Embed");
        discord_embed_set_description(embed, "This is an example embed created with discord.h!");
        discord_embed_set_color(embed, 0x00FF00); /* Green */
        discord_embed_add_field(embed, "Field 1", "Value 1", true);
        discord_embed_add_field(embed, "Field 2", "Value 2", true);
        discord_embed_set_footer(embed, "Footer text", NULL);
        discord_embed_set_timestamp(embed, discord_timestamp_now());
        
        discord_create_message_embed(client, message->channel_id, embed);
        discord_embed_destroy(embed);
    }
    
    /* Respond to !info command */
    else if (strcmp(message->content, "!info") == 0) {
        char response[512];
        snprintf(response, sizeof(response),
                 "**Bot Information**\n"
                 "Username: %s#%s\n"
                 "User ID: %s\n"
                 "Library: discord.h v1.0 (libwebsockets)",
                 client->user->username,
                 client->user->discriminator,
                 client->user->id);
        
        discord_create_message(client, message->channel_id, response);
    }

    /* Respond to !help command */
    else if (strcmp(message->content, "!help") == 0) {
        discord_embed_t *embed = discord_embed_create();
        discord_embed_set_title(embed, "Bot Commands");
        discord_embed_set_description(embed, "Here are the available commands:");
        discord_embed_set_color(embed, 0x3498db); /* Blue */
        discord_embed_add_field(embed, "!ping", "Check if the bot is responsive", false);
        discord_embed_add_field(embed, "!embed", "Display an example embed", false);
        discord_embed_add_field(embed, "!info", "Show bot information", false);
        discord_embed_add_field(embed, "!login", "Put login info into JSON format", false);
        discord_embed_add_field(embed, "!help", "Show this help message", false);
        
        discord_create_message_embed(client, message->channel_id, embed);
        discord_embed_destroy(embed);
    }
}

void on_message_delete(discord_client_t *client, const char *message_id, const char *channel_id) {
    printf("Message %s was deleted in channel %s\n", message_id, channel_id);
}

void on_guild_create(discord_client_t *client, discord_guild_t *guild) {
    printf("Joined guild: %s (ID: %s, Members: %d)\n", 
           guild->name, guild->id, guild->member_count);
}

int main() {
    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* Create client with common intents */
    int intents = DISCORD_INTENT_GUILDS | 
                  DISCORD_INTENT_GUILD_MESSAGES | 
                  DISCORD_INTENT_MESSAGE_CONTENT;

    const char *token = getenv("BOT_TOKEN");
    if (!token) {
        fprintf(stderr, "Please set BOT_TOKEN environment variable.\n");
        return 1;
    }
    
    discord_client_t *client = discord_client_create(token, intents);
    if (!client) {
        fprintf(stderr, "Failed to create Discord client\n");
        return 1;
    }
    
    g_client = client;
    
    /* Set event handlers */
    discord_set_on_ready(client, on_ready);
    discord_set_on_message(client, on_message);
    discord_set_on_message_delete(client, on_message_delete);
    discord_set_on_guild_create(client, on_guild_create);
    
    /* Run the bot (blocking) */
    printf("Starting bot...\n");
    int result = discord_client_run(client);
    
    /* Cleanup */
    discord_client_destroy(client);
    
    return result;
}
