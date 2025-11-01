# discord_py.pxd - Cython definitions for discord.h
# This file declares the C API

from libc.stdint cimport uint64_t
from libc.time cimport time_t

cdef extern from "discord.h":
    # Constants
    int DISCORD_OP_DISPATCH
    int DISCORD_OP_HEARTBEAT
    int DISCORD_OP_IDENTIFY
    
    # Gateway Intents
    int DISCORD_INTENT_GUILDS
    int DISCORD_INTENT_GUILD_MEMBERS
    int DISCORD_INTENT_GUILD_BANS
    int DISCORD_INTENT_GUILD_MESSAGES
    int DISCORD_INTENT_GUILD_MESSAGE_REACTIONS
    int DISCORD_INTENT_DIRECT_MESSAGES
    int DISCORD_INTENT_MESSAGE_CONTENT
    int DISCORD_INTENT_ALL_UNPRIVILEGED
    
    # Permissions
    uint64_t DISCORD_PERM_VIEW_CHANNEL
    uint64_t DISCORD_PERM_SEND_MESSAGES
    uint64_t DISCORD_PERM_SEND_MESSAGES_IN_THREADS
    uint64_t DISCORD_PERM_CREATE_PUBLIC_THREADS
    uint64_t DISCORD_PERM_CREATE_PRIVATE_THREADS
    
    # Forward declarations
    ctypedef struct discord_client_t:
        pass
    
    ctypedef struct discord_user_t:
        char *id
        char *username
        char *discriminator
        char *avatar
        bint bot
        bint system
    
    ctypedef struct discord_channel_t:
        char *id
        int type
        char *guild_id
        char *name
        char *topic
        int position
    
    ctypedef struct discord_guild_t:
        char *id
        char *name
        char *icon
        char *owner_id
        int member_count
    
    ctypedef struct discord_member_t:
        discord_user_t *user
        char *nick
        char **roles
        int role_count
        char *joined_at
    
    ctypedef struct discord_embed_field_t:
        char *name
        char *value
        bint inline_field
    
    ctypedef struct discord_embed_footer_t:
        char *text
        char *icon_url
    
    ctypedef struct discord_embed_author_t:
        char *name
        char *url
        char *icon_url
    
    ctypedef struct discord_embed_t:
        char *title
        char *description
        char *url
        int color
        char *timestamp
        discord_embed_footer_t *footer
        discord_embed_author_t *author
        discord_embed_field_t *fields
        int field_count
        char *thumbnail_url
        char *image_url
    
    ctypedef struct discord_message_t:
        char *id
        char *channel_id
        char *guild_id
        discord_user_t *author
        discord_member_t *member
        char *content
        char *timestamp
        bint tts
        bint mention_everyone
        discord_user_t **mentions
        int mention_count
        discord_embed_t **embeds
        int embed_count
    
    ctypedef struct discord_guild_ban_t:
        discord_user_t *user
        char *reason
    
    # Callback types
    ctypedef void (*discord_on_ready_cb)(discord_client_t *client, discord_user_t *user)
    ctypedef void (*discord_on_message_cb)(discord_client_t *client, discord_message_t *message)
    ctypedef void (*discord_on_message_delete_cb)(discord_client_t *client, const char *message_id, const char *channel_id)
    ctypedef void (*discord_on_guild_create_cb)(discord_client_t *client, discord_guild_t *guild)
    
    # Client management
    discord_client_t *discord_client_create(const char *token, int intents)
    void discord_client_destroy(discord_client_t *client)
    int discord_client_run(discord_client_t *client)
    void discord_client_stop(discord_client_t *client)
    
    # Event handlers
    void discord_set_on_ready(discord_client_t *client, discord_on_ready_cb callback)
    void discord_set_on_message(discord_client_t *client, discord_on_message_cb callback)
    void discord_set_on_message_delete(discord_client_t *client, discord_on_message_delete_cb callback)
    void discord_set_on_guild_create(discord_client_t *client, discord_on_guild_create_cb callback)
    
    # DM operations
    discord_channel_t *discord_create_dm(discord_client_t *client, const char *recipient_id)
    
    # Message operations
    discord_message_t *discord_create_message(discord_client_t *client, const char *channel_id, const char *content)
    discord_message_t *discord_create_message_embed(discord_client_t *client, const char *channel_id, discord_embed_t *embed)
    int discord_delete_message(discord_client_t *client, const char *channel_id, const char *message_id)
    int discord_edit_message(discord_client_t *client, const char *channel_id, const char *message_id, const char *content)
    
    # Channel operations
    discord_channel_t *discord_get_channel(discord_client_t *client, const char *channel_id)
    int discord_send_typing(discord_client_t *client, const char *channel_id)
    
    # Guild operations
    discord_guild_t *discord_get_guild(discord_client_t *client, const char *guild_id)
    
    # Embed builder
    discord_embed_t *discord_embed_create()
    void discord_embed_destroy(discord_embed_t *embed)
    void discord_embed_set_title(discord_embed_t *embed, const char *title)
    void discord_embed_set_description(discord_embed_t *embed, const char *description)
    void discord_embed_set_url(discord_embed_t *embed, const char *url)
    void discord_embed_set_color(discord_embed_t *embed, int color)
    void discord_embed_set_timestamp(discord_embed_t *embed, const char *timestamp)
    void discord_embed_set_footer(discord_embed_t *embed, const char *text, const char *icon_url)
    void discord_embed_set_author(discord_embed_t *embed, const char *name, const char *url, const char *icon_url)
    void discord_embed_add_field(discord_embed_t *embed, const char *name, const char *value, bint inline_field)
    void discord_embed_set_thumbnail(discord_embed_t *embed, const char *url)
    void discord_embed_set_image(discord_embed_t *embed, const char *url)
    
    # Moderation operations
    int discord_kick_member(discord_client_t *client, const char *guild_id, const char *user_id, const char *reason)
    int discord_ban_member(discord_client_t *client, const char *guild_id, const char *user_id, int delete_message_seconds, const char *reason)
    int discord_unban_member(discord_client_t *client, const char *guild_id, const char *user_id, const char *reason)
    int discord_timeout_member(discord_client_t *client, const char *guild_id, const char *user_id, int duration_seconds, const char *reason)
    int discord_remove_timeout(discord_client_t *client, const char *guild_id, const char *user_id, const char *reason)
    int discord_add_member_role(discord_client_t *client, const char *guild_id, const char *user_id, const char *role_id, const char *reason)
    int discord_remove_member_role(discord_client_t *client, const char *guild_id, const char *user_id, const char *role_id, const char *reason)
    int discord_set_voice_mute(discord_client_t *client, const char *guild_id, const char *user_id, bint mute, const char *reason)
    int discord_set_voice_deaf(discord_client_t *client, const char *guild_id, const char *user_id, bint deaf, const char *reason)
    
    # Bans list
    discord_guild_ban_t **discord_get_guild_bans(discord_client_t *client, const char *guild_id, int *out_count)
    void discord_guild_ban_destroy(discord_guild_ban_t *ban)
    void discord_guild_ban_list_destroy(discord_guild_ban_t **bans, int count)
    
    # Roles
    int discord_create_role(discord_client_t *client, const char *guild_id, const char *name, const char *permissions,
                           int color, bint hoist, bint mentionable, const char *reason, char **out_role_id)
    int discord_modify_role(discord_client_t *client, const char *guild_id, const char *role_id,
                           const char *name, const char *permissions, int color,
                           bint hoist_set, bint hoist, bint mentionable_set, bint mentionable, const char *reason)
    int discord_delete_role(discord_client_t *client, const char *guild_id, const char *role_id, const char *reason)
    
    # Channel permissions
    int discord_channel_set_permission_overwrite(discord_client_t *client, const char *channel_id,
                                                 const char *overwrite_id, int type, uint64_t allow,
                                                 uint64_t deny, const char *reason)
    int discord_channel_delete_permission_overwrite(discord_client_t *client, const char *channel_id,
                                                    const char *overwrite_id, const char *reason)
    int discord_lock_text_channel(discord_client_t *client, const char *guild_id, const char *channel_id, const char *reason)
    int discord_unlock_text_channel(discord_client_t *client, const char *guild_id, const char *channel_id, const char *reason)
    
    # Prune & soft-ban
    int discord_get_prune_count(discord_client_t *client, const char *guild_id, int days,
                               const char **include_role_ids, int include_roles_count, int *out_count)
    int discord_begin_prune(discord_client_t *client, const char *guild_id, int days,
                           const char **include_role_ids, int include_roles_count,
                           bint compute_prune_count, const char *reason, int *out_count)
    int discord_softban_member(discord_client_t *client, const char *guild_id, const char *user_id,
                              int delete_message_seconds, const char *reason)
    
    # Thread moderation
    int discord_thread_set_locked(discord_client_t *client, const char *thread_id, bint locked, const char *reason)
    int discord_thread_set_archived(discord_client_t *client, const char *thread_id, bint archived, const char *reason)
    int discord_thread_set_auto_archive_duration(discord_client_t *client, const char *thread_id, int minutes, const char *reason)
    int discord_thread_join(discord_client_t *client, const char *thread_id)
    int discord_thread_leave(discord_client_t *client, const char *thread_id)
    int discord_thread_add_member(discord_client_t *client, const char *thread_id, const char *user_id)
    int discord_thread_remove_member(discord_client_t *client, const char *thread_id, const char *user_id)
    
    # Memory cleanup
    void discord_message_destroy(discord_message_t *message)
    void discord_user_destroy(discord_user_t *user)
    void discord_channel_destroy(discord_channel_t *channel)
    void discord_guild_destroy(discord_guild_t *guild)
    void discord_member_destroy(discord_member_t *member)
    
    # Utility functions
    char *discord_timestamp_offset_seconds(int seconds)
    char *discord_timestamp_now()