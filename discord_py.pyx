# discord_py.pyx - Python bindings for discord.h
# cython: language_level=3

from libc.stdlib cimport malloc, free
from libc.string cimport strlen
from libc.stdint cimport uint64_t
cimport discord_py

# Export constants
INTENT_GUILDS = discord_py.DISCORD_INTENT_GUILDS
INTENT_GUILD_MEMBERS = discord_py.DISCORD_INTENT_GUILD_MEMBERS
INTENT_GUILD_BANS = discord_py.DISCORD_INTENT_GUILD_BANS
INTENT_GUILD_MESSAGES = discord_py.DISCORD_INTENT_GUILD_MESSAGES
INTENT_GUILD_MESSAGE_REACTIONS = discord_py.DISCORD_INTENT_GUILD_MESSAGE_REACTIONS
INTENT_DIRECT_MESSAGES = discord_py.DISCORD_INTENT_DIRECT_MESSAGES
INTENT_MESSAGE_CONTENT = discord_py.DISCORD_INTENT_MESSAGE_CONTENT
INTENT_ALL_UNPRIVILEGED = discord_py.DISCORD_INTENT_ALL_UNPRIVILEGED

PERM_VIEW_CHANNEL = discord_py.DISCORD_PERM_VIEW_CHANNEL
PERM_SEND_MESSAGES = discord_py.DISCORD_PERM_SEND_MESSAGES
PERM_SEND_MESSAGES_IN_THREADS = discord_py.DISCORD_PERM_SEND_MESSAGES_IN_THREADS
PERM_CREATE_PUBLIC_THREADS = discord_py.DISCORD_PERM_CREATE_PUBLIC_THREADS
PERM_CREATE_PRIVATE_THREADS = discord_py.DISCORD_PERM_CREATE_PRIVATE_THREADS


# Helper functions
cdef bytes _to_bytes(s):
    if isinstance(s, bytes):
        return s
    elif isinstance(s, str):
        return s.encode('utf-8')
    return b''

cdef str _to_str(const char* s):
    if s == NULL:
        return None
    return s.decode('utf-8')

cdef const char* _get_cstr(bytes b):
    """Safely get C string from bytes, returning NULL for None"""
    if b is None:
        return NULL
    return <const char*>b


# Python wrapper classes
cdef class User:
    cdef discord_py.discord_user_t *_c_user
    cdef bint _owned
    
    def __cinit__(self):
        self._c_user = NULL
        self._owned = False
    
    @staticmethod
    cdef User from_ptr(discord_py.discord_user_t *ptr, bint owned=False):
        if ptr == NULL:
            return None
        u = User()
        u._c_user = ptr
        u._owned = owned
        return u
    
    def __dealloc__(self):
        if self._owned and self._c_user != NULL:
            discord_py.discord_user_destroy(self._c_user)
    
    @property
    def id(self):
        if self._c_user == NULL:
            return None
        return _to_str(self._c_user.id)
    
    @property
    def username(self):
        if self._c_user == NULL:
            return None
        return _to_str(self._c_user.username)
    
    @property
    def discriminator(self):
        if self._c_user == NULL:
            return None
        return _to_str(self._c_user.discriminator)
    
    @property
    def avatar(self):
        if self._c_user == NULL:
            return None
        return _to_str(self._c_user.avatar)
    
    @property
    def bot(self):
        if self._c_user == NULL:
            return False
        return self._c_user.bot
    
    @property
    def system(self):
        if self._c_user == NULL:
            return False
        return self._c_user.system
    
    def __repr__(self):
        return f"<User id={self.id} username={self.username}>"


cdef class Channel:
    cdef discord_py.discord_channel_t *_c_channel
    cdef bint _owned
    
    def __cinit__(self):
        self._c_channel = NULL
        self._owned = False
    
    @staticmethod
    cdef Channel from_ptr(discord_py.discord_channel_t *ptr, bint owned=True):
        if ptr == NULL:
            return None
        c = Channel()
        c._c_channel = ptr
        c._owned = owned
        return c
    
    def __dealloc__(self):
        if self._owned and self._c_channel != NULL:
            discord_py.discord_channel_destroy(self._c_channel)
    
    @property
    def id(self):
        if self._c_channel == NULL:
            return None
        return _to_str(self._c_channel.id)
    
    @property
    def type(self):
        if self._c_channel == NULL:
            return None
        return self._c_channel.type
    
    @property
    def guild_id(self):
        if self._c_channel == NULL:
            return None
        return _to_str(self._c_channel.guild_id)
    
    @property
    def name(self):
        if self._c_channel == NULL:
            return None
        return _to_str(self._c_channel.name)
    
    @property
    def topic(self):
        if self._c_channel == NULL:
            return None
        return _to_str(self._c_channel.topic)
    
    def __repr__(self):
        return f"<Channel id={self.id} name={self.name}>"


cdef class Guild:
    cdef discord_py.discord_guild_t *_c_guild
    cdef bint _owned
    
    def __cinit__(self):
        self._c_guild = NULL
        self._owned = False
    
    @staticmethod
    cdef Guild from_ptr(discord_py.discord_guild_t *ptr, bint owned=True):
        if ptr == NULL:
            return None
        g = Guild()
        g._c_guild = ptr
        g._owned = owned
        return g
    
    def __dealloc__(self):
        if self._owned and self._c_guild != NULL:
            discord_py.discord_guild_destroy(self._c_guild)
    
    @property
    def id(self):
        if self._c_guild == NULL:
            return None
        return _to_str(self._c_guild.id)
    
    @property
    def name(self):
        if self._c_guild == NULL:
            return None
        return _to_str(self._c_guild.name)
    
    @property
    def icon(self):
        if self._c_guild == NULL:
            return None
        return _to_str(self._c_guild.icon)
    
    @property
    def owner_id(self):
        if self._c_guild == NULL:
            return None
        return _to_str(self._c_guild.owner_id)
    
    @property
    def member_count(self):
        if self._c_guild == NULL:
            return 0
        return self._c_guild.member_count
    
    def __repr__(self):
        return f"<Guild id={self.id} name={self.name}>"


cdef class Member:
    cdef discord_py.discord_member_t *_c_member
    cdef bint _owned
    
    def __cinit__(self):
        self._c_member = NULL
        self._owned = False
    
    @staticmethod
    cdef Member from_ptr(discord_py.discord_member_t *ptr, bint owned=True):
        if ptr == NULL:
            return None
        m = Member()
        m._c_member = ptr
        m._owned = owned
        return m
    
    def __dealloc__(self):
        if self._owned and self._c_member != NULL:
            discord_py.discord_member_destroy(self._c_member)
    
    @property
    def user(self):
        if self._c_member == NULL or self._c_member.user == NULL:
            return None
        return User.from_ptr(self._c_member.user, False)
    
    @property
    def nick(self):
        if self._c_member == NULL:
            return None
        return _to_str(self._c_member.nick)
    
    @property
    def roles(self):
        if self._c_member == NULL:
            return []
        result = []
        for i in range(self._c_member.role_count):
            if self._c_member.roles[i] != NULL:
                result.append(_to_str(self._c_member.roles[i]))
        return result
    
    @property
    def joined_at(self):
        if self._c_member == NULL:
            return None
        return _to_str(self._c_member.joined_at)


cdef class Message:
    cdef discord_py.discord_message_t *_c_message
    cdef bint _owned
    
    def __cinit__(self):
        self._c_message = NULL
        self._owned = False
    
    @staticmethod
    cdef Message from_ptr(discord_py.discord_message_t *ptr, bint owned=True):
        if ptr == NULL:
            return None
        m = Message()
        m._c_message = ptr
        m._owned = owned
        return m
    
    def __dealloc__(self):
        if self._owned and self._c_message != NULL:
            discord_py.discord_message_destroy(self._c_message)
    
    @property
    def id(self):
        if self._c_message == NULL:
            return None
        return _to_str(self._c_message.id)
    
    @property
    def channel_id(self):
        if self._c_message == NULL:
            return None
        return _to_str(self._c_message.channel_id)
    
    @property
    def guild_id(self):
        if self._c_message == NULL:
            return None
        return _to_str(self._c_message.guild_id)
    
    @property
    def author(self):
        if self._c_message == NULL or self._c_message.author == NULL:
            return None
        return User.from_ptr(self._c_message.author, False)
    
    @property
    def member(self):
        if self._c_message == NULL or self._c_message.member == NULL:
            return None
        return Member.from_ptr(self._c_message.member, False)
    
    @property
    def content(self):
        if self._c_message == NULL:
            return None
        return _to_str(self._c_message.content)
    
    @property
    def timestamp(self):
        if self._c_message == NULL:
            return None
        return _to_str(self._c_message.timestamp)
    
    def __repr__(self):
        return f"<Message id={self.id} content={self.content[:50] if self.content else ''}>"


cdef class GuildBan:
    cdef discord_py.discord_guild_ban_t *_c_ban
    cdef bint _owned
    
    def __cinit__(self):
        self._c_ban = NULL
        self._owned = False
    
    @staticmethod
    cdef GuildBan from_ptr(discord_py.discord_guild_ban_t *ptr, bint owned=True):
        if ptr == NULL:
            return None
        b = GuildBan()
        b._c_ban = ptr
        b._owned = owned
        return b
    
    def __dealloc__(self):
        if self._owned and self._c_ban != NULL:
            discord_py.discord_guild_ban_destroy(self._c_ban)
    
    @property
    def user(self):
        if self._c_ban == NULL or self._c_ban.user == NULL:
            return None
        return User.from_ptr(self._c_ban.user, False)
    
    @property
    def reason(self):
        if self._c_ban == NULL:
            return None
        return _to_str(self._c_ban.reason)


cdef class Embed:
    cdef discord_py.discord_embed_t *_c_embed
    cdef bint _owned
    
    def __cinit__(self):
        self._c_embed = discord_py.discord_embed_create()
        self._owned = True
    
    def __dealloc__(self):
        if self._owned and self._c_embed != NULL:
            discord_py.discord_embed_destroy(self._c_embed)
    
    def set_title(self, str title):
        cdef bytes b_title = _to_bytes(title)
        discord_py.discord_embed_set_title(self._c_embed, b_title)
        return self
    
    def set_description(self, str description):
        cdef bytes b_desc = _to_bytes(description)
        discord_py.discord_embed_set_description(self._c_embed, b_desc)
        return self
    
    def set_url(self, str url):
        cdef bytes b_url = _to_bytes(url)
        discord_py.discord_embed_set_url(self._c_embed, b_url)
        return self
    
    def set_color(self, int color):
        discord_py.discord_embed_set_color(self._c_embed, color)
        return self
    
    def set_timestamp(self, str timestamp):
        cdef bytes b_ts = _to_bytes(timestamp)
        discord_py.discord_embed_set_timestamp(self._c_embed, b_ts)
        return self
    
    def set_footer(self, str text, str icon_url=None):
        cdef bytes b_text = _to_bytes(text)
        cdef bytes b_icon = _to_bytes(icon_url) if icon_url else None
        cdef const char* c_icon = _get_cstr(b_icon)
        discord_py.discord_embed_set_footer(self._c_embed, b_text, c_icon)
        return self
    
    def set_author(self, str name, str url=None, str icon_url=None):
        cdef bytes b_name = _to_bytes(name)
        cdef bytes b_url = _to_bytes(url) if url else None
        cdef bytes b_icon = _to_bytes(icon_url) if icon_url else None
        cdef const char* c_url = _get_cstr(b_url)
        cdef const char* c_icon = _get_cstr(b_icon)
        discord_py.discord_embed_set_author(self._c_embed, b_name, c_url, c_icon)
        return self
    
    def add_field(self, str name, str value, bint inline=False):
        cdef bytes b_name = _to_bytes(name)
        cdef bytes b_value = _to_bytes(value)
        discord_py.discord_embed_add_field(self._c_embed, b_name, b_value, inline)
        return self
    
    def set_thumbnail(self, str url):
        cdef bytes b_url = _to_bytes(url)
        discord_py.discord_embed_set_thumbnail(self._c_embed, b_url)
        return self
    
    def set_image(self, str url):
        cdef bytes b_url = _to_bytes(url)
        discord_py.discord_embed_set_image(self._c_embed, b_url)
        return self


# Callback storage
cdef dict _callback_storage = {}

# C callback wrappers - declare as noexcept to match C function pointer type
cdef void _on_ready_wrapper(discord_py.discord_client_t *client, discord_py.discord_user_t *user) noexcept with gil:
    cdef object callback = _callback_storage.get('on_ready')
    if callback:
        py_user = User.from_ptr(user, False)
        callback(py_user)

cdef void _on_message_wrapper(discord_py.discord_client_t *client, discord_py.discord_message_t *message) noexcept with gil:
    cdef object callback = _callback_storage.get('on_message')
    if callback:
        py_message = Message.from_ptr(message, False)
        callback(py_message)

cdef void _on_message_delete_wrapper(discord_py.discord_client_t *client, const char *msg_id, const char *ch_id) noexcept with gil:
    cdef object callback = _callback_storage.get('on_message_delete')
    if callback:
        callback(_to_str(msg_id), _to_str(ch_id))

cdef void _on_guild_create_wrapper(discord_py.discord_client_t *client, discord_py.discord_guild_t *guild) noexcept with gil:
    cdef object callback = _callback_storage.get('on_guild_create')
    if callback:
        py_guild = Guild.from_ptr(guild, False)
        callback(py_guild)


# Main Client class
cdef class Client:
    cdef discord_py.discord_client_t *_c_client
    
    def __cinit__(self, str token, int intents):
        cdef bytes b_token = _to_bytes(token)
        self._c_client = discord_py.discord_client_create(b_token, intents)
        if self._c_client == NULL:
            raise MemoryError("Failed to create Discord client")
    
    def __dealloc__(self):
        if self._c_client != NULL:
            discord_py.discord_client_destroy(self._c_client)
    
    def run(self):
        """Run the client (blocking call)"""
        cdef int result
        # Don't release GIL - callbacks need it
        result = discord_py.discord_client_run(self._c_client)
        return result
    
    def stop(self):
        """Stop the client"""
        discord_py.discord_client_stop(self._c_client)
    
    # Event handlers
    def on_ready(self, callback):
        """Set the ready callback"""
        _callback_storage['on_ready'] = callback
        discord_py.discord_set_on_ready(self._c_client, _on_ready_wrapper)
    
    def on_message(self, callback):
        """Set the message callback"""
        _callback_storage['on_message'] = callback
        discord_py.discord_set_on_message(self._c_client, _on_message_wrapper)
    
    def on_message_delete(self, callback):
        """Set the message delete callback"""
        _callback_storage['on_message_delete'] = callback
        discord_py.discord_set_on_message_delete(self._c_client, _on_message_delete_wrapper)
    
    def on_guild_create(self, callback):
        """Set the guild create callback"""
        _callback_storage['on_guild_create'] = callback
        discord_py.discord_set_on_guild_create(self._c_client, _on_guild_create_wrapper)
    
    # DM operations
    def create_dm(self, str recipient_id):
        """Create a DM channel"""
        cdef bytes b_id = _to_bytes(recipient_id)
        cdef discord_py.discord_channel_t *ch = discord_py.discord_create_dm(self._c_client, b_id)
        return Channel.from_ptr(ch, True)
    
    # Message operations
    def create_message(self, str channel_id, str content):
        """Send a message"""
        cdef bytes b_ch = _to_bytes(channel_id)
        cdef bytes b_content = _to_bytes(content)
        cdef discord_py.discord_message_t *msg = discord_py.discord_create_message(
            self._c_client, b_ch, b_content)
        return Message.from_ptr(msg, True)
    
    def create_message_embed(self, str channel_id, Embed embed):
        """Send a message with an embed"""
        cdef bytes b_ch = _to_bytes(channel_id)
        cdef discord_py.discord_message_t *msg = discord_py.discord_create_message_embed(
            self._c_client, b_ch, embed._c_embed)
        return Message.from_ptr(msg, True)
    
    def delete_message(self, str channel_id, str message_id):
        """Delete a message"""
        cdef bytes b_ch = _to_bytes(channel_id)
        cdef bytes b_msg = _to_bytes(message_id)
        return discord_py.discord_delete_message(self._c_client, b_ch, b_msg)
    
    def edit_message(self, str channel_id, str message_id, str content):
        """Edit a message"""
        cdef bytes b_ch = _to_bytes(channel_id)
        cdef bytes b_msg = _to_bytes(message_id)
        cdef bytes b_content = _to_bytes(content)
        return discord_py.discord_edit_message(self._c_client, b_ch, b_msg, b_content)
    
    # Channel operations
    def get_channel(self, str channel_id):
        """Get channel information"""
        cdef bytes b_ch = _to_bytes(channel_id)
        cdef discord_py.discord_channel_t *ch = discord_py.discord_get_channel(self._c_client, b_ch)
        return Channel.from_ptr(ch, True)
    
    def send_typing(self, str channel_id):
        """Send typing indicator"""
        cdef bytes b_ch = _to_bytes(channel_id)
        return discord_py.discord_send_typing(self._c_client, b_ch)
    
    # Guild operations
    def get_guild(self, str guild_id):
        """Get guild information"""
        cdef bytes b_g = _to_bytes(guild_id)
        cdef discord_py.discord_guild_t *g = discord_py.discord_get_guild(self._c_client, b_g)
        return Guild.from_ptr(g, True)
    
    # Moderation operations
    def kick_member(self, str guild_id, str user_id, str reason=None):
        """Kick a member"""
        cdef bytes b_g = _to_bytes(guild_id)
        cdef bytes b_u = _to_bytes(user_id)
        cdef bytes b_r = _to_bytes(reason) if reason else None
        cdef const char* c_r = _get_cstr(b_r)
        return discord_py.discord_kick_member(self._c_client, b_g, b_u, c_r)
    
    def ban_member(self, str guild_id, str user_id, int delete_message_seconds=0, str reason=None):
        """Ban a member"""
        cdef bytes b_g = _to_bytes(guild_id)
        cdef bytes b_u = _to_bytes(user_id)
        cdef bytes b_r = _to_bytes(reason) if reason else None
        cdef const char* c_r = _get_cstr(b_r)
        return discord_py.discord_ban_member(self._c_client, b_g, b_u, delete_message_seconds, c_r)
    
    def unban_member(self, str guild_id, str user_id, str reason=None):
        """Unban a member"""
        cdef bytes b_g = _to_bytes(guild_id)
        cdef bytes b_u = _to_bytes(user_id)
        cdef bytes b_r = _to_bytes(reason) if reason else None
        cdef const char* c_r = _get_cstr(b_r)
        return discord_py.discord_unban_member(self._c_client, b_g, b_u, c_r)
    
    def timeout_member(self, str guild_id, str user_id, int duration_seconds, str reason=None):
        """Timeout a member"""
        cdef bytes b_g = _to_bytes(guild_id)
        cdef bytes b_u = _to_bytes(user_id)
        cdef bytes b_r = _to_bytes(reason) if reason else None
        cdef const char* c_r = _get_cstr(b_r)
        return discord_py.discord_timeout_member(self._c_client, b_g, b_u, duration_seconds, c_r)
    
    def remove_timeout(self, str guild_id, str user_id, str reason=None):
        """Remove timeout from a member"""
        cdef bytes b_g = _to_bytes(guild_id)
        cdef bytes b_u = _to_bytes(user_id)
        cdef bytes b_r = _to_bytes(reason) if reason else None
        cdef const char* c_r = _get_cstr(b_r)
        return discord_py.discord_remove_timeout(self._c_client, b_g, b_u, c_r)
    
    def add_member_role(self, str guild_id, str user_id, str role_id, str reason=None):
        """Add a role to a member"""
        cdef bytes b_g = _to_bytes(guild_id)
        cdef bytes b_u = _to_bytes(user_id)
        cdef bytes b_role = _to_bytes(role_id)
        cdef bytes b_r = _to_bytes(reason) if reason else None
        cdef const char* c_r = _get_cstr(b_r)
        return discord_py.discord_add_member_role(self._c_client, b_g, b_u, b_role, c_r)
    
    def remove_member_role(self, str guild_id, str user_id, str role_id, str reason=None):
        """Remove a role from a member"""
        cdef bytes b_g = _to_bytes(guild_id)
        cdef bytes b_u = _to_bytes(user_id)
        cdef bytes b_role = _to_bytes(role_id)
        cdef bytes b_r = _to_bytes(reason) if reason else None
        cdef const char* c_r = _get_cstr(b_r)
        return discord_py.discord_remove_member_role(self._c_client, b_g, b_u, b_role, c_r)
    
    def set_voice_mute(self, str guild_id, str user_id, bint mute, str reason=None):
        """Mute/unmute a member in voice"""
        cdef bytes b_g = _to_bytes(guild_id)
        cdef bytes b_u = _to_bytes(user_id)
        cdef bytes b_r = _to_bytes(reason) if reason else None
        cdef const char* c_r = _get_cstr(b_r)
        return discord_py.discord_set_voice_mute(self._c_client, b_g, b_u, mute, c_r)
    
    def set_voice_deaf(self, str guild_id, str user_id, bint deaf, str reason=None):
        """Deafen/undeafen a member in voice"""
        cdef bytes b_g = _to_bytes(guild_id)
        cdef bytes b_u = _to_bytes(user_id)
        cdef bytes b_r = _to_bytes(reason) if reason else None
        cdef const char* c_r = _get_cstr(b_r)
        return discord_py.discord_set_voice_deaf(self._c_client, b_g, b_u, deaf, c_r)
    
    def get_guild_bans(self, str guild_id):
        """Get list of guild bans"""
        cdef bytes b_g = _to_bytes(guild_id)
        cdef int count = 0
        cdef discord_py.discord_guild_ban_t **bans = discord_py.discord_get_guild_bans(
            self._c_client, b_g, &count)
        
        result = []
        if bans != NULL:
            for i in range(count):
                if bans[i] != NULL:
                    result.append(GuildBan.from_ptr(bans[i], False))
            discord_py.discord_guild_ban_list_destroy(bans, count)
        
        return result
    
    def create_role(self, str guild_id, str name, str permissions=None, 
                   int color=-1, bint hoist=False, bint mentionable=False, str reason=None):
        """Create a role"""
        cdef bytes b_g = _to_bytes(guild_id)
        cdef bytes b_name = _to_bytes(name)
        cdef bytes b_perms = _to_bytes(permissions) if permissions else None
        cdef bytes b_r = _to_bytes(reason) if reason else None
        cdef const char* c_perms = _get_cstr(b_perms)
        cdef const char* c_r = _get_cstr(b_r)
        cdef char *role_id = NULL
        
        cdef int result = discord_py.discord_create_role(
            self._c_client, b_g, b_name, c_perms,
            color, hoist, mentionable, c_r, &role_id)
        
        py_role_id = None
        if result == 0 and role_id != NULL:
            py_role_id = _to_str(role_id)
            free(role_id)
        
        return py_role_id if result == 0 else None
    
    def delete_role(self, str guild_id, str role_id, str reason=None):
        """Delete a role"""
        cdef bytes b_g = _to_bytes(guild_id)
        cdef bytes b_role = _to_bytes(role_id)
        cdef bytes b_r = _to_bytes(reason) if reason else None
        cdef const char* c_r = _get_cstr(b_r)
        return discord_py.discord_delete_role(self._c_client, b_g, b_role, c_r)
    
    def lock_text_channel(self, str guild_id, str channel_id, str reason=None):
        """Lock a text channel"""
        cdef bytes b_g = _to_bytes(guild_id)
        cdef bytes b_ch = _to_bytes(channel_id)
        cdef bytes b_r = _to_bytes(reason) if reason else None
        cdef const char* c_r = _get_cstr(b_r)
        return discord_py.discord_lock_text_channel(self._c_client, b_g, b_ch, c_r)
    
    def unlock_text_channel(self, str guild_id, str channel_id, str reason=None):
        """Unlock a text channel"""
        cdef bytes b_g = _to_bytes(guild_id)
        cdef bytes b_ch = _to_bytes(channel_id)
        cdef bytes b_r = _to_bytes(reason) if reason else None
        cdef const char* c_r = _get_cstr(b_r)
        return discord_py.discord_unlock_text_channel(self._c_client, b_g, b_ch, c_r)
    
    def softban_member(self, str guild_id, str user_id, int delete_message_seconds=0, str reason=None):
        """Soft-ban a member (ban then unban to delete messages)"""
        cdef bytes b_g = _to_bytes(guild_id)
        cdef bytes b_u = _to_bytes(user_id)
        cdef bytes b_r = _to_bytes(reason) if reason else None
        cdef const char* c_r = _get_cstr(b_r)
        return discord_py.discord_softban_member(self._c_client, b_g, b_u, delete_message_seconds, c_r)
    
    # Thread operations
    def thread_set_locked(self, str thread_id, bint locked, str reason=None):
        """Lock/unlock a thread"""
        cdef bytes b_t = _to_bytes(thread_id)
        cdef bytes b_r = _to_bytes(reason) if reason else None
        cdef const char* c_r = _get_cstr(b_r)
        return discord_py.discord_thread_set_locked(self._c_client, b_t, locked, c_r)
    
    def thread_set_archived(self, str thread_id, bint archived, str reason=None):
        """Archive/unarchive a thread"""
        cdef bytes b_t = _to_bytes(thread_id)
        cdef bytes b_r = _to_bytes(reason) if reason else None
        cdef const char* c_r = _get_cstr(b_r)
        return discord_py.discord_thread_set_archived(self._c_client, b_t, archived, c_r)
    
    def thread_set_auto_archive_duration(self, str thread_id, int minutes, str reason=None):
        """Set thread auto-archive duration"""
        cdef bytes b_t = _to_bytes(thread_id)
        cdef bytes b_r = _to_bytes(reason) if reason else None
        cdef const char* c_r = _get_cstr(b_r)
        return discord_py.discord_thread_set_auto_archive_duration(self._c_client, b_t, minutes, c_r)
    
    def thread_join(self, str thread_id):
        """Join a thread"""
        cdef bytes b_t = _to_bytes(thread_id)
        return discord_py.discord_thread_join(self._c_client, b_t)
    
    def thread_leave(self, str thread_id):
        """Leave a thread"""
        cdef bytes b_t = _to_bytes(thread_id)
        return discord_py.discord_thread_leave(self._c_client, b_t)
    
    def thread_add_member(self, str thread_id, str user_id):
        """Add a member to a thread"""
        cdef bytes b_t = _to_bytes(thread_id)
        cdef bytes b_u = _to_bytes(user_id)
        return discord_py.discord_thread_add_member(self._c_client, b_t, b_u)
    
    def thread_remove_member(self, str thread_id, str user_id):
        """Remove a member from a thread"""
        cdef bytes b_t = _to_bytes(thread_id)
        cdef bytes b_u = _to_bytes(user_id)
        return discord_py.discord_thread_remove_member(self._c_client, b_t, b_u)


# Utility functions
def timestamp_now():
    """Get current timestamp in ISO 8601 format"""
    cdef char *ts = discord_py.discord_timestamp_now()
    if ts == NULL:
        return None
    py_ts = _to_str(ts)
    free(ts)
    return py_ts

def timestamp_offset_seconds(int seconds):
    """Get timestamp offset by seconds from now"""
    cdef char *ts = discord_py.discord_timestamp_offset_seconds(seconds)
    if ts == NULL:
        return None
    py_ts = _to_str(ts)
    free(ts)
    return py_ts