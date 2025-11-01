# Discord.py - Python Bindings for discord.h

Python 3 bindings for the `discord.h` C library using Cython. This provides a high-performance Discord bot API with Python's ease of use.

## Features

- Full Discord Bot API implementation
- WebSocket Gateway support with automatic reconnection
- Message operations (create, edit, delete)
- Embed support with builder pattern
- Moderation commands (kick, ban, timeout, roles)
- Channel and guild operations
- Thread management
- Direct message support
- Event-driven architecture

## Requirements

### System Dependencies

You need the following C libraries installed:

- **libcurl** - For HTTPS requests
- **cJSON** - For JSON parsing
- **libwebsockets** - For WebSocket connections

#### Linux (Ubuntu/Debian)
```bash
sudo apt-get install libcurl4-openssl-dev libcjson-dev libwebsockets-dev
```

#### Linux (Fedora/RHEL)
```bash
sudo dnf install libcurl-devel cjson-devel libwebsockets-devel
```

#### macOS (Homebrew)
```bash
brew install curl cjson libwebsockets
```

#### Windows
Download and install prebuilt binaries or use vcpkg:
```bash
vcpkg install curl cjson libwebsockets
```

### Python Dependencies

- Python 3.6 or higher
- Cython 0.29.0 or higher

## Installation

1. Clone the repository and ensure `discord.h` is in the same directory
2. Install Python dependencies:
```bash
pip install cython
```

3. Build the extension:
```bash
python setup.py build_ext --inplace
```

Or install it as a package:
```bash
pip install .
```

## Quick Start

```python
import discord_py as discord

# Create client with intents
intents = (
    discord.INTENT_GUILDS |
    discord.INTENT_GUILD_MESSAGES |
    discord.INTENT_MESSAGE_CONTENT
)

client = discord.Client("YOUR_BOT_TOKEN", intents)

# Define event handlers
def on_ready(user):
    print(f"Logged in as {user.username}")

def on_message(message):
    if message.content == "!ping":
        client.create_message(message.channel_id, "Pong!")

# Register handlers
client.on_ready(on_ready)
client.on_message(on_message)

# Run the bot
client.run()
```

## API Reference

### Constants

#### Intents
- `INTENT_GUILDS`
- `INTENT_GUILD_MEMBERS` (privileged)
- `INTENT_GUILD_BANS`
- `INTENT_GUILD_MESSAGES`
- `INTENT_GUILD_MESSAGE_REACTIONS`
- `INTENT_DIRECT_MESSAGES`
- `INTENT_MESSAGE_CONTENT` (privileged)
- `INTENT_ALL_UNPRIVILEGED`

#### Permissions
- `PERM_VIEW_CHANNEL`
- `PERM_SEND_MESSAGES`
- `PERM_SEND_MESSAGES_IN_THREADS`
- `PERM_CREATE_PUBLIC_THREADS`
- `PERM_CREATE_PRIVATE_THREADS`

### Client Class

#### Constructor
```python
client = discord.Client(token: str, intents: int)
```

#### Methods

**Client Control:**
- `run()` - Start the bot (blocking)
- `stop()` - Stop the bot

**Event Handlers:**
- `on_ready(callback)` - Set ready callback
- `on_message(callback)` - Set message callback
- `on_message_delete(callback)` - Set message delete callback
- `on_guild_create(callback)` - Set guild create callback

**Messages:**
- `create_message(channel_id, content)` - Send a message
- `create_message_embed(channel_id, embed)` - Send an embed
- `delete_message(channel_id, message_id)` - Delete a message
- `edit_message(channel_id, message_id, content)` - Edit a message
- `send_typing(channel_id)` - Send typing indicator

**Channels:**
- `get_channel(channel_id)` - Get channel info
- `create_dm(recipient_id)` - Create DM channel
- `lock_text_channel(guild_id, channel_id, reason)` - Lock channel
- `unlock_text_channel(guild_id, channel_id, reason)` - Unlock channel

**Guilds:**
- `get_guild(guild_id)` - Get guild info
- `get_guild_bans(guild_id)` - Get ban list

**Moderation:**
- `kick_member(guild_id, user_id, reason)` - Kick member
- `ban_member(guild_id, user_id, delete_msg_secs, reason)` - Ban member
- `unban_member(guild_id, user_id, reason)` - Unban member
- `softban_member(guild_id, user_id, delete_msg_secs, reason)` - Soft-ban
- `timeout_member(guild_id, user_id, duration_secs, reason)` - Timeout member
- `remove_timeout(guild_id, user_id, reason)` - Remove timeout

**Roles:**
- `add_member_role(guild_id, user_id, role_id, reason)` - Add role
- `remove_member_role(guild_id, user_id, role_id, reason)` - Remove role
- `create_role(guild_id, name, perms, color, hoist, mentionable, reason)` - Create role
- `delete_role(guild_id, role_id, reason)` - Delete role

**Voice:**
- `set_voice_mute(guild_id, user_id, mute, reason)` - Mute in voice
- `set_voice_deaf(guild_id, user_id, deaf, reason)` - Deafen in voice

**Threads:**
- `thread_set_locked(thread_id, locked, reason)` - Lock/unlock thread
- `thread_set_archived(thread_id, archived, reason)` - Archive/unarchive
- `thread_set_auto_archive_duration(thread_id, minutes, reason)` - Set auto-archive
- `thread_join(thread_id)` - Join thread
- `thread_leave(thread_id)` - Leave thread
- `thread_add_member(thread_id, user_id)` - Add member to thread
- `thread_remove_member(thread_id, user_id)` - Remove member from thread

### Embed Class

```python
embed = discord.Embed()
embed.set_title("Title")
embed.set_description("Description")
embed.set_url("https://example.com")
embed.set_color(0x3498db)  # Hex color
embed.set_timestamp(discord.timestamp_now())
embed.set_footer("Footer text", icon_url)
embed.set_author("Author", url, icon_url)
embed.add_field("Name", "Value", inline=True)
embed.set_thumbnail("https://example.com/image.png")
embed.set_image("https://example.com/image.png")
```

### Data Classes

**User:**
- `id` - User ID
- `username` - Username
- `discriminator` - Discriminator
- `avatar` - Avatar hash
- `bot` - Is bot
- `system` - Is system user

**Message:**
- `id` - Message ID
- `channel_id` - Channel ID
- `guild_id` - Guild ID
- `author` - User object
- `member` - Member object
- `content` - Message content
- `timestamp` - ISO timestamp

**Channel:**
- `id` - Channel ID
- `type` - Channel type
- `guild_id` - Guild ID
- `name` - Channel name
- `topic` - Channel topic

**Guild:**
- `id` - Guild ID
- `name` - Guild name
- `icon` - Icon hash
- `owner_id` - Owner ID
- `member_count` - Member count

**Member:**
- `user` - User object
- `nick` - Nickname
- `roles` - List of role IDs
- `joined_at` - Join timestamp

**GuildBan:**
- `user` - User object
- `reason` - Ban reason

### Utility Functions

```python
# Get current timestamp
timestamp = discord.timestamp_now()

# Get timestamp offset by seconds
future_timestamp = discord.timestamp_offset_seconds(3600)  # 1 hour from now
```

## Examples

### Basic Echo Bot
```python
import discord_py as discord

client = discord.Client(token, discord.INTENT_GUILDS | discord.INTENT_GUILD_MESSAGES | discord.INTENT_MESSAGE_CONTENT)

def on_message(msg):
    if not msg.author.bot and msg.content:
        client.create_message(msg.channel_id, f"You said: {msg.content}")

client.on_message(on_message)
client.run()
```

### Moderation Bot
```python
def on_message(msg):
    if msg.content.startswith("!ban"):
        parts = msg.content.split()
        if len(parts) >= 2:
            user_id = parts[1]
            reason = " ".join(parts[2:]) or "No reason"
            client.ban_member(msg.guild_id, user_id, 86400, reason)
            client.create_message(msg.channel_id, f"Banned user {user_id}")
```

### Rich Embeds
```python
embed = discord.Embed()
embed.set_title("Server Stats")
embed.set_color(0x2ecc71)
embed.add_field("Members", "1,234", inline=True)
embed.add_field("Online", "567", inline=True)
embed.set_footer("Last updated")
embed.set_timestamp(discord.timestamp_now())

client.create_message_embed(channel_id, embed)
```

## Building from Source

### Development Mode
```bash
python setup.py build_ext --inplace
```

### Production Build
```bash
python setup.py build_ext --inplace --force
```

### Clean Build
```bash
rm -rf build/ discord_py.c discord_py*.so
python setup.py build_ext --inplace
```

## Troubleshooting

### Import Error
If you get `ImportError: cannot import name 'discord_py'`:
- Ensure the extension was built successfully
- Check that the `.so` (Linux/Mac) or `.pyd` (Windows) file exists
- Try `python setup.py build_ext --inplace --force`

### Linking Errors
If you get undefined symbol errors:
- Verify all dependencies are installed
- Check library paths with `ldconfig -p` (Linux) or `brew --prefix` (Mac)
- Add library paths to `LD_LIBRARY_PATH` (Linux) or `DYLD_LIBRARY_PATH` (Mac)

### SSL/TLS Errors
If WebSocket connection fails:
- Ensure you have OpenSSL installed
- On Windows, place `curl-ca-bundle.crt` or `cacert.pem` in the working directory

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please ensure:
- Code follows PEP 8 style guidelines
- All functions have docstrings
- New features include examples
- Memory management is handled correctly

## Support

For issues related to:
- **Python bindings**: Open an issue in this repository
- **C library (discord.h)**: Refer to the original library documentation
- **Discord API**: Check the [Discord Developer Portal](https://discord.com/developers/docs)