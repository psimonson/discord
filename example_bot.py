#!/usr/bin/env python3
"""
Example Discord bot using the Python bindings for discord.h

This demonstrates basic usage of the library including:
- Handling ready and message events
- Sending messages and embeds
- Basic moderation commands
"""

import sys
import os

# Handle DLL dependencies on Windows
if sys.platform == 'win32':
    # Try to add common DLL locations
    dll_paths = [
        os.path.join(os.path.dirname(__file__), 'lib'),
        r'C:\msys64\mingw64\bin',
        r'C:\msys2\mingw64\bin',
    ]
    
    for path in dll_paths:
        if os.path.exists(path):
            try:
                os.add_dll_directory(path)
                print(f"Added DLL directory: {path}")
            except (AttributeError, OSError) as e:
                # Python < 3.8 or path already added
                os.environ['PATH'] = path + os.pathsep + os.environ.get('PATH', '')

# Import the Cython module
try:
    import discord_py
except ImportError as e:
    print(f"Error: Could not import discord_py module: {e}")
    print("\nTroubleshooting steps:")
    print("1. Run: python copy_libraries.py")
    print("2. Make sure MSYS2 is installed at C:\\msys64")
    print("3. Or add C:\\msys64\\mingw64\\bin to your PATH")
    sys.exit(1)

# Import the Cython module
try:
    import discord_py
except ImportError as e:
    print(f"Error: Could not import discord_py module: {e}")
    print("\nMake sure you have built and installed the module:")
    print("  make build-python")
    print("  make install-python")
    print("\nOr run from the build directory where discord_py.pyd is located")
    sys.exit(1)

# Get token from environment variable
TOKEN = os.getenv('DISCORD_BOT_TOKEN')
if not TOKEN:
    print("Error: DISCORD_BOT_TOKEN environment variable not set")
    print("\nSet it with:")
    print("  Windows (PowerShell): $env:DISCORD_BOT_TOKEN='your_token_here'")
    print("  Windows (CMD): set DISCORD_BOT_TOKEN=your_token_here")
    print("  Linux/Mac: export DISCORD_BOT_TOKEN='your_token_here'")
    sys.exit(1)

# Configure intents - include MESSAGE_CONTENT for reading message content
intents = (
    discord_py.INTENT_GUILDS |
    discord_py.INTENT_GUILD_MESSAGES |
    discord_py.INTENT_DIRECT_MESSAGES |
    discord_py.INTENT_MESSAGE_CONTENT
)

print(f"Creating client with intents: {intents}")

# Create the client
try:
    client = discord_py.Client(TOKEN, intents)
except Exception as e:
    print(f"Error creating client: {e}")
    sys.exit(1)

# Event handlers
def on_ready(user):
    """Called when bot is ready"""
    print(f"Bot is ready! Logged in as {user.username}#{user.discriminator}")
    print(f"Bot ID: {user.id}")

def on_message(message):
    """Called when a message is received"""
    # Ignore messages from bots (including ourselves)
    if message.author and message.author.bot:
        return
    
    content = message.content
    if not content:
        return
    
    print(f"[{message.author.username}]: {content}")
    
    # Simple command handling
    if content.startswith("!ping"):
        client.create_message(message.channel_id, "Pong!")
    
    elif content.startswith("!hello"):
        client.create_message(message.channel_id, f"Hello {message.author.username}!")
    
    elif content.startswith("!embed"):
        # Create and send an embed
        embed = discord_py.Embed()
        embed.set_title("Example Embed")
        embed.set_description("This is an example embed created from Python!")
        embed.set_color(0x3498db)  # Blue color
        embed.add_field("Field 1", "Value 1", True)
        embed.add_field("Field 2", "Value 2", True)
        embed.set_footer("Footer text", None)
        embed.set_timestamp(discord_py.timestamp_now())
        
        client.create_message_embed(message.channel_id, embed)
    
    elif content.startswith("!info"):
        # Get channel information
        channel = client.get_channel(message.channel_id)
        if channel:
            msg = f"Channel: {channel.name}\nID: {channel.id}\nType: {channel.type}"
            client.create_message(message.channel_id, msg)
    
    elif content.startswith("!guild"):
        # Get guild information
        if message.guild_id:
            guild = client.get_guild(message.guild_id)
            if guild:
                msg = f"Guild: {guild.name}\nID: {guild.id}\nMembers: {guild.member_count}"
                client.create_message(message.channel_id, msg)
    
    elif content.startswith("!kick"):
        # Example moderation command (requires proper permissions)
        parts = content.split()
        if len(parts) >= 2 and message.guild_id:
            user_id = parts[1].strip('<@!>')  # Remove mention formatting
            reason = " ".join(parts[2:]) if len(parts) > 2 else "No reason provided"
            
            result = client.kick_member(message.guild_id, user_id, reason)
            if result == 0:
                client.create_message(message.channel_id, f"Kicked user {user_id}")
            else:
                client.create_message(message.channel_id, "Failed to kick user")
    
    elif content.startswith("!timeout"):
        # Timeout a user (requires proper permissions)
        parts = content.split()
        if len(parts) >= 3 and message.guild_id:
            user_id = parts[1].strip('<@!>')
            try:
                duration = int(parts[2])  # Duration in seconds
            except ValueError:
                client.create_message(message.channel_id, "Duration must be a number in seconds")
                return
            
            reason = " ".join(parts[3:]) if len(parts) > 3 else "No reason provided"
            
            result = client.timeout_member(message.guild_id, user_id, duration, reason)
            if result == 0:
                client.create_message(message.channel_id, 
                                    f"Timed out user {user_id} for {duration} seconds")
            else:
                client.create_message(message.channel_id, "Failed to timeout user")
    
    elif content.startswith("!help"):
        help_text = """**Available Commands:**
`!ping` - Ping the bot
`!hello` - Say hello
`!embed` - Send an example embed
`!info` - Get channel information
`!guild` - Get guild information
`!kick <user_id> [reason]` - Kick a user (requires permissions)
`!timeout <user_id> <seconds> [reason]` - Timeout a user (requires permissions)
`!help` - Show this message"""
        client.create_message(message.channel_id, help_text)

def on_message_delete(message_id, channel_id):
    """Called when a message is deleted"""
    print(f"Message {message_id} was deleted from channel {channel_id}")

def on_guild_create(guild):
    """Called when bot joins a guild or on startup for each guild"""
    print(f"Guild available: {guild.name} (ID: {guild.id})")

# Register event handlers
print("Registering event handlers...")
client.on_ready(on_ready)
client.on_message(on_message)
client.on_message_delete(on_message_delete)
client.on_guild_create(on_guild_create)

# Run the bot (blocking call)
print("Starting bot...")
print("Press Ctrl+C to stop")
try:
    result = client.run()
    if result != 0:
        print(f"Bot exited with code {result}")
except KeyboardInterrupt:
    print("\nReceived interrupt, stopping bot...")
    client.stop()
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    client.stop()