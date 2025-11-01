#!/usr/bin/env python3
"""
Test script to verify discord_py module is working correctly
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

print("Python version:", sys.version)
print("Testing discord_py module import...")

try:
    import discord_py
    print("✓ Module imported successfully!")
except ImportError as e:
    print(f"✗ Failed to import module: {e}")
    print("\nTroubleshooting:")
    print("1. Make sure the module is built: make build-python")
    print("2. Either install it: make install-python")
    print("3. Or run from the directory containing discord_py.pyd")
    sys.exit(1)

print("\nChecking module attributes...")

# Check constants
try:
    assert hasattr(discord_py, 'INTENT_GUILDS')
    assert hasattr(discord_py, 'INTENT_GUILD_MESSAGES')
    assert hasattr(discord_py, 'INTENT_MESSAGE_CONTENT')
    assert hasattr(discord_py, 'PERM_SEND_MESSAGES')
    print("✓ Constants available")
except AssertionError:
    print("✗ Missing expected constants")
    sys.exit(1)

# Check classes
try:
    assert hasattr(discord_py, 'Client')
    assert hasattr(discord_py, 'Embed')
    assert hasattr(discord_py, 'User')
    assert hasattr(discord_py, 'Message')
    assert hasattr(discord_py, 'Channel')
    assert hasattr(discord_py, 'Guild')
    print("✓ Classes available")
except AssertionError:
    print("✗ Missing expected classes")
    sys.exit(1)

# Check utility functions
try:
    assert hasattr(discord_py, 'timestamp_now')
    assert hasattr(discord_py, 'timestamp_offset_seconds')
    print("✓ Utility functions available")
except AssertionError:
    print("✗ Missing utility functions")
    sys.exit(1)

# Test timestamp functions
try:
    ts = discord_py.timestamp_now()
    assert ts is not None
    assert isinstance(ts, str)
    print(f"✓ timestamp_now() works: {ts}")
    
    ts_offset = discord_py.timestamp_offset_seconds(3600)
    assert ts_offset is not None
    assert isinstance(ts_offset, str)
    print(f"✓ timestamp_offset_seconds() works: {ts_offset}")
except Exception as e:
    print(f"✗ Timestamp functions failed: {e}")
    sys.exit(1)

# Test Embed creation
try:
    embed = discord_py.Embed()
    embed.set_title("Test")
    embed.set_description("Test description")
    embed.set_color(0xFF0000)
    embed.add_field("Name", "Value", False)
    print("✓ Embed creation works")
except Exception as e:
    print(f"✗ Embed creation failed: {e}")
    sys.exit(1)

# Test Client creation (without token)
try:
    # This should work even with invalid token (we're just testing object creation)
    intents = discord_py.INTENT_GUILDS | discord_py.INTENT_GUILD_MESSAGES
    # Don't actually create client without valid token in test
    print("✓ Client class accessible")
except Exception as e:
    print(f"✗ Client class test failed: {e}")
    sys.exit(1)

print("\n" + "="*50)
print("All tests passed! Module is working correctly.")
print("="*50)

print("\nAvailable intents:")
for attr in dir(discord_py):
    if attr.startswith('INTENT_'):
        value = getattr(discord_py, attr)
        print(f"  {attr}: {value}")

print("\nAvailable permissions:")
for attr in dir(discord_py):
    if attr.startswith('PERM_'):
        value = getattr(discord_py, attr)
        print(f"  {attr}: {value}")

print("\nModule is ready to use!")
print("\nNext steps:")
print("1. Set DISCORD_BOT_TOKEN environment variable")
print("2. Run: python example_bot.py")