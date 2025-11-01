CC = gcc
CFLAGS = -std=c11 -Wall -I./include
LDFLAGS = 
DEBUG ?= 0

# Python settings
PYTHON = python
PYTHON_VERSION = $(shell $(PYTHON) -c "import sys; print(f'{sys.version_info.major}{sys.version_info.minor}')")
PYTHON_INCLUDE = $(shell $(PYTHON) -c "import sysconfig; print(sysconfig.get_path('include'))")
PYTHON_LIBDIR = $(shell $(PYTHON) -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))")

HEADERS = include/discord.h

SOURCE1 = src/hello.c
OBJECT1 = $(SOURCE1:%.c=%.c.o)
TARGET1 = hello_bot

SOURCE2 = src/hello2.c
OBJECT2 = $(SOURCE2:%.c=%.c.o)
TARGET2 = hello_bot2

SOURCE3 = src/auth.c
OBJECT3 = $(SOURCE3:%.c=%.c.o)
TARGET3 = auth_bot

# Python module files
PYTHON_PYX = discord_py.pyx
PYTHON_PXD = discord_py.pxd
PYTHON_C = discord_py.c

ifeq ($(OS),Windows_NT)
	HEADERS := include\discord.h
	CFLAGS  += -I/msys64/mingw64/include
	LDFLAGS := -L/msys64/mingw64/lib -lcurl -lcJSON -lwebsockets -lws2_32

	SOURCE1 := src\hello.c
	TARGET1 := $(TARGET1).exe

	SOURCE2 := src\hello2.c
	TARGET2 := $(TARGET2).exe

	SOURCE3 := src\auth.c
	TARGET3 := $(TARGET3).exe

	# Python module for Windows
	PYTHON_MODULE = discord_py.pyd
	PYTHON_CFLAGS = -shared -O2 -DDISCORD_IMPLEMENTATION -I. -I./include -I/msys64/mingw64/include -I"$(PYTHON_INCLUDE)"
	PYTHON_LDFLAGS = -L/msys64/mingw64/lib -L"$(PYTHON_LIBDIR)" -lcurl -lcJSON -lwebsockets -lws2_32 -lpython$(PYTHON_VERSION)
	RM = del /Q
	RMDIR = rmdir /S /Q
else
	LDFLAGS := -lcurl -lcjson -lwebsockets -lpthread

	# Python module for Unix/Linux/macOS
	PYTHON_MODULE = discord_py.so
	PYTHON_CFLAGS = -shared -fPIC -O2 -DDISCORD_IMPLEMENTATION -I. -I./include -I$(PYTHON_INCLUDE)
	PYTHON_LDFLAGS = -lcurl -lcjson -lwebsockets -lpthread
	
	# macOS specific settings
	ifeq ($(shell uname -s),Darwin)
		PYTHON_CFLAGS += -undefined dynamic_lookup
		# Try to find Homebrew paths
		ifneq ($(wildcard /opt/homebrew),)
			PYTHON_CFLAGS += -I/opt/homebrew/include
			PYTHON_LDFLAGS += -L/opt/homebrew/lib
		else ifneq ($(wildcard /usr/local),)
			PYTHON_CFLAGS += -I/usr/local/include
			PYTHON_LDFLAGS += -L/usr/local/lib
		endif
	endif
	
	RM = rm -f
	RMDIR = rm -rf
endif

OBJECTS = $(OBJECT1) $(OBJECT2) $(OBJECT3)
TARGETS = $(TARGET1) $(TARGET2) $(TARGET3)

.PHONY: all clean build-python clean-python test-python help install-deps install-python uninstall-python

all: $(TARGETS)

help:
	@echo "Available targets:"
	@echo "  make all             - Build all C bot examples"
	@echo "  make build-python    - Build Python bindings"
	@echo "  make install-python  - Install Python module for user"
	@echo "  make uninstall-python- Uninstall Python module"
	@echo "  make test-python     - Test Python module import"
	@echo "  make clean           - Clean C bot builds"
	@echo "  make clean-python    - Clean Python builds"
	@echo "  make install-deps    - Install dependencies (MSYS2 only)"
	@echo ""

clean:
ifeq ($(OS),Windows_NT)
	-$(RM) $(OBJECTS) $(TARGETS) 2>nul
else
	$(RM) $(OBJECTS) $(TARGETS)
endif

# Build Python module using direct gcc compilation (faster, more control)
build-python: $(PYTHON_MODULE)

$(PYTHON_C): $(PYTHON_PYX) $(PYTHON_PXD) $(HEADERS)
	@echo "Generating C code from Cython..."
	$(PYTHON) -m cython $(PYTHON_PYX) --3str

$(PYTHON_MODULE): $(PYTHON_C) $(HEADERS)
	@echo "Compiling Python module with MinGW..."
	$(CC) $(PYTHON_CFLAGS) $(PYTHON_C) -o $(PYTHON_MODULE) $(PYTHON_LDFLAGS)
	@echo "Successfully built $(PYTHON_MODULE)!"

# Alternative: Build using setup.py (uses distutils/setuptools)
build-python-setup: $(HEADERS)
	@echo "Building Python module using setup.py..."
	$(PYTHON) setup.py build_ext --inplace --compiler=mingw32

# Test the Python module
test-python: $(PYTHON_MODULE)
	@echo "Testing Python module import..."
	$(PYTHON) -c "import discord_py; print('Module loaded successfully!'); print('Available constants:', dir(discord_py))"

# Install Python module to user site-packages
install-python: $(PYTHON_MODULE)
	@echo "Installing Python module for user..."
	$(PYTHON) -c "import shutil, site, os; os.makedirs(site.USER_SITE, exist_ok=True); shutil.copy('$(PYTHON_MODULE)', site.USER_SITE); print(f'Installed to: {site.USER_SITE}')"
	@echo "Module installed successfully! You can now 'import discord_py' from anywhere."

# Uninstall Python module from user site-packages
uninstall-python:
	@echo "Uninstalling Python module..."
	$(PYTHON) -c "import site, os; module_path = os.path.join(site.USER_SITE, '$(PYTHON_MODULE)'); (os.remove(module_path), print('Uninstalled from:', site.USER_SITE)) if os.path.exists(module_path) else print('Module not found in:', site.USER_SITE)"

clean-python: clean
ifeq ($(OS),Windows_NT)
	-$(RM) $(PYTHON_C) discord_py*.pyd discord_py*.so 2>nul
	-$(RMDIR) build 2>nul
	-$(RMDIR) discord_py_bindings.egg-info 2>nul
	-$(RMDIR) __pycache__ 2>nul
else
	$(RM) $(PYTHON_C) discord_py*.so discord_py*.pyd
	$(RMDIR) build discord_py_bindings.egg-info __pycache__
endif

# Install MSYS2 dependencies (Windows only)
install-deps:
ifeq ($(OS),Windows_NT)
	@echo "Installing MSYS2 dependencies..."
	pacman -S --needed --noconfirm \
		mingw-w64-x86_64-curl \
		mingw-w64-x86_64-libwebsockets \
		mingw-w64-x86_64-cjson \
		mingw-w64-x86_64-gcc
	@echo "Dependencies installed!"
else
	@echo "This target is for Windows/MSYS2 only."
	@echo "For Linux: sudo apt-get install libcurl4-openssl-dev libcjson-dev libwebsockets-dev"
	@echo "For macOS: brew install curl cjson libwebsockets"
endif

$(TARGET1): $(OBJECT1) $(HEADERS)
	$(CC) $(CFLAGS) $(OBJECT1) -o $@ $(LDFLAGS)

$(TARGET2): $(OBJECT2) $(HEADERS)
	$(CC) $(CFLAGS) $(OBJECT2) -o $@ $(LDFLAGS)

$(TARGET3): $(OBJECT3) $(HEADERS)
	$(CC) $(CFLAGS) $(OBJECT3) -o $@ $(LDFLAGS)

%.c.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<