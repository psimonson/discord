CC = gcc
CFLAGS = -std=c11 -Wall -I./include -I/msys64/mingw64/include
LDFLAGS = -L/msys64/mingw64/lib -lcurl -lcJSON -lwebsockets -lws2_32
DEBUG ?= 0

HEADERS = include/discord.h include/json_builder.h

SOURCE1 = src/hello.c
OBJECT1 = $(SOURCE1:%.c=%.c.o)
TARGET1 = hello_bot

SOURCE2 = src/hello2.c
OBJECT2 = $(SOURCE2:%.c=%.c.o)
TARGET2 = hello_bot2

SOURCE3 = src/auth.c
OBJECT3 = $(SOURCE3:%.c=%.c.o)
TARGET3 = auth_bot

ifeq ($(OS),Windows_NT)
	HEADERS := include\discord.h include\json_builder.h

	SOURCE1 := src\hello.c
	TARGET1 := $(TARGET1).exe

	SOURCE2 := src\hello2.c
	TARGET2 := $(TARGET2).exe

	SOURCE3 := src\auth.c
	TARGET3 := $(TARGET3).exe
endif

OBJECTS = $(OBJECT1) $(OBJECT2) $(OBJECT3)
TARGETS = $(TARGET1) $(TARGET2) $(TARGET3)

.PHONY: all clean
all: $(TARGETS)

clean:
ifeq ($(OS),Windows_NT)
	del /Q $(OBJECTS) $(TARGETS)
else
	rm -f $(OBJECTS) $(TARGETS)
endif

$(TARGET1): $(OBJECT1) $(HEADERS)
	$(CC) $(CFLAGS) $(OBJECT1) -o $@ $(LDFLAGS)

$(TARGET2): $(OBJECT2) $(HEADERS)
	$(CC) $(CFLAGS) $(OBJECT2) -o $@ $(LDFLAGS)

$(TARGET3): $(OBJECT3) $(HEADERS)
	$(CC) $(CFLAGS) $(OBJECT3) -o $@ $(LDFLAGS)

%.c.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<
