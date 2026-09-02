CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror
BUILD_DIR := build
CORE_TEST := $(BUILD_DIR)/test-core
SOURCES := src/core.c src/windows_store.c src/pkcs11_bridge.c
INCLUDES := -Iinclude -Isrc
WINDOWS_LIBS := -lcrypt32 -lncrypt -lbcrypt -ladvapi32 -lwinscard

.PHONY: all test windows clean

all: test

$(CORE_TEST): src/core.c src/core.h tests/test_core.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -std=c11 -Isrc src/core.c tests/test_core.c -o $@

test: $(CORE_TEST)
	$(CORE_TEST)

windows: $(BUILD_DIR)/x64/pkcs11-cng-bridge.dll $(BUILD_DIR)/x64/test-pkcs11-abi.exe \
	$(BUILD_DIR)/x86/pkcs11-cng-bridge.dll $(BUILD_DIR)/x86/test-pkcs11-abi.exe

$(BUILD_DIR)/x64/pkcs11-cng-bridge.dll: $(SOURCES) include/pkcs11.h src/windows_store.h src/pkcs11_bridge.def
	mkdir -p $(BUILD_DIR)/x64
	x86_64-w64-mingw32-gcc $(CFLAGS) -std=c11 $(INCLUDES) -shared -static-libgcc \
		$(SOURCES) src/pkcs11_bridge.def $(WINDOWS_LIBS) -o $@

$(BUILD_DIR)/x86/pkcs11-cng-bridge.dll: $(SOURCES) include/pkcs11.h src/windows_store.h src/pkcs11_bridge.def
	mkdir -p $(BUILD_DIR)/x86
	i686-w64-mingw32-gcc $(CFLAGS) -std=c11 $(INCLUDES) -shared -static-libgcc \
		$(SOURCES) src/pkcs11_bridge.def $(WINDOWS_LIBS) -o $@

$(BUILD_DIR)/x64/test-pkcs11-abi.exe: tests/test_pkcs11_abi.c include/pkcs11.h
	x86_64-w64-mingw32-gcc $(CFLAGS) -std=c11 -municode -Iinclude $< -o $@

$(BUILD_DIR)/x86/test-pkcs11-abi.exe: tests/test_pkcs11_abi.c include/pkcs11.h
	i686-w64-mingw32-gcc $(CFLAGS) -std=c11 -municode -Iinclude $< -o $@

clean:
	rm -rf $(BUILD_DIR)
