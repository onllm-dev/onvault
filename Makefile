# onvault — Seamless File Encryption & Access Control for macOS
# Makefile

CC       = clang
CFLAGS   = -Wall -Wextra -Werror -pedantic -std=c17 -O2
CFLAGS  += -mmacosx-version-min=15.0

OBJCFLAGS = -Wall -Wextra -Werror -O2 -fobjc-arc
OBJCFLAGS += -mmacosx-version-min=15.0

# Homebrew paths
BREW_PREFIX  = $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)
OPENSSL_DIR  = $(shell brew --prefix openssl@3 2>/dev/null || echo $(BREW_PREFIX)/opt/openssl@3)
ARGON2_DIR   = $(shell brew --prefix argon2 2>/dev/null || echo $(BREW_PREFIX)/opt/argon2)

INCLUDES  = -Isrc/common -Isrc/keystore -Isrc/auth -Isrc/fuse -Isrc/esf -Isrc/watch
INCLUDES += -I$(OPENSSL_DIR)/include
INCLUDES += -I$(ARGON2_DIR)/include

# macFUSE detection
FUSE_AVAILABLE := $(shell pkg-config --exists fuse 2>/dev/null && echo 1 || echo 0)
ifeq ($(FUSE_AVAILABLE),1)
FUSE_CFLAGS  := $(shell pkg-config --cflags fuse 2>/dev/null)
FUSE_LDFLAGS := $(shell pkg-config --libs fuse 2>/dev/null)
CFLAGS      += -DHAVE_MACFUSE $(FUSE_CFLAGS)
OBJCFLAGS   += -DHAVE_MACFUSE $(FUSE_CFLAGS)
$(info FUSE: enabled (macFUSE found via pkg-config))
else
$(info FUSE: disabled (macFUSE not found))
endif

# Dynamic linking (development)
LDFLAGS  = -L$(OPENSSL_DIR)/lib -lcrypto
LDFLAGS += -L$(ARGON2_DIR)/lib -largon2
LDFLAGS += -framework Security
LDFLAGS += -framework Foundation

# Static linking (distribution) — no Homebrew needed by end users
STATIC_LDFLAGS  = $(OPENSSL_DIR)/lib/libcrypto.a
STATIC_LDFLAGS += $(ARGON2_DIR)/lib/libargon2.a
STATIC_LDFLAGS += -framework Security
STATIC_LDFLAGS += -framework Foundation

LDFLAGS_GUI  = $(LDFLAGS)
LDFLAGS_GUI += -framework Cocoa
LDFLAGS_GUI += -framework UserNotifications
LDFLAGS_GUI += -framework LocalAuthentication

# Find the newest macOS SDK that has EndpointSecurity
MACOS_SDK := $(shell for sdk in /Library/Developer/CommandLineTools/SDKs/MacOSX26*.sdk /Library/Developer/CommandLineTools/SDKs/MacOSX15*.sdk; do \
	[ -f "$$sdk/usr/lib/libEndpointSecurity.tbd" ] && echo "$$sdk" && break; \
done 2>/dev/null)
ifdef MACOS_SDK
CFLAGS    += -isysroot $(MACOS_SDK)
OBJCFLAGS += -isysroot $(MACOS_SDK)
LDFLAGS   += -isysroot $(MACOS_SDK)
endif
ESF_TBD := $(if $(MACOS_SDK),$(shell test -f "$(MACOS_SDK)/usr/lib/libEndpointSecurity.tbd" && echo 1 || echo 0),0)
LDFLAGS_ESF  = $(LDFLAGS)
ifeq ($(ESF_TBD),1)
LDFLAGS_ESF += -lEndpointSecurity -lbsm
CFLAGS      += -DHAVE_ESF
OBJCFLAGS   += -DHAVE_ESF
$(info ESF: enabled (found libEndpointSecurity.tbd in SDK))
else
$(info ESF: disabled (libEndpointSecurity.tbd not found))
endif

# Source files
COMMON_C_SRC = src/common/crypto.c \
               src/common/hash.c \
               src/common/memwipe.c \
               src/common/argon2_kdf.c \
               src/common/ipc.c \
               src/common/config.c \
               src/common/log.c

FUSE_C_SRC   = src/fuse/encrypt.c \
               src/fuse/vault.c \
               src/fuse/onvault_fuse.c

ESF_C_SRC    = src/esf/policy.c

AUTH_C_SRC   = src/auth/auth.c

WATCH_C_SRC  = src/watch/watch.c

# Object files
COMMON_OBJ   = $(COMMON_C_SRC:.c=.o)
FUSE_OBJ     = $(FUSE_C_SRC:.c=.o)
ESF_C_OBJ    = $(ESF_C_SRC:.c=.o)
AUTH_OBJ     = $(AUTH_C_SRC:.c=.o)
WATCH_OBJ    = $(WATCH_C_SRC:.c=.o)
KEYSTORE_OBJ = src/keystore/keystore.o
ESF_M_OBJ    = src/esf/agent.o
MENUBAR_OBJ  = src/menubar/menubar.o
TOUCHID_OBJ  = src/auth/touchid.o

ALL_C_OBJ    = $(COMMON_OBJ) $(FUSE_OBJ) $(ESF_C_OBJ) $(AUTH_OBJ) $(WATCH_OBJ)

# Binaries
CLI_BIN      = onvault
DAEMON_BIN   = onvaultd
TEST_BIN     = tests/test_crypto

.PHONY: all clean test cli daemon

all: $(ALL_C_OBJ) $(KEYSTORE_OBJ) $(ESF_M_OBJ) $(MENUBAR_OBJ) $(TOUCHID_OBJ) $(CLI_BIN) $(DAEMON_BIN) $(TEST_BIN)

# C compilation
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Obj-C compilation
src/keystore/keystore.o: src/keystore/keystore.m
	$(CC) $(OBJCFLAGS) $(INCLUDES) -c $< -o $@

src/esf/agent.o: src/esf/agent.m
	$(CC) $(OBJCFLAGS) $(INCLUDES) -c $< -o $@

src/menubar/menubar.o: src/menubar/menubar.m
	$(CC) $(OBJCFLAGS) $(INCLUDES) -c $< -o $@

src/auth/touchid.o: src/auth/touchid.m
	$(CC) $(OBJCFLAGS) $(INCLUDES) -c $< -o $@

# CLI binary
$(CLI_BIN): src/cli/onvault.c $(COMMON_OBJ) $(AUTH_OBJ) $(KEYSTORE_OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

# Daemon binary (includes all modules)
$(DAEMON_BIN): src/daemon/onvaultd.c $(ALL_C_OBJ) $(KEYSTORE_OBJ) $(ESF_M_OBJ) $(MENUBAR_OBJ) $(TOUCHID_OBJ)
	$(CC) $(OBJCFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS_GUI) $(LDFLAGS_ESF) $(FUSE_LDFLAGS)

TEST_VAULT_BIN = tests/test_vault

# Test binaries
$(TEST_BIN): tests/test_crypto.c $(COMMON_OBJ) $(AUTH_OBJ) $(KEYSTORE_OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

$(TEST_VAULT_BIN): tests/test_vault.c $(COMMON_OBJ) $(FUSE_OBJ) $(ESF_C_OBJ) $(AUTH_OBJ) $(KEYSTORE_OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS) $(FUSE_LDFLAGS)

# Run tests
test: $(TEST_BIN) $(TEST_VAULT_BIN)
	@echo "=== Running crypto tests ==="
	./$(TEST_BIN)
	@echo ""
	@echo "=== Running vault tests ==="
	./$(TEST_VAULT_BIN)

# Distribution build (static linking — no Homebrew needed by end users)
.PHONY: dist install uninstall

dist: LDFLAGS = $(STATIC_LDFLAGS)
dist: LDFLAGS_GUI = $(STATIC_LDFLAGS) -framework Cocoa -framework UserNotifications -framework LocalAuthentication
dist: $(ALL_C_OBJ) $(KEYSTORE_OBJ) $(ESF_M_OBJ) $(MENUBAR_OBJ) $(TOUCHID_OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(CLI_BIN) src/cli/onvault.c \
		src/common/crypto.o src/common/hash.o src/common/memwipe.o src/common/argon2_kdf.o \
		src/common/ipc.o src/common/config.o src/common/log.o src/auth/auth.o src/keystore/keystore.o \
		$(STATIC_LDFLAGS)
	$(CC) $(OBJCFLAGS) $(INCLUDES) -o $(DAEMON_BIN) src/daemon/onvaultd.c \
		$(ALL_C_OBJ) $(KEYSTORE_OBJ) $(ESF_M_OBJ) $(MENUBAR_OBJ) $(TOUCHID_OBJ) \
		$(STATIC_LDFLAGS) -framework Cocoa -framework UserNotifications \
		-framework LocalAuthentication $(FUSE_LDFLAGS) \
		$(if $(filter 1,$(ESF_TBD)),-lEndpointSecurity -lbsm)
	@echo ""
	@echo "=== Distribution build complete ==="
	@echo "Binaries: onvault, onvaultd"
	@echo "No Homebrew dependencies required for end users."
	@echo "Users only need: macFUSE (brew install --cask macfuse)"
	@echo ""
	@# Verify no homebrew dylib dependencies
	@echo "Dynamic library dependencies:"
	@otool -L $(CLI_BIN) | grep -v "/usr/lib\|/System\|@rpath" || echo "  (none — all static)"
	@otool -L $(DAEMON_BIN) | grep -v "/usr/lib\|/System\|@rpath" || echo "  (none — all static)"

install: dist
	install -m 755 $(CLI_BIN) /usr/local/bin/onvault
	install -m 755 $(DAEMON_BIN) /usr/local/bin/onvaultd
	@echo "Installed to /usr/local/bin/"

uninstall:
	rm -f /usr/local/bin/onvault /usr/local/bin/onvaultd
	@echo "Uninstalled from /usr/local/bin/"

clean:
	find src -name "*.o" -delete
	rm -f $(CLI_BIN) $(DAEMON_BIN) $(TEST_BIN) $(TEST_VAULT_BIN) tests/*.o
