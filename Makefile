# discord-wrangler — Makefile
# v2: NFQUEUE daemon model. Install requires root; daemon runs as system user.

PREFIX     ?= /usr/local
SBINDIR    := $(PREFIX)/sbin
SYSCONFDIR ?= /etc
UNITDIR    := /etc/systemd/system
SYSUSERDIR := /etc/sysusers.d

# nft(8) binary path baked into the daemon at compile time. Override if your
# distro installs it somewhere other than /usr/sbin (e.g. NixOS, Guix).
NFT_BIN    ?= /usr/sbin/nft

# -Werror is on by default for developer builds; distro packagers (or anyone
# building against a newer compiler that may flag new warnings) can opt out
# with `make WERROR=`.
WERROR     ?= -Werror

# Optional sanitizer build: `make SANITIZE=1`. Combines AddressSanitizer and
# UBSan; mutually exclusive with -O2 (we drop opt level to keep traces useful).
SANITIZE   ?=
ifeq ($(SANITIZE),1)
  CXXOPT    := -O1 -fno-omit-frame-pointer -fsanitize=address,undefined
  LDSAN     := -fsanitize=address,undefined
else
  CXXOPT    := -O2
  LDSAN     :=
endif

CXX        ?= g++
CXXSTD     := -std=c++17
DEFS       := -DDISCORD_WRANGLER_SYSCONFDIR='"$(SYSCONFDIR)"' \
              -DDISCORD_WRANGLER_NFT_BIN='"$(NFT_BIN)"'
CXXFLAGS   ?= $(CXXOPT) -g -Wall -Wextra $(WERROR)
LDLIBS     := -lnetfilter_queue -lmnl -lpthread

BUILD      := build
DAEMON     := $(BUILD)/discord-wranglerd

SRCS       := src/main.cpp \
              src/config.cpp \
              src/proxy/url.cpp \
              src/proxy/client.cpp \
              src/proxy/cgroup.cpp \
              src/proxy/relay.cpp \
              src/proxy/nft.cpp \
              src/direct/inject.cpp \
              src/direct/flow_table.cpp \
              src/direct/nfq_loop.cpp \
              src/direct/packet_file.cpp
OBJS       := $(SRCS:%.cpp=$(BUILD)/%.o)

.PHONY: all clean
all: $(DAEMON)

$(BUILD)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXSTD) $(CXXFLAGS) $(DEFS) -Isrc -c $< -o $@

$(DAEMON): $(OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(LDSAN) -o $@ $(OBJS) $(LDLIBS)

# ---- tests ----
TEST_CXXFLAGS := $(CXXSTD) -O0 -g -Wall -Wextra $(WERROR) -Isrc -Itests/vendor
TEST_BUILD    := $(BUILD)/tests

UNIT_TESTS    := packet_file flow_table config url rate_limit client cgroup

# Per-test extras: additional source files and link flags.
TEST_SRCS_packet_file := src/direct/packet_file.cpp
TEST_SRCS_flow_table  := src/direct/flow_table.cpp
TEST_SRCS_config      := src/config.cpp
TEST_SRCS_url         := src/proxy/url.cpp
TEST_SRCS_rate_limit  :=
TEST_SRCS_client      := src/proxy/client.cpp src/proxy/url.cpp
TEST_SRCS_cgroup      := src/proxy/cgroup.cpp

TEST_LIBS_flow_table  := -lpthread
TEST_LIBS_client      := -lpthread

.PHONY: test test-unit test-integration
test: test-unit test-integration

test-unit: $(addprefix run-test-,$(UNIT_TESTS))

test-integration: $(DAEMON)
	@echo "Integration tests require sudo (raw sockets, nftables). Run individually if needed:"
	@echo "  sudo tests/integration/test_inject.sh"
	@echo "  sudo tests/integration/test_nft.sh"

run-test-%: $(TEST_BUILD)/%_test
	$<

# Single pattern rule for unit tests. Per-test extras come from the
# TEST_SRCS_<name> / TEST_LIBS_<name> variables above.
.SECONDEXPANSION:
$(TEST_BUILD)/%_test: tests/unit/%_test.cpp tests/unit/main_test.cpp $$(TEST_SRCS_%)
	@mkdir -p $(dir $@)
	$(CXX) $(TEST_CXXFLAGS) $(LDSAN) $^ $(TEST_LIBS_$*) -o $@

# ---- install / uninstall ----
QUEUE_NUM   ?= 0
SBINDIR_INST  := $(DESTDIR)$(SBINDIR)
UNITDIR_INST  := $(DESTDIR)$(UNITDIR)
SYSUSERS_INST := $(DESTDIR)$(SYSUSERDIR)
NFTRULES_DIR  := $(DESTDIR)/etc/nftables.d
DOCDIR_INST   := $(DESTDIR)$(PREFIX)/share/doc/discord-wrangler

.PHONY: install uninstall
install: $(DAEMON)
	@if [ -z "$(DESTDIR)" ] && [ "$$(id -u)" != "0" ]; then \
	    echo "install requires root (try: sudo make install)"; exit 1; \
	fi
	install -d "$(SBINDIR_INST)" "$(UNITDIR_INST)" "$(SYSUSERS_INST)" "$(NFTRULES_DIR)" "$(DOCDIR_INST)"
	install -m 0755 "$(DAEMON)" "$(SBINDIR_INST)/discord-wranglerd"
	install -m 0644 README.md "$(DOCDIR_INST)/README.md"
	sed -e 's|@SBINDIR@|$(SBINDIR)|g' \
	    -e 's|@DOCDIR@|$(PREFIX)/share/doc/discord-wrangler|g' \
	    -e 's|@QUEUE_NUM@|$(QUEUE_NUM)|g' \
	    share/discord-wrangler.service.in \
	  > "$(UNITDIR_INST)/discord-wrangler.service"
	chmod 0644 "$(UNITDIR_INST)/discord-wrangler.service"
	install -m 0644 share/discord-wrangler.sysusers.in \
	    "$(SYSUSERS_INST)/discord-wrangler.conf"
	sed -e 's|@QUEUE_NUM@|$(QUEUE_NUM)|g' share/discord-wrangler.nft.in \
	  > "$(NFTRULES_DIR)/discord-wrangler.nft"
	chmod 0644 "$(NFTRULES_DIR)/discord-wrangler.nft"
	install -m 0644 share/discord-wrangler-proxy.nft.in \
	    "$(NFTRULES_DIR)/discord-wrangler-proxy.nft.in"
	install -d "$(DESTDIR)$(SYSCONFDIR)/discord-wrangler"
	install -m 0644 share/discord-wrangler.conf.example \
	    "$(DESTDIR)$(SYSCONFDIR)/discord-wrangler/discord-wrangler.conf.example"
	# Don't overwrite an existing conf file.
	if [ ! -f "$(DESTDIR)$(SYSCONFDIR)/discord-wrangler/discord-wrangler.conf" ]; then \
	    install -m 0644 share/discord-wrangler.conf.example \
	        "$(DESTDIR)$(SYSCONFDIR)/discord-wrangler/discord-wrangler.conf"; \
	fi
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m 0755 share/discord-wrangler-launch  "$(DESTDIR)$(PREFIX)/bin/discord-wrangler-launch"
	install -m 0755 share/discord-wrangler-cleanup "$(SBINDIR_INST)/discord-wrangler-cleanup"
	@if [ -z "$(DESTDIR)" ]; then \
	    systemd-sysusers && \
	    systemctl daemon-reload && \
	    systemctl enable --now discord-wrangler.service && \
	    echo "" && \
	    echo "Installed. Verify: systemctl status discord-wrangler" && \
	    echo "Logs:           journalctl -u discord-wrangler -f"; \
	else \
	    echo "DESTDIR install: skipped systemd/sysusers (rerun without DESTDIR to activate)"; \
	fi

uninstall:
	@if [ "$$(id -u)" != "0" ]; then \
	    echo "uninstall requires root (try: sudo make uninstall)"; exit 1; \
	fi
	-systemctl disable --now discord-wrangler.service 2>/dev/null
	-rm -f "$(UNITDIR_INST)/discord-wrangler.service"
	-rm -f "$(SYSUSERS_INST)/discord-wrangler.conf"
	-rm -f "$(NFTRULES_DIR)/discord-wrangler.nft"
	-rm -f "$(NFTRULES_DIR)/discord-wrangler-proxy.nft.in"
	-$(NFT_BIN) delete table inet discord_wrangler_proxy 2>/dev/null
	-rm -f "$(SBINDIR_INST)/discord-wrangler-cleanup"
	-rm -f "$(DESTDIR)$(PREFIX)/bin/discord-wrangler-launch"
	-rm -f "$(DESTDIR)$(SYSCONFDIR)/discord-wrangler/discord-wrangler.conf.example"
	@echo "(Note: $(SYSCONFDIR)/discord-wrangler/discord-wrangler.conf preserved if you customized it)"
	-rm -f "$(SBINDIR_INST)/discord-wranglerd"
	-rm -rf "$(DOCDIR_INST)"
	-systemctl daemon-reload
	-$(NFT_BIN) delete table inet discord_wrangler 2>/dev/null
	@echo "Uninstall complete (note: discord-wrangler user kept; remove with: sudo userdel discord-wrangler)"

# ---- integration helpers ----
$(BUILD)/inject_driver: tests/integration/inject_driver.cpp src/direct/inject.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXSTD) -O0 -g -Wall -Wextra -Isrc $(DEFS) $^ -o $@

clean:
	rm -rf $(BUILD)
