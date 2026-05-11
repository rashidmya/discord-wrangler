# discord-wrangler — Makefile
# v2: NFQUEUE daemon model. Install requires root; daemon runs as system user.

PREFIX     ?= /usr/local
SBINDIR    := $(PREFIX)/sbin
SYSCONFDIR := /etc
UNITDIR    := /etc/systemd/system
SYSUSERDIR := /etc/sysusers.d

CXX        ?= g++
CXXSTD     := -std=c++17
CXXFLAGS   ?= -O2 -g -Wall -Wextra -Werror
LDLIBS     := -lnetfilter_queue -lmnl -lpthread

BUILD      := build
DAEMON     := $(BUILD)/discord-wranglerd

# Source files are added per-task — start with just main.cpp.
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
	$(CXX) $(CXXSTD) $(CXXFLAGS) -Isrc -c $< -o $@

$(DAEMON): $(OBJS)
	@mkdir -p $(dir $@)
	$(CXX) -o $@ $(OBJS) $(LDLIBS)

# ---- tests ----
TEST_CXXFLAGS := -std=c++17 -O0 -g -Wall -Wextra -Werror -Isrc -Itests/unit
TEST_BUILD    := $(BUILD)/tests

UNIT_TESTS    := packet_file flow_table config url rate_limit client cgroup

.PHONY: test test-unit test-integration
test: test-unit test-integration

test-unit: $(addprefix run-test-,$(UNIT_TESTS))

test-integration: $(DAEMON)
	@echo "Integration tests require sudo (raw sockets, nftables). Run individually if needed:"
	@echo "  sudo tests/integration/test_inject.sh"
	@echo "  sudo tests/integration/test_nft.sh"

run-test-%: $(TEST_BUILD)/%_test
	$<

$(TEST_BUILD)/packet_file_test: tests/unit/packet_file_test.cpp tests/unit/main_test.cpp src/direct/packet_file.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(TEST_CXXFLAGS) $^ -o $@

$(TEST_BUILD)/flow_table_test: tests/unit/flow_table_test.cpp tests/unit/main_test.cpp src/direct/flow_table.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(TEST_CXXFLAGS) $^ -lpthread -o $@

$(TEST_BUILD)/config_test: tests/unit/config_test.cpp tests/unit/main_test.cpp src/config.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(TEST_CXXFLAGS) $^ -o $@

$(TEST_BUILD)/url_test: tests/unit/url_test.cpp tests/unit/main_test.cpp src/proxy/url.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(TEST_CXXFLAGS) $^ -o $@

$(TEST_BUILD)/rate_limit_test: tests/unit/rate_limit_test.cpp tests/unit/main_test.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(TEST_CXXFLAGS) $^ -o $@

$(TEST_BUILD)/client_test: tests/unit/client_test.cpp tests/unit/main_test.cpp src/proxy/client.cpp src/proxy/url.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(TEST_CXXFLAGS) $^ -lpthread -o $@

$(TEST_BUILD)/cgroup_test: tests/unit/cgroup_test.cpp tests/unit/main_test.cpp src/proxy/cgroup.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(TEST_CXXFLAGS) $^ -o $@

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
	install -d "$(DESTDIR)/etc/discord-wrangler"
	install -m 0644 share/discord-wrangler.conf.example \
	    "$(DESTDIR)/etc/discord-wrangler/discord-wrangler.conf.example"
	# Don't overwrite an existing conf file.
	if [ ! -f "$(DESTDIR)/etc/discord-wrangler/discord-wrangler.conf" ]; then \
	    install -m 0644 share/discord-wrangler.conf.example \
	        "$(DESTDIR)/etc/discord-wrangler/discord-wrangler.conf"; \
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
	-nft delete table inet discord_wrangler_proxy 2>/dev/null
	-rm -f "$(SBINDIR_INST)/discord-wrangler-cleanup"
	-rm -f "$(DESTDIR)$(PREFIX)/bin/discord-wrangler-launch"
	-rm -f "$(DESTDIR)/etc/discord-wrangler/discord-wrangler.conf.example"
	@echo "(Note: /etc/discord-wrangler/discord-wrangler.conf preserved if you customized it)"
	-rm -f "$(SBINDIR_INST)/discord-wranglerd"
	-rm -rf "$(DOCDIR_INST)"
	-systemctl daemon-reload
	-nft delete table inet discord_wrangler 2>/dev/null
	@echo "Uninstall complete (note: discord-wrangler user kept; remove with: sudo userdel discord-wrangler)"

# ---- integration helpers ----
$(BUILD)/inject_driver: tests/integration/inject_driver.cpp src/direct/inject.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXSTD) -O0 -g -Wall -Wextra -Isrc $^ -o $@

clean:
	rm -rf $(BUILD)
