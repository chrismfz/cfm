# -------------------------------
# Project directories & binary
# -------------------------------
VERSION      ?= $(shell date -u +%Y.%m.%d)
BUILD_TIME   ?= $(shell date -u +"%Y-%m-%dT%H:%M:%S")
TAG          ?= v$(VERSION)
# Release date for the CHANGELOG heading — UTC, date-only, always equal to the
# date portion of VERSION/TAG (kept separate because VERSION is overridden to
# carry a -HHMMSS suffix for the .deb below).
REL_DATE     := $(shell date -u +%Y.%m.%d)

RPM_VERSION  := $(shell echo "$(VERSION)" | sed 's/-.*//; s/[^A-Za-z0-9._+~]/./g')
RPM_TS       := $(shell echo "$(BUILD_TIME)" | sed 's/.*T//; s/://g')
RPM_RELEASE  := 1.$(RPM_TS)
RPM_ARCH     := $(shell rpm --eval '%{_arch}')


BIN_DIR := bin
MAIN_DIR := cmd/cfm
BINARY := $(BIN_DIR)/cfm
PKGROOT      ?= build/pkgroot
RPMTOP       ?= packaging/rpm
SPECFILE     ?= $(RPMTOP)/SPECS/cfm.spec
ARCH         ?= x86_64


override ARCH    := amd64
override VERSION := $(shell date -u +%Y.%m.%d-%H%M%S)
override PKGROOT := build/pkgroot
override OUTDIR  := build/deb
BIN := bin/cfm
CONFIG_DIR := configs
SCRIPTS_DIR := scripts
PLUGINS_DIR := plugins
DEB_SRC := packaging/debian/DEBIAN


# --- Remote Sync ---
REMOTE_USER ?= chris
REMOTE_HOST ?= repo.nixpal.com
REMOTE_PORT ?= 65535
REMOTE_DIR  ?= ~/packages/
SYNC_ON_RELEASE ?= 1

# rsync options (ασφαλής default)
RSYNC_FLAGS ?= -av --partial --inplace
SSH_CMD     ?= ssh -p $(REMOTE_PORT)


# -------------------------------
# Go build target config (CPU/OS)
# -------------------------------
GOOS    ?= linux
GOARCH  ?= amd64
GOAMD64 ?= v1
GOAMD64 := $(strip $(GOAMD64))
CGO_ENABLED ?= 0
# v1=vintage (μέγιστη συμβατότητα), v2, v3, v4

# -------------------------------
# Phony targets
# -------------------------------
.PHONY: help setup update build run clean git clean-deb clean-rpm distclean check-cli-transport lua test-lua test-js verify-bpf-bindings

# -------------------------------
# Help
# -------------------------------
help: ## Show this help message
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""

# -------------------------------
# Setup
# -------------------------------
setup: ## First-time setup after git clone
	go mod tidy
	@echo "✅ Setup complete."


check-cli-transport: ## Verify CLI runtime HTTP transport consistency (clihttp)
	@./scripts/check_cli_transport.sh


LUA_CONFIG_SOURCES := $(wildcard configs/lua/*.lua)

lua: ## Syntax-check production Lua configs under configs/lua/
	@command -v luajit >/dev/null 2>&1 || { echo "❌ luajit is required for 'make lua' but was not found in PATH."; exit 1; }
	@[ -n "$(LUA_CONFIG_SOURCES)" ] || { echo "❌ No Lua config files found at configs/lua/*.lua"; exit 1; }
	@echo "→ Validating Lua syntax for production configs (via luajit; OpenResty/Angie embed LuaJIT, not standalone Lua 5.1):"
	@printf '%s\n' $(LUA_CONFIG_SOURCES)
	@for f in $(LUA_CONFIG_SOURCES); do \
		echo "Checking $$f"; \
		luajit -bl "$$f" >/dev/null || exit $$?; \
	done
	@echo "✅ Lua syntax checks passed."

LUA_TESTS := $(wildcard scripts/tests/*_test.lua)

JS_TESTS := $(shell find internal/webui/static/assets -type f \( -name '*.test.js' -o -name '*.test.cjs' \) 2>/dev/null | sort)

test-js: ## Run cfm-admin JS unit tests (internal/webui/static/assets/**/*.test.{js,cjs}) with node --test
	@command -v node >/dev/null 2>&1 || { echo "❌ node is required for 'make test-js' but was not found in PATH."; exit 1; }
	@[ -n "$(JS_TESTS)" ] || { echo "❌ No JS tests found under internal/webui/static/assets/"; exit 1; }
	@echo "→ Running JS tests (node --test, $(words $(JS_TESTS)) files):"
	@node --test $(JS_TESTS)

test-lua: ## Run Lua unit tests under scripts/tests/*_test.lua
	@command -v luajit >/dev/null 2>&1 || { echo "❌ luajit is required for 'make test-lua' but was not found in PATH."; exit 1; }
	@[ -n "$(LUA_TESTS)" ] || { echo "❌ No Lua tests found at scripts/tests/*_test.lua"; exit 1; }
	@echo "→ Running Lua tests:"
	@failed=0; for f in $(LUA_TESTS); do \
		echo "  $$f"; \
		luajit "$$f" || failed=$$((failed + 1)); \
	done; \
	if [ $$failed -gt 0 ]; then \
		echo "❌ $$failed Lua test file(s) failed."; exit 1; \
	else \
		echo "✅ Lua tests passed."; \
	fi

update: ## Update all dependencies
	@echo "🔍 Checking for module updates..."
	go list -m -u all | grep -E '\[|\.'
	go get -u ./...
	go mod tidy
	@echo "✅ Dependencies updated."

# -------------------------------
# Build
# -------------------------------
# Pre-build guard: cross-check the bpf2go-generated Go bindings in
# internal/lsm/cfmlsm_*_bpfel.go against the .o files they //go:embed.
# Pure Go (no clang dependency), runs in milliseconds. Refuses to
# build if cfmlsm.bpf.c was edited but the .o was never regenerated
# (or vice versa) — the failure mode that produced the runtime error
# `field CfmCred003: unknown program cfm_cred003` after PR #863.
verify-bpf-bindings: ## Verify embedded .o matches the bpf2go Go bindings (catches stale BPF bytecode)
	@echo "→ Verifying internal/lsm/cfmlsm_*_bpfel.{go,o} are in sync"
	@go run ./scripts/verify-bpf-bindings

build: verify-bpf-bindings ## Build the binary into ./bin/
	@mkdir -p $(BIN_DIR)
	@echo "→ Building for $(GOOS)/$(GOARCH) (GOAMD64=$(GOAMD64), CGO_ENABLED=$(CGO_ENABLED))"
	env -u GOAMD64 \
	GOOS=$(GOOS) GOARCH=$(GOARCH) GOAMD64=$(GOAMD64) CGO_ENABLED=$(CGO_ENABLED) \
	go build -a \
		-tags netgo,osusergo \
		-ldflags "-X 'main.Version=$(shell date -u +%Y.%m.%d)' -X 'main.BuildTime=$(shell date -u +%Y-%m-%dT%H:%M:%S)'" \
		-o $(BINARY) ./$(MAIN_DIR)
	@echo "✅ Built: $(BINARY)"

bpf: ## Regenerate cfm-lsm BPF objects (contributors only; needs clang + libbpf-dev)
	@command -v clang >/dev/null 2>&1 || { \
	  echo "✗ clang not found."; \
	  echo "    Debian/Ubuntu:           apt install clang"; \
	  echo "    EL10 (Alma/Rocky/CS10):  dnf install epel-release && dnf install clang18"; \
	  echo "    EL9  (Alma/Rocky/CS9):   dnf install epel-release && dnf install clang"; \
	  exit 1; }
	@test -f /usr/include/bpf/bpf_helpers.h \
	  || test -f /usr/include/x86_64-linux-gnu/bpf/bpf_helpers.h \
	  || { echo "✗ libbpf headers missing."; \
	       echo "    Debian/Ubuntu: apt install libbpf-dev"; \
	       echo "    EL9 / EL10:    dnf config-manager --set-enabled crb && dnf install libbpf-devel"; \
	       exit 1; }
	@echo "→ Regenerating cfm-lsm BPF objects via bpf2go"
	go generate ./internal/lsm/...
	@echo "✅ BPF objects regenerated. Review the diff:"
	@echo "    git status -- internal/lsm/cfmlsm_*.o internal/lsm/cfmlsm_*.go"
	@echo "    git diff   -- internal/lsm/cfmlsm_*.go"
	@echo "Commit the regenerated artifacts alongside your .bpf.c changes so"
	@echo "downstream builds (go build, deb, rpm) keep working without clang."

run: build ## Run the application
	@./$(BINARY)

# -------------------------------
# Clean
# -------------------------------
# Καθαρίζει το binary και τα staged package payload directories
clean:
	@test -n "$(PKGROOT)" && test "$(PKGROOT)" != "/"
	@rm -f "$(BINARY)"
	@rm -rf "$(PKGROOT)/DEBIAN"
	@rm -rf "$(PKGROOT)/etc"
	@rm -rf "$(PKGROOT)/usr"
	@rm -rf "$(PKGROOT)/lib"
	@rm -rf "$(PKGROOT)/var/lib/cfm/lua"
	@rm -f  "$(PKGROOT)/LICENSE"
	@echo "🧹 Cleaned: $(BINARY), staged package payload under $(PKGROOT)"

# Καθαρίζει DEB artifacts (deb πακέτα + staging)
clean-deb:
	@rm -rf build/deb
	@rm -f  build/*.deb build/deb/*.deb build/deb/*/*.deb
	@# προαιρετικά: καθάρισε και ό,τι deb έμεινε κάπου αλλού
	@find build -maxdepth 2 -type f -name '*.deb' -delete 2>/dev/null || true
	@echo "🧹 Cleaned: deb artifacts"

# Καθαρίζει RPM artifacts αλλά ΔΕΝ αγγίζει SPECS/
clean-rpm:
	@rm -rf packaging/rpm/BUILD packaging/rpm/BUILDROOT
	@rm -rf packaging/rpm/RPMS packaging/rpm/SRPMS packaging/rpm/SOURCES
	@# αν έχεις αλλάξει το ARCH folder name, σβήσ’ τα όλα:
	@find packaging/rpm -type f -name '*.rpm' -delete 2>/dev/null || true
	@echo "🧹 Cleaned: rpm artifacts (kept SPECS/)"

# Πλήρες cleanup (ό,τι κάνει το clean + deb + rpm)
distclean: clean clean-deb clean-rpm
	@echo "🧨 Distclean done"



# -------------------------------
# Git helper
# -------------------------------
git: ## Commit + push με προσαρμοσμένο μήνυμα
	@read -p "Enter commit message: " MSG && \
	git add . && \
	git commit -m "$$MSG" && \
	git push


deb: build
	@echo "PKGROOT=[$(PKGROOT)] OUTDIR=[$(OUTDIR)]"
	@test -n "$(PKGROOT)" && test -n "$(OUTDIR)"
	@rm -rf "$(PKGROOT)" && mkdir -p "$(PKGROOT)/DEBIAN" \
		"$(PKGROOT)/usr/bin" \
		"$(PKGROOT)/lib/systemd/system" \
		"$(PKGROOT)/usr/share/cfm/configs" \
		"$(PKGROOT)/usr/share/cfm/scripts" \
		"$(PKGROOT)/usr/share/cfm/plugins" \
		"$(PKGROOT)/var/lib/cfm/lua" \
		"$(PKGROOT)/etc/cfm" \
		"$(OUTDIR)"
	@chmod 0700 "$(PKGROOT)/etc/cfm"

	# copy DEBIAN metadata/scripts
	@cp -a "$(DEB_SRC)/." "$(PKGROOT)/DEBIAN/"
	@sed -i "s/^Version:.*/Version: $(VERSION)-1/" "$(PKGROOT)/DEBIAN/control"

	# payload
	@install -m0755 "$(BIN)" "$(PKGROOT)/usr/bin/cfm"
	@install -m0640 "$(CONFIG_DIR)/cfm.service"   "$(PKGROOT)/lib/systemd/system/cfm.service"
	@install -m0640 "$(CONFIG_DIR)/cfm.conf"      "$(PKGROOT)/etc/cfm/cfm.conf"
	@install -m0640 "$(CONFIG_DIR)/detectors.conf"      "$(PKGROOT)/etc/cfm/detectors.conf"
	@install -m0600 "$(CONFIG_DIR)/kernsec.conf"        "$(PKGROOT)/etc/cfm/kernsec.conf"
	@install -m0600 "$(CONFIG_DIR)/lsm.conf"            "$(PKGROOT)/etc/cfm/lsm.conf"
	@install -m0640 "$(CONFIG_DIR)/notify.conf"      "$(PKGROOT)/etc/cfm/notify.conf"
	@install -m0640 "$(CONFIG_DIR)/cfm.allow"     "$(PKGROOT)/etc/cfm/cfm.allow"
	@install -m0640 "$(CONFIG_DIR)/cfm.deny"      "$(PKGROOT)/etc/cfm/cfm.deny"
	@install -m0640 "$(CONFIG_DIR)/cfm.blocklists" "$(PKGROOT)/etc/cfm/cfm.blocklists"
	@install -m0640 "$(CONFIG_DIR)/cfm.ignore" "$(PKGROOT)/etc/cfm/cfm.ignore"
	@install -m0600 "$(CONFIG_DIR)/cfm.dnat_bypass" "$(PKGROOT)/etc/cfm/cfm.dnat_bypass"
	@install -m0600 "$(CONFIG_DIR)/cfm.dnat_cpanel_bypass" "$(PKGROOT)/etc/cfm/cfm.dnat_cpanel_bypass"
	@install -m0640 "$(CONFIG_DIR)/cfm.dyndns"    "$(PKGROOT)/etc/cfm/cfm.dyndns"
	@install -m0640 "$(CONFIG_DIR)/cfm-admin.htpasswd" "$(PKGROOT)/etc/cfm/cfm-admin.htpasswd"
	@install -m0640 "$(CONFIG_DIR)/webdetector_malpaths.txt"      "$(PKGROOT)/etc/cfm/webdetector_malpaths.txt"
	@install -m0640 "$(CONFIG_DIR)/webdetector_challenge_paths.txt"      "$(PKGROOT)/etc/cfm/webdetector_challenge_paths.txt"
	@install -m0640 "$(CONFIG_DIR)/webdetector_challenge_exclude.txt"      "$(PKGROOT)/etc/cfm/webdetector_challenge_exclude.txt"



	@rsync -a --delete --exclude "lua/" "$(CONFIG_DIR)/" "$(PKGROOT)/usr/share/cfm/configs/"
	@rsync -a --delete "$(CONFIG_DIR)/lua/" "$(PKGROOT)/var/lib/cfm/lua/"
	@rsync -a --delete "$(SCRIPTS_DIR)/" "$(PKGROOT)/usr/share/cfm/scripts/"
	@rsync -a --delete "$(PLUGINS_DIR)/" "$(PKGROOT)/usr/share/cfm/plugins/"
	# executables
	@chmod 0755 "$(PKGROOT)/DEBIAN/postinst" "$(PKGROOT)/DEBIAN/prerm" "$(PKGROOT)/DEBIAN/postrm" 2>/dev/null || true

	# build artifact -> build/deb/
	@fakeroot dpkg-deb --build "$(PKGROOT)" "$(OUTDIR)/cfm_$(VERSION)-1_$(ARCH).deb"
	@echo "📦 Built: $(OUTDIR)/cfm_$(VERSION)-1_$(ARCH).deb"





stage-pkgroot: build
	@echo "→ Staging into $(PKGROOT)"
	# binary
	@mkdir -p $(PKGROOT)/usr/bin
	@cp -f $(BINARY) $(PKGROOT)/usr/bin/cfm
	# configs
	@mkdir -p $(PKGROOT)/etc/cfm
	@[ -f $(PKGROOT)/etc/cfm/cfm.conf ]       || cp -f $(CONFIG_DIR)/cfm.conf       $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/detectors.conf ]       || cp -f $(CONFIG_DIR)/detectors.conf       $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/kernsec.conf ]         || install -m0600 $(CONFIG_DIR)/kernsec.conf        $(PKGROOT)/etc/cfm/kernsec.conf
	@chmod go-rwx $(PKGROOT)/etc/cfm/kernsec.conf
	@[ -f $(PKGROOT)/etc/cfm/lsm.conf ]             || install -m0600 $(CONFIG_DIR)/lsm.conf            $(PKGROOT)/etc/cfm/lsm.conf
	@chmod go-rwx $(PKGROOT)/etc/cfm/lsm.conf
	@[ -f $(PKGROOT)/etc/cfm/notify.conf ]       || cp -f $(CONFIG_DIR)/notify.conf       $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/cfm.allow ]      || cp -f $(CONFIG_DIR)/cfm.allow      $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/cfm.deny ]       || cp -f $(CONFIG_DIR)/cfm.deny       $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/cfm.blocklists ] || cp -f $(CONFIG_DIR)/cfm.blocklists $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/cfm.ignore ] || cp -f $(CONFIG_DIR)/cfm.ignore $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/cfm.dnat_bypass ] || cp -f $(CONFIG_DIR)/cfm.dnat_bypass $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/cfm.dnat_cpanel_bypass ] || cp -f $(CONFIG_DIR)/cfm.dnat_cpanel_bypass $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/cfm.dyndns ]     || cp -f $(CONFIG_DIR)/cfm.dyndns     $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/cfm-admin.htpasswd ] || cp -f $(CONFIG_DIR)/cfm-admin.htpasswd $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/webdetector_malpaths.txt ]       || cp -f $(CONFIG_DIR)/webdetector_malpaths.txt       $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/webdetector_challenge_paths.txt ]       || cp -f $(CONFIG_DIR)/webdetector_challenge_paths.txt       $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/webdetector_challenge_exclude.txt ]       || cp -f $(CONFIG_DIR)/webdetector_challenge_exclude.txt       $(PKGROOT)/etc/cfm/


	# === ship ALL example configs ===
	@mkdir -p $(PKGROOT)/usr/share/cfm/configs
	@mkdir -p $(PKGROOT)/var/lib/cfm/lua
	@rsync -a --delete --exclude "lua/" "$(CONFIG_DIR)/" "$(PKGROOT)/usr/share/cfm/configs/"
	@rsync -a --delete "$(CONFIG_DIR)/lua/" "$(PKGROOT)/var/lib/cfm/lua/"
	@mkdir -p $(PKGROOT)/usr/share/cfm/scripts
	@rsync -a --delete "$(SCRIPTS_DIR)/" "$(PKGROOT)/usr/share/cfm/scripts/"
	@mkdir -p $(PKGROOT)/usr/share/cfm/plugins
	@rsync -a --delete "$(PLUGINS_DIR)/" "$(PKGROOT)/usr/share/cfm/plugins/"

	# systemd unit (RPM-friendly path)
	@mkdir -p $(PKGROOT)/usr/lib/systemd/system
	@cp -f $(CONFIG_DIR)/cfm.service $(PKGROOT)/usr/lib/systemd/system/cfm.service


rpm_prep_dirs:
	@mkdir -p $(RPMTOP)/{BUILD,BUILDROOT,RPMS,SRPMS,SPECS,SOURCES}

rpm_spec_version:
	@sed -i 's/^Version:.*/Version:        $(RPM_VERSION)/' $(SPECFILE)
	@sed -i 's/^Release:.*/Release:        $(RPM_RELEASE)%{?dist}/' $(SPECFILE)


.PHONY: stage-rpm
stage-rpm: stage-pkgroot
	@echo "→ Staging RPM systemd unit"
	@mkdir -p $(PKGROOT)/usr/lib/systemd/system
	@cp -f $(CONFIG_DIR)/cfm.service $(PKGROOT)/usr/lib/systemd/system/cfm.service



# --- RPM (.rpm) --- (μόνο η τελευταία γραμμή αλλάζει)
rpm: rpm_prep_dirs rpm_spec_version stage-rpm ## Δημιουργεί .rpm
	@# The spec-comment macro trap only bites on EL, i.e. here at release time
	@# and not on ubuntu CI — so check it on the build host too, not just in CI.
	@./scripts/tests/check_rpm_spec_macros.sh
	@echo "→ Creating RPM package: cfm-$(RPM_VERSION)-$(RPM_RELEASE)"
	@rpmbuild \
	  --define "_topdir $(CURDIR)/$(RPMTOP)" \
	  --define "_binary_payload w9.gzdio" \
	  --define "debug_package %{nil}" \
	  --define "pkgroot $(CURDIR)/$(PKGROOT)" \
	  --define "projectroot $(CURDIR)" \
	  --buildroot "$(CURDIR)/$(RPMTOP)/BUILDROOT" \
	  --target $(RPM_ARCH) \
	  -bb $(SPECFILE)
	@echo "✅ RPMs under: $(RPMTOP)/RPMS/$(RPM_ARCH)"




# --- Sync both DEB & RPM to remote repo ---
.PHONY: sync
sync:
	@set -euo pipefail; \
	DEB_FILE="$$(ls -1t build/deb/cfm_*_amd64.deb | head -n1)"; \
	RPM_FILE="$$(ls -1t packaging/rpm/RPMS/*/cfm-*.rpm | head -n1)"; \
	[ -n "$$DEB_FILE" ] || { echo "❌ No .deb package found in build/deb"; exit 1; }; \
	[ -n "$$RPM_FILE" ] || { echo "❌ No .rpm package found in packaging/rpm/RPMS"; exit 1; }; \
	echo "🌐 Syncing to $(REMOTE_USER)@$(REMOTE_HOST):$(REMOTE_DIR)"; \
	$(SSH_CMD) $(REMOTE_USER)@$(REMOTE_HOST) "mkdir -p $(REMOTE_DIR)/deb $(REMOTE_DIR)/rpm"; \
	echo "→ Upload: $$DEB_FILE -> $(REMOTE_DIR)/deb/"; \
	rsync $(RSYNC_FLAGS) -e "$(SSH_CMD)" "$$DEB_FILE" "$(REMOTE_USER)@$(REMOTE_HOST):$(REMOTE_DIR)/deb/"; \
	echo "→ Upload: $$RPM_FILE -> $(REMOTE_DIR)/rpm/"; \
	rsync $(RSYNC_FLAGS) -e "$(SSH_CMD)" "$$RPM_FILE" "$(REMOTE_USER)@$(REMOTE_HOST):$(REMOTE_DIR)/rpm/"; \
	echo "→ Upload: checksums.txt -> $(REMOTE_DIR)/"; \
	if [ -f checksums.txt ]; then \
	  rsync $(RSYNC_FLAGS) -e "$(SSH_CMD)" checksums.txt "$(REMOTE_USER)@$(REMOTE_HOST):$(REMOTE_DIR)/"; \
	fi; \
	echo "✅ Remote sync complete."




.PHONY: release

# at top (or before recipe)
GH := gh

# Release path always regenerates BPF bytecode before packaging so a
# contributor's local oversight (editing cfmlsm.bpf.c without committing
# the refreshed .o) can never reach a published .deb/.rpm. The
# verify-bpf-bindings guard wired into `build:` will then re-validate
# the freshly-regenerated .o against the Go bindings as a sanity check.
# Requires clang + libbpf-devel on the release host (see `make bpf`).
.PHONY: changelog
# Stamp CHANGELOG.md: move [Unreleased] under today's UTC date. Run
# automatically by `release`; also available standalone. Idempotent.
changelog:
	@scripts/stamp-changelog.sh $(REL_DATE)

# release flow: (1) stamp CHANGELOG for today's UTC date; (2) commit & push
# ONLY CHANGELOG.md — never the whole tree, since a release host usually has
# built binaries / compiled BPF objects sitting in the working dir that must
# not be committed; (3) create + publish a tag-only GitHub release (title +
# CHANGELOG notes, NO .deb/.rpm assets; packages ship via `make sync`). Steps 2 and 3
# are each ONE self-contained shell segment — do NOT add a bare `#` comment line
# inside them: a comment without a trailing backslash ends the segment, so the
# shell vars (DEB_FILE/RPM_FILE/REPO/NOTES_FILE) set above it silently vanish and the rest
# runs without `set -e`. (That exact trap masked a broken gh-release publish.)
release: bpf deb rpm
	@scripts/stamp-changelog.sh $(REL_DATE)
	@set -uo pipefail; \
	if git rev-parse --git-dir >/dev/null 2>&1 && [ -n "$$(git status --porcelain -- CHANGELOG.md)" ]; then \
	  echo "📝 Committing CHANGELOG.md (only) for $(REL_DATE)..."; \
	  if git commit -q -m "changelog: stamp $(REL_DATE) release" -- CHANGELOG.md; then \
	    branch="$$(git rev-parse --abbrev-ref HEAD)"; \
	    if [ "$$branch" = "HEAD" ]; then \
	      echo "⚠️  detached HEAD — CHANGELOG committed locally, not pushed."; \
	    elif git push origin "HEAD:$$branch"; then \
	      echo "✅ CHANGELOG committed & pushed to $$branch."; \
	    else \
	      echo "⚠️  push failed — commit is local; run: git push origin HEAD:$$branch"; \
	    fi; \
	  else \
	    echo "⚠️  git commit failed — CHANGELOG stamped but not committed."; \
	  fi; \
	else \
	  echo "📝 CHANGELOG.md unchanged since HEAD — nothing to commit."; \
	fi
	@set -euo pipefail; \
	echo "🔐 Checking GitHub auth..."; \
	$(GH) auth status -h github.com >/dev/null || { echo "Run: gh auth login"; exit 1; }; \
	DEB_FILE="$$(ls -1t build/deb/cfm_*_amd64.deb | head -n1)"; \
	RPM_FILE="$$(ls -1t packaging/rpm/RPMS/*/cfm-*.rpm | head -n1)"; \
	[ -n "$$DEB_FILE" ] || { echo "No .deb package found in build/deb"; exit 1; }; \
	[ -n "$$RPM_FILE" ] || { echo "No .rpm package found in packaging/rpm/RPMS"; exit 1; }; \
	echo "📦 DEB=$$DEB_FILE"; echo "📦 RPM=$$RPM_FILE"; \
	sha256sum "$$DEB_FILE" "$$RPM_FILE" > checksums.txt; \
	REPO="chrismfz/cfm"; \
	NOTES_FILE="$$(mktemp)"; \
	scripts/release-notes.sh $(REL_DATE) > "$$NOTES_FILE"; \
	echo "🚀 Ensuring release $(TAG) exists..."; \
	if ! $(GH) release view "$(TAG)" --repo "$$REPO" >/dev/null 2>&1; then \
	  $(GH) release create "$(TAG)" \
	    --repo "$$REPO" \
	    --title "cfm $(TAG)" \
	    --notes-file "$$NOTES_FILE" \
	    --draft ; \
	  echo "✅ Created draft release $(TAG)."; \
	else \
	  echo "↻ Release $(TAG) already exists."; \
	fi; \
	rm -f "$$NOTES_FILE"; \
	echo "📣 Publishing release (tag + CHANGELOG notes; no .deb/.rpm assets — packages ship via 'make sync')..."; \
	$(GH) release edit "$(TAG)" --repo "$$REPO" --draft=false ; \
	echo "✅ Release $(TAG) published."
