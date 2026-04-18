# -------------------------------
# Project directories & binary
# -------------------------------
VERSION      ?= $(shell date +%Y.%m.%d)
BUILD_TIME   ?= $(shell date -u +"%Y-%m-%dT%H:%M:%S")
TAG          ?= v$(VERSION)

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
override VERSION := $(shell date +%Y.%m.%d-%H%M%S)
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
.PHONY: help setup update build run clean git clean-deb clean-rpm distclean check-cli-transport

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

update: ## Update all dependencies
	@echo "🔍 Checking for module updates..."
	go list -m -u all | grep -E '\[|\.'
	go get -u ./...
	go mod tidy
	@echo "✅ Dependencies updated."

# -------------------------------
# Build
# -------------------------------
build: ## Build the binary into ./bin/
	@mkdir -p $(BIN_DIR)
	@echo "→ Building for $(GOOS)/$(GOARCH) (GOAMD64=$(GOAMD64), CGO_ENABLED=$(CGO_ENABLED))"
	env -u GOAMD64 \
	GOOS=$(GOOS) GOARCH=$(GOARCH) GOAMD64=$(GOAMD64) CGO_ENABLED=$(CGO_ENABLED) \
	go build -a \
		-tags netgo,osusergo \
		-ldflags "-X 'main.Version=$(shell date +%Y.%m.%d)' -X 'main.BuildTime=$(shell date +%Y-%m-%dT%H:%M:%S)'" \
		-o $(BINARY) ./$(MAIN_DIR)
	@echo "✅ Built: $(BINARY)"

run: build ## Run the application
	@./$(BINARY)

# -------------------------------
# Clean
# -------------------------------
# Καθαρίζει το binary και ό,τι προσωρινό υπάρχει στο pkgroot
clean:
	@rm -f bin/cfm
	@rm -rf build/pkgroot/DEBIAN
	@rm -rf build/pkgroot/etc
	@rm -rf build/pkgroot/usr
	@rm -rf build/pkgroot/lib
	@rm -f  build/pkgroot/LICENSE
	@echo "🧹 Cleaned: bin, build/pkgroot"

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
		"$(PKGROOT)/etc/cfm" \
		"$(OUTDIR)"

	# copy DEBIAN metadata/scripts
	@cp -a "$(DEB_SRC)/." "$(PKGROOT)/DEBIAN/"
	@sed -i "s/^Version:.*/Version: $(VERSION)-1/" "$(PKGROOT)/DEBIAN/control"

	# payload
	@install -m0755 "$(BIN)" "$(PKGROOT)/usr/bin/cfm"
	@install -m0640 "$(CONFIG_DIR)/cfm.service"   "$(PKGROOT)/lib/systemd/system/cfm.service"
	@install -m0640 "$(CONFIG_DIR)/cfm.conf"      "$(PKGROOT)/etc/cfm/cfm.conf"
	@install -m0640 "$(CONFIG_DIR)/detectors.conf"      "$(PKGROOT)/etc/cfm/detectors.conf"
	@install -m0640 "$(CONFIG_DIR)/notify.conf"      "$(PKGROOT)/etc/cfm/notify.conf"
	@install -m0640 "$(CONFIG_DIR)/cfm.allow"     "$(PKGROOT)/etc/cfm/cfm.allow"
	@install -m0640 "$(CONFIG_DIR)/cfm.deny"      "$(PKGROOT)/etc/cfm/cfm.deny"
	@install -m0640 "$(CONFIG_DIR)/cfm.blocklists" "$(PKGROOT)/etc/cfm/cfm.blocklists"
	@install -m0640 "$(CONFIG_DIR)/cfm.ignore" "$(PKGROOT)/etc/cfm/cfm.ignore"
	@install -m0640 "$(CONFIG_DIR)/cfm.dyndns"    "$(PKGROOT)/etc/cfm/cfm.dyndns"
	@install -m0640 "$(CONFIG_DIR)/cfm-admin.htpasswd" "$(PKGROOT)/etc/cfm/cfm-admin.htpasswd"
	@install -m0640 "$(CONFIG_DIR)/webdetector_malpaths.txt"      "$(PKGROOT)/etc/cfm/webdetector_malpaths.txt"
	@install -m0640 "$(CONFIG_DIR)/webdetector_challenge_paths.txt"      "$(PKGROOT)/etc/cfm/webdetector_challenge_paths.txt"
	@install -m0640 "$(CONFIG_DIR)/webdetector_challenge_exclude.txt"      "$(PKGROOT)/etc/cfm/webdetector_challenge_exclude.txt"



	@rsync -a --delete "$(CONFIG_DIR)/" "$(PKGROOT)/usr/share/cfm/configs/"
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
	@[ -f $(PKGROOT)/etc/cfm/notify.conf ]       || cp -f $(CONFIG_DIR)/notify.conf       $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/cfm.allow ]      || cp -f $(CONFIG_DIR)/cfm.allow      $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/cfm.deny ]       || cp -f $(CONFIG_DIR)/cfm.deny       $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/cfm.blocklists ] || cp -f $(CONFIG_DIR)/cfm.blocklists $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/cfm.ignore ] || cp -f $(CONFIG_DIR)/cfm.ignore $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/cfm.dyndns ]     || cp -f $(CONFIG_DIR)/cfm.dyndns     $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/cfm-admin.htpasswd ] || cp -f $(CONFIG_DIR)/cfm-admin.htpasswd $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/webdetector_malpaths.txt ]       || cp -f $(CONFIG_DIR)/webdetector_malpaths.txt       $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/webdetector_challenge_paths.txt ]       || cp -f $(CONFIG_DIR)/webdetector_challenge_paths.txt       $(PKGROOT)/etc/cfm/
	@[ -f $(PKGROOT)/etc/cfm/webdetector_challenge_exclude.txt ]       || cp -f $(CONFIG_DIR)/webdetector_challenge_exclude.txt       $(PKGROOT)/etc/cfm/


	# === ship ALL example configs ===
	@mkdir -p $(PKGROOT)/usr/share/cfm/configs
	@rsync -a --delete "$(CONFIG_DIR)/" "$(PKGROOT)/usr/share/cfm/configs/"
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

release: deb rpm
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
	# 1) create (no assets). If it exists (422), continue.
	echo "🚀 Ensuring release $(TAG) exists..."; \
	if ! $(GH) release view "$(TAG)" --repo "$$REPO" >/dev/null 2>&1; then \
	  $(GH) release create "$(TAG)" \
	    --repo "$$REPO" \
	    --title "cfm $(TAG)" \
	    --notes "Automated release" \
	    --draft ; \
	  echo "✅ Created draft release $(TAG)."; \
	else \
	  echo "↻ Release $(TAG) already exists."; \
	fi; \
	# 2) upload assets (clobber)
	echo "⬆️  Uploading: $$DEB_FILE $$RPM_FILE"; \
	$(GH) release upload "$(TAG)" "$$DEB_FILE" "$$RPM_FILE" checksums.txt \
	  --repo "$$REPO" --clobber; \
	echo "✅ Assets uploaded."; \
	# 3) publish (optional – only if you want non-draft)
	echo "📣 Publishing release..."; \
	$(GH) release edit "$(TAG)" --repo "$$REPO" --draft=false ; \
	echo "✅ Release $(TAG) published."
