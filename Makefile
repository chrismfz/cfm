# -------------------------------
# Project directories & binary
# -------------------------------
BIN_DIR := bin
MAIN_DIR := cmd/cfm
BINARY := $(BIN_DIR)/cfm
TAG := v$(shell date +%Y-%m-%d-%H%M%S)

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
.PHONY: help setup update build run clean git

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
clean: ## Remove build artifacts
	@rm -rf $(BIN_DIR)
	@echo "🧹 Cleaned: $(BIN_DIR)"

# -------------------------------
# Git helper
# -------------------------------
git: ## Commit + push με προσαρμοσμένο μήνυμα
	@read -p "Enter commit message: " MSG && \
	git add . && \
	git commit -m "$$MSG" && \
	git push

release: build ## Build & create GitHub release with timestamp
	@echo "🚀 Creating release $(TAG)..."
	@git tag "$(TAG)"
	@git push origin "$(TAG)"
	@gh release create "$(TAG)" ./bin/cfm \
		-t "cfm $(TAG)" -n "Automated release"
	@echo "✅ Release $(TAG) created"












override ARCH    := amd64
override VERSION := $(shell date +%Y.%m.%d-%H%M%S)
override PKGROOT := build/pkgroot
override OUTDIR  := build/deb
BIN := bin/cfm
CONFIG_DIR := configs
DEB_SRC := packaging/debian/DEBIAN

deb: build
	@echo "PKGROOT=[$(PKGROOT)] OUTDIR=[$(OUTDIR)]"
	@test -n "$(PKGROOT)" && test -n "$(OUTDIR)"
	@rm -rf "$(PKGROOT)" && mkdir -p "$(PKGROOT)/DEBIAN" \
		"$(PKGROOT)/usr/bin" \
		"$(PKGROOT)/lib/systemd/system" \
		"$(PKGROOT)/etc/cfm" \
		"$(OUTDIR)"

	# copy DEBIAN metadata/scripts
	@cp -a "$(DEB_SRC)/." "$(PKGROOT)/DEBIAN/"
	@sed -i "s/^Version:.*/Version: $(VERSION)-1/" "$(PKGROOT)/DEBIAN/control"

	# payload
	@install -m0755 "$(BIN)" "$(PKGROOT)/usr/bin/cfm"
	@install -m0644 "$(CONFIG_DIR)/cfm.service"   "$(PKGROOT)/lib/systemd/system/cfm.service"
	@install -m0644 "$(CONFIG_DIR)/cfm.conf"      "$(PKGROOT)/etc/cfm/cfm.conf"
	@install -m0644 "$(CONFIG_DIR)/cfm.allow"     "$(PKGROOT)/etc/cfm/cfm.allow"
	@install -m0644 "$(CONFIG_DIR)/cfm.deny"      "$(PKGROOT)/etc/cfm/cfm.deny"
	@install -m0644 "$(CONFIG_DIR)/cfm.blocklists" "$(PKGROOT)/etc/cfm/cfm.blocklists"
	@install -m0644 "$(CONFIG_DIR)/cfm.dyndns"    "$(PKGROOT)/etc/cfm/cfm.dyndns"

	# executables
	@chmod 0755 "$(PKGROOT)/DEBIAN/postinst" "$(PKGROOT)/DEBIAN/prerm" "$(PKGROOT)/DEBIAN/postrm" 2>/dev/null || true

	# build artifact -> build/deb/
	@fakeroot dpkg-deb --build "$(PKGROOT)" "$(OUTDIR)/cfm_$(VERSION)-1_$(ARCH).deb"
	@echo "📦 Built: $(OUTDIR)/cfm_$(VERSION)-1_$(ARCH).deb"


