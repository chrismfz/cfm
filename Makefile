# -------------------------------
# Project directories & binary
# -------------------------------
BIN_DIR := bin
MAIN_DIR := cmd/cfm
BINARY := $(BIN_DIR)/cfm

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
	go build \
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
	@TAG=v$(shell date +%Y.%m.%d-%H%M%S)
	@echo "🚀 Creating release $$TAG..."
	@git tag $$TAG
	@git push origin $$TAG
	@gh release create $$TAG ./bin/cfm \
		-t "cfm $$TAG" -n "Automated release"
	@echo "✅ Release $$TAG created"
