# ============================================================================
# DEFT-Intruder: Real-time Heuristic Malware Detection System
# 
# Copyright (C) 2025 - Open Source Project
# License: GPL-3.0
# 
# Makefile - Build configuration
# ============================================================================

# Project name
PROJECT = deft-intruder

# Version
VERSION = 1.0.0

# Directories
SRC_DIR = src
INC_DIR = include
BUILD_DIR = build
BIN_DIR = bin

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c11 -O2 -fPIE -fstack-protector-strong
CPPFLAGS = -I$(INC_DIR) -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -DDEFT_EMBEDDED_MODEL
LDFLAGS = -pie -Wl,-z,relro,-z,now
LDLIBS = -lpthread -lm

# Debug build flags
DEBUG_CFLAGS = -g -O0 -DDEBUG -fsanitize=address,undefined
DEBUG_LDFLAGS = -fsanitize=address,undefined

# Source files
SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))

# Header files (for dependency tracking)
HEADERS = $(wildcard $(INC_DIR)/*.h)

# Target executable
TARGET = $(BIN_DIR)/$(PROJECT)

# Installation directories
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
SYSCONFDIR = /etc/$(PROJECT)
LOGDIR = /var/log
RUNDIR = /var/run

# ============================================================================
# Build Rules
# ============================================================================

.PHONY: all clean debug install uninstall test model help

# Default target
all: $(TARGET)

# Create directories
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS) | $(BUILD_DIR)
	@echo "  CC      $<"
	@$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# Link executable
$(TARGET): $(OBJECTS) | $(BIN_DIR)
	@echo "  LD      $@"
	@$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@
	@echo ""
	@echo "Build complete: $@"

# Debug build
debug: CFLAGS += $(DEBUG_CFLAGS)
debug: LDFLAGS += $(DEBUG_LDFLAGS)
debug: clean $(TARGET)
	@echo "Debug build complete"

# Build with embedded model
embedded: CPPFLAGS += -DDEFT_EMBEDDED_MODEL
embedded: all
	@echo "Built with embedded model"

# Clean build artifacts
clean:
	@echo "  CLEAN"
	@rm -rf $(BUILD_DIR) $(BIN_DIR)

# Deep clean (including generated model data)
distclean: clean
	@rm -f $(INC_DIR)/deft_model_data.h
	@rm -f *.bin *.log

# ============================================================================
# Model Training
# ============================================================================

# Train model on EMBER dataset
model:
	@echo "Training ML model..."
	@if [ -f ember_dataset_2018_2.tar.bz2 ]; then \
		echo "Found EMBER dataset archive"; \
		if [ ! -d ember_dataset ]; then \
			echo "Extracting dataset..."; \
			tar -xjf ember_dataset_2018_2.tar.bz2 -C .; \
		fi; \
		python3 train_model.py ember_dataset $(INC_DIR); \
	else \
		echo "EMBER dataset not found, creating sample model..."; \
		python3 train_model.py --sample $(INC_DIR); \
	fi
	@echo "Model training complete"

# Generate sample model (for testing without EMBER)
sample-model:
	@echo "Generating sample model..."
	@python3 train_model.py --sample $(INC_DIR)

# ============================================================================
# Installation
# ============================================================================

# Install to system
install: $(TARGET)
	@echo "Installing $(PROJECT)..."
	@install -d $(DESTDIR)$(BINDIR)
	@install -d $(DESTDIR)$(SYSCONFDIR)
	@install -d $(DESTDIR)$(LOGDIR)
	@install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(PROJECT)
	@if [ -f $(INC_DIR)/deft_model.bin ]; then \
		install -m 644 $(INC_DIR)/deft_model.bin $(DESTDIR)$(SYSCONFDIR)/model.bin; \
	fi
	@if [ -f config/whitelist.txt ]; then \
		install -m 644 config/whitelist.txt $(DESTDIR)$(SYSCONFDIR)/; \
	fi
	@echo "Installation complete"
	@echo ""
	@echo "Run '$(PROJECT) -h' for usage information"

# Install systemd service
install-service:
	@echo "Installing systemd service..."
	@install -d $(DESTDIR)/etc/systemd/system
	@install -m 644 config/deft-intruder.service $(DESTDIR)/etc/systemd/system/
	@systemctl daemon-reload
	@echo "Service installed. Enable with: systemctl enable deft-intruder"

# Uninstall
uninstall:
	@echo "Uninstalling $(PROJECT)..."
	@rm -f $(DESTDIR)$(BINDIR)/$(PROJECT)
	@rm -rf $(DESTDIR)$(SYSCONFDIR)
	@rm -f $(DESTDIR)/etc/systemd/system/deft-intruder.service
	@echo "Uninstallation complete"

# ============================================================================
# Testing
# ============================================================================

# Run basic tests
test: $(TARGET)
	@echo "Running tests..."
	@echo ""
	@echo "Test 1: Help output"
	@$(TARGET) --help > /dev/null && echo "  PASS: Help output"
	@echo ""
	@echo "Test 2: Version output"
	@$(TARGET) --version > /dev/null && echo "  PASS: Version output"
	@echo ""
	@echo "Test 3: Dry-run scan (requires root for full test)"
	@if [ $$(id -u) = 0 ]; then \
		$(TARGET) -s -n && echo "  PASS: Scan completed"; \
	else \
		echo "  SKIP: Requires root"; \
	fi
	@echo ""
	@echo "All tests passed!"

# Run with Valgrind (memory checking)
valgrind: debug
	valgrind --leak-check=full --show-leak-kinds=all $(TARGET) -s -n

# ============================================================================
# Static Analysis
# ============================================================================

# Run cppcheck
cppcheck:
	cppcheck --enable=all --inconclusive --std=c11 \
		-I$(INC_DIR) $(SRC_DIR)/*.c

# Run clang-tidy
clang-tidy:
	clang-tidy $(SRC_DIR)/*.c -- $(CPPFLAGS)

# ============================================================================
# Documentation
# ============================================================================

# Generate documentation (requires doxygen)
docs:
	doxygen Doxyfile

# ============================================================================
# Packaging
# ============================================================================

# Create source tarball
dist:
	@mkdir -p $(PROJECT)-$(VERSION)
	@cp -r src include Makefile README.md LICENSE train_model.py config $(PROJECT)-$(VERSION)/
	@tar -czf $(PROJECT)-$(VERSION).tar.gz $(PROJECT)-$(VERSION)
	@rm -rf $(PROJECT)-$(VERSION)
	@echo "Created $(PROJECT)-$(VERSION).tar.gz"

# ============================================================================
# Help
# ============================================================================

help:
	@echo "DEFT-Intruder Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all           Build the project (default)"
	@echo "  debug         Build with debug symbols and sanitizers"
	@echo "  embedded      Build with embedded ML model"
	@echo "  clean         Remove build artifacts"
	@echo "  distclean     Remove all generated files"
	@echo ""
	@echo "  model         Train ML model on EMBER dataset"
	@echo "  sample-model  Generate sample model (no EMBER required)"
	@echo ""
	@echo "  install       Install to system"
	@echo "  install-service Install systemd service"
	@echo "  uninstall     Remove from system"
	@echo ""
	@echo "  test          Run basic tests"
	@echo "  valgrind      Run with memory checker"
	@echo "  cppcheck      Run static analysis"
	@echo ""
	@echo "  docs          Generate documentation"
	@echo "  dist          Create source tarball"
	@echo "  help          Show this message"
	@echo ""
	@echo "Configuration:"
	@echo "  PREFIX=$(PREFIX)"
	@echo "  CC=$(CC)"
	@echo "  CFLAGS=$(CFLAGS)"
