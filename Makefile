# Compiler and flags
CC 		:= gcc
CFLAGS 	:= -Wall -Wextra -Iinclude
LDFLAGS := -lssl -lcrypto

# Project structure
SRC_DIR := src
INC_DIR := include
OBJ_DIR := build
BIN_DIR := bin
TEST_DIR := tests

TARGET	:= $(BIN_DIR)/encryptcli

# Source files
SRCS := $(wildcard $(SRC_DIR)/*.c)

# Module objects (all .c files except main.c)
MODULE_OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(filter-out $(SRC_DIR)/main.c, $(SRCS)))

# CLI objects (main.c)
CLI_OBJS := $(OBJ_DIR)/main.o

# Test sources and binaries
TEST_SRCS := $(wildcard $(TEST_DIR)/*.c)
TEST_OBJS := $(patsubst $(TEST_DIR)/%.c, $(OBJ_DIR)/%.test.o, $(TEST_SRCS))
TEST_BINS := $(patsubst $(TEST_DIR)/%.c, $(BIN_DIR)/%, $(TEST_SRCS))

# Default target
all: $(TARGET)

tests: $(TEST_BINS)

# Link main CLI
$(TARGET): $(MODULE_OBJS) $(CLI_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Link unit tests
$(BIN_DIR)/%: $(OBJ_DIR)/%.test.o $(MODULE_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compile module objects
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile CLI object
$(OBJ_DIR)/main.o: $(SRC_DIR)/main.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile test files into objects
$(OBJ_DIR)/%.test.o: $(TEST_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Create directories
$(OBJ_DIR) $(BIN_DIR):
	mkdir -p $@

# Run unit tests
run-tests: tests
	@fail_count=0; \
	for t in $(TEST_BINS); do \
		echo "Running $$t..."; \
		./$$t; \
		if [ $$? -ne 0 ]; then \
			echo "❌ $$t failed"; \
			fail_count=$$((fail_count + 1)); \
		else \
			echo "✅ $$t passed"; \
		fi; \
	done; \
	if [ $$fail_count -ne 0 ]; then \
		echo "$$fail_count test(s) failed"; \
		exit 1; \
	else \
		echo "All tests passed!"; \
	fi

# Clean build artifacts
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

# Run static analysis
lint:
	cppcheck --enable=all --inconclusive --std=c11 -I$(INC_DIR) $(SRC_DIR)

.PHONY: all clean lint run-tests
