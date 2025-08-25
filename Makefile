# Compiler and flags
CC 		:= gcc
CFLAGS 	:= -Wall -Wextra -Iinclude
LDFLAGS := -lssl -lcrypto

# Project structure
SRC_DIR := src
INC_DIR := include
OBJ_DIR := build
BIN_DIR := bin
TARGET	:= $(BIN_DIR)/encryptcli

# Source files
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

# Default target
all: $(TARGET)

# Link object files into final binary
$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compile source files into objects
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Create object directory
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Create bin directory
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Clean build artifacts
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

# Run static analysis
lint:
	cppcheck --enable=all --inconclusive --std=c11 -I$(INC_DIR) $(SRC_DIR)

.PHONY: all clean lint
