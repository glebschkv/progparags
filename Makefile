# Makefile for Mars Rover Memory Allocator
# COMP2221 Systems Programming - Summative Assignment
# Copyright 2025 COMP2221 Systems Programming
#
# Targets:
#   all   - Build library and test executable
#   runme - Build test executable (alias for build_runme)
#   test  - Run test suite
#   clean - Remove build artifacts
#   help  - Display available targets

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -O2 -fPIC -std=c11
LDFLAGS = -shared
TEST_FLAGS = -L. -lallocator -Wl,-rpath,.

# Source files
LIB_SRC = allocator.c
TEST_SRC = runme.c
LIB_OBJ = $(LIB_SRC:.c=.o)
TEST_OBJ = $(TEST_SRC:.c=.o)

# Output files
LIBRARY = liballocator.so
EXECUTABLE = runme

# Phony targets (not actual files)
.PHONY: all test clean help build_runme

# Default target: build everything
all: $(LIBRARY) $(EXECUTABLE)
	@echo "Build complete!"
	@echo "Library: $(LIBRARY)"
	@echo "Executable: $(EXECUTABLE)"

# Build the shared library
$(LIBRARY): $(LIB_OBJ)
	@echo "Building library..."
	$(CC) $(LDFLAGS) -o $@ $^

# Alias for building runme executable
build_runme: $(EXECUTABLE)

# Build the test executable
$(EXECUTABLE): $(TEST_OBJ) $(LIBRARY)
	@echo "Building executable..."
	$(CC) -o $@ $(TEST_OBJ) $(TEST_FLAGS)

# Compile source files to object files
%.o: %.c allocator.h
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c -o $@ $<

# Run the test suite
test: $(EXECUTABLE)
	@echo ""
	@echo "============================="
	@echo " Running Test Suite"
	@echo "============================="
	@echo ""
	@echo "Test 1: Basic functionality"
	@echo "-----------------------------"
	./$(EXECUTABLE) --size 8192 --seed 42 --storm 0
	@echo ""
	@echo "Test 2: Light storm"
	@echo "-----------------------------"
	./$(EXECUTABLE) --size 8192 --seed 123 --storm 1
	@echo ""
	@echo "Test 3: Heavy storm"
	@echo "-----------------------------"
	./$(EXECUTABLE) --size 8192 --seed 456 --storm 2
	@echo ""
	@echo "Test 4: Large heap"
	@echo "-----------------------------"
	./$(EXECUTABLE) --size 32768 --seed 789 --storm 0
	@echo ""
	@echo "Test 5: Operations"
	@echo "-----------------------------"
	./$(EXECUTABLE) --size 16384 --seed 999 --storm 1 --ops 100

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -f $(LIB_OBJ) $(TEST_OBJ) $(LIBRARY) $(EXECUTABLE)
	rm -f *.o *.so
	@echo "Clean complete!"

# Display help information
help:
	@echo "Mars Rover Memory Allocator - Build Targets"
	@echo ""
	@echo "Targets:"
	@echo "  all     - Build library and executable (default)"
	@echo "  runme   - Build test executable"
	@echo "  test    - Run test suite"
	@echo "  clean   - Remove build artifacts"
	@echo "  help    - Show this message"
	@echo ""
	@echo "Usage:"
	@echo "  make        - Build everything"
	@echo "  make test   - Run tests"
	@echo "  make clean  - Clean up"
