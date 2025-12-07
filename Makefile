# Copyright 2025 COMP2221 Systems Programming
# Mars Rover Memory Allocator Makefile

CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -O2 -fPIC -std=c11
LDFLAGS = -shared
TEST_FLAGS = -L. -lallocator -Wl,-rpath,.

LIB_SRC = allocator.c
TEST_SRC = runme.c
LIB_OBJ = $(LIB_SRC:.c=.o)
TEST_OBJ = $(TEST_SRC:.c=.o)
LIBRARY = liballocator.so
EXECUTABLE = runme

.PHONY: all test clean help build_runme

all: $(LIBRARY) $(EXECUTABLE)
	@echo "Build complete!"
	@echo "Library: $(LIBRARY)"
	@echo "Executable: $(EXECUTABLE)"

$(LIBRARY): $(LIB_OBJ)
	@echo "Building library..."
	$(CC) $(LDFLAGS) -o $@ $^

build_runme: $(EXECUTABLE)

$(EXECUTABLE): $(TEST_OBJ) $(LIBRARY)
	@echo "Building executable..."
	$(CC) -o $@ $(TEST_OBJ) $(TEST_FLAGS)

%.o: %.c allocator.h
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c -o $@ $<

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

clean:
	@echo "Cleaning..."
	rm -f $(LIB_OBJ) $(TEST_OBJ) $(LIBRARY) $(EXECUTABLE)
	rm -f *.o *.so
	@echo "Clean complete!"

help:
	@echo "Targets:"
	@echo "  all   - Build library and executable"
	@echo "  runme - Build executable"
	@echo "  test  - Run test suite"
	@echo "  clean - Remove build artifacts"
	@echo "  help  - Show this message"
