CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -O2
LDFLAGS = -lcrypto

SRC_DIR = src
TEST_DIR = tests
OBJ_DIR = obj
BIN_DIR = bin
COQ_DIR = verification/coq

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

TEST_SRCS = $(wildcard $(TEST_DIR)/bench_*.c $(TEST_DIR)/test_*.c)
TEST_BINS = $(patsubst $(TEST_DIR)/%.c, $(BIN_DIR)/%, $(TEST_SRCS))

# Default targets (production: PQC-only)
all: prep $(OBJS) verify

# Directory preparation
prep:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

# Compile C source files (production: PQC-only)
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Compile test binaries (HIG-002: allow classical algorithms in test builds)
$(BIN_DIR)/%: $(TEST_DIR)/%.c $(OBJS)
	$(CC) $(CFLAGS) -DHIGGAION_ALLOW_CLASSICAL $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/test_pqc_mock: LDFLAGS += -Wl,--wrap=malloc -Wl,--wrap=EVP_PKEY_keygen_init -Wl,--wrap=EVP_PKEY_keygen -Wl,--wrap=EVP_MD_CTX_new -Wl,--wrap=EVP_DigestSignInit -Wl,--wrap=EVP_DigestSign -Wl,--wrap=EVP_DigestVerifyInit

# Coq formal verification target
verify:
	@echo "==> Running mechanized proofs in Gallina (Coq)..."
	cd $(COQ_DIR) && coqc -Q . Higgaion HiggaionTypes.v
	cd $(COQ_DIR) && coqc -Q . Higgaion PQCMigration.v
	cd $(COQ_DIR) && coqc -Q . Higgaion Gateway.v

# ── Test object/library targets (classical algorithms allowed) ──────
# HIG-002: Test builds permit ED25519 fallback via -DHIGGAION_ALLOW_CLASSICAL.
# Test objects use the SAME filenames as production so that CGO, ctypes,
# and Cargo resolve them via their hardcoded paths unchanged.

obj/pqc_crypto_test.o: src/pqc_crypto.c
	$(CC) $(CFLAGS) -DHIGGAION_ALLOW_CLASSICAL -c $< -o obj/pqc_crypto.o

# Production shared library (PQC-only)
obj/libpqc_crypto.so: src/pqc_crypto.c
	$(CC) $(CFLAGS) -shared -fPIC $< -o $@ $(LDFLAGS)

# Test shared library — output as libpqc_crypto.so so ctypes/Cargo find it
obj/libpqc_crypto_test.so: src/pqc_crypto.c
	$(CC) $(CFLAGS) -DHIGGAION_ALLOW_CLASSICAL -shared -fPIC $< -o obj/libpqc_crypto.so $(LDFLAGS)

# ── Test runners ────────────────────────────────────────────────────

# Main C test runner
test: prep $(TEST_BINS)
	@echo "==> Running C cryptographic test suite..."
	@for test in $(TEST_BINS); do \
		echo "Running $$test..."; \
		./$$test || exit 1; \
	done
	@echo "==> All C tests passed."

# Go: build test object as pqc_crypto.o so CGO hardcoded link finds it
test-go: prep obj/pqc_crypto_test.o
	@echo "==> Running Go CGO integration tests..."
	@cd go && go test -v ./...

# Python: build test SO under the standard name so ctypes finds it
test-python: prep obj/libpqc_crypto_test.so
	@echo "==> Running Python CTypes integration tests..."
	@PYTHONPATH=$(PWD)/python python3 -m unittest discover -v -s python/tests/

# Rust: build test SO under the standard name so Cargo finds it
test-rust: prep obj/libpqc_crypto_test.so
	@echo "==> Running Rust FFI integration tests..."
	@cd rust && LD_LIBRARY_PATH=$(PWD)/obj cargo test

# ── Dynamic Security Analysis ───────────────────────────────────────

# AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan)
sanitize: CFLAGS += -fsanitize=address,undefined -g -O1 -fno-omit-frame-pointer -DHIGGAION_ALLOW_CLASSICAL
sanitize: LDFLAGS += -fsanitize=address,undefined
sanitize: clean test

# Valgrind Memory Leak Checker
valgrind: clean test
	@echo "==> Running Valgrind Memcheck..."
	@for test in $(TEST_BINS); do \
		valgrind --leak-check=full --error-exitcode=1 ./$$test || exit 1; \
	done

# libFuzzer Target
fuzz: clean prep
	clang -g -fsanitize=fuzzer,address -Iinclude src/pqc_crypto.c tests/fuzz_target.c \
		-o $(BIN_DIR)/fuzz_target -lcrypto -DHIGGAION_ALLOW_CLASSICAL

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	cd $(COQ_DIR) && rm -f *.vo *.glob *.vok *.vos .*.aux

# Code Coverage (test mode: classical allowed)
coverage: CFLAGS += --coverage -DHIGGAION_ALLOW_CLASSICAL
coverage: LDFLAGS += --coverage
coverage: clean test
	@echo "==> Generating coverage report..."
	lcov --capture --directory . --output-file coverage.info
	lcov --remove coverage.info '/usr/*' 'tests/*' --output-file coverage.info
	genhtml coverage.info --output-directory coverage_report
	@echo "Coverage report generated in coverage_report/index.html"

.PHONY: all prep verify test test-go test-python test-rust clean coverage
