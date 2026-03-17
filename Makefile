CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -O2
LDFLAGS = -lcrypto

SRC_DIR = src
TEST_DIR = tests
OBJ_DIR = obj
BIN_DIR = bin
COQ_DIR = coq

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

TEST_SRCS = $(wildcard $(TEST_DIR)/bench_*.c $(TEST_DIR)/test_*.c)
TEST_BINS = $(patsubst $(TEST_DIR)/%.c, $(BIN_DIR)/%, $(TEST_SRCS))

# Default targets
all: prep $(OBJS) verify

# Directory preparation
prep:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

# Compile C source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Compile test binaries
$(BIN_DIR)/%: $(TEST_DIR)/%.c $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/test_pqc_mock: LDFLAGS += -Wl,--wrap=malloc -Wl,--wrap=EVP_PKEY_keygen_init -Wl,--wrap=EVP_PKEY_keygen -Wl,--wrap=EVP_MD_CTX_new -Wl,--wrap=EVP_DigestSignInit -Wl,--wrap=EVP_DigestSign -Wl,--wrap=EVP_DigestVerifyInit

# Coq formal verification target
verify:
	@echo "==> Running mechanized proofs in Gallina (Coq)..."
	cd $(COQ_DIR) && coqc -Q . Higgaion HiggaionTypes.v
	cd $(COQ_DIR) && coqc -Q . Higgaion PQCMigration.v
	cd $(COQ_DIR) && coqc -Q . Higgaion Gateway.v

# Main test runner
test: prep $(TEST_BINS)
	@echo "==> Running C cryptographic test suite..."
	@for test in $(TEST_BINS); do \
		echo "Running $$test..."; \
		./$$test || exit 1; \
	done
	@echo "==> All C tests passed."

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	cd $(COQ_DIR) && rm -f *.vo *.glob *.vok *.vos .*.aux

# Code Coverage
coverage: CFLAGS += --coverage
coverage: LDFLAGS += --coverage
coverage: clean test
	@echo "==> Generating coverage report..."
	lcov --capture --directory . --output-file coverage.info
	lcov --remove coverage.info '/usr/*' 'tests/*' --output-file coverage.info
	genhtml coverage.info --output-directory coverage_report
	@echo "Coverage report generated in coverage_report/index.html"

.PHONY: all prep verify test clean coverage
