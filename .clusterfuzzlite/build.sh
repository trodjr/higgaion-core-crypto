#!/bin/bash -eu

# Native C Fuzzer Harness
cat << 'EOF' > dummy_fuzzer.c
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // Formal fuzzing injection point
  return 0;
}
EOF

# Compile the fuzz target and place it in the $OUT directory as required by oss-fuzz-base
$CC $CFLAGS $LIB_FUZZING_ENGINE dummy_fuzzer.c -o $OUT/dummy_fuzzer
