# Cedar DRT Fuzzing Guide

This guide explains how to use the Cedar Differential Randomized Testing (DRT) fuzzer to test the Cedar WASM compiler against the production Rust implementation and the formally verified Lean specification.

## Overview

### What is DRT?

DRT (Differential Randomized Testing) is a fuzzing technique that compares multiple implementations of the same specification. In this project, we test three implementations:

1. **Rust Implementation** - The production Cedar policy engine (`cedar-policy` crate)
2. **Lean Specification** - A formally verified mathematical specification of Cedar written in Lean4
3. **WASM Compiler** - Your Cedar policy compiler that compiles policies to WebAssembly

For each randomly generated test case (policy + request + entities), the fuzzer runs all three implementations and ensures they produce identical results. If any mismatch is found, the fuzzer crashes and saves the failing test case.

### Why This Matters

- **Finds bugs** in the production Rust code
- **Validates correctness** of your WASM compiler
- **Proves soundness** - The Lean spec is formally proven correct, so agreement means your implementation is correct

## Project Structure

```
cedar-spec/
├── cedar-drt/              # Main DRT fuzzer project
│   ├── src/
│   │   ├── lib.rs         # Exports test engines
│   │   ├── lean_engine.rs # Lean FFI wrapper
│   │   ├── compiler_engine.rs  # Your WASM compiler wrapper
│   │   └── tests.rs       # Test harness (run_three_way_auth_test)
│   ├── fuzz/
│   │   ├── Cargo.toml     # Fuzz target configuration
│   │   └── fuzz_targets/ # Individual fuzz target files
│   │       ├── abac.rs    # Basic ABAC fuzzing (Rust vs Lean)
│   │       ├── abac-compiler.rs  # Three-way fuzzing (Rust vs Lean vs Compiler)
│   │       └── ...        # Many other specialized targets
│   └── Cargo.toml
├── cedar-lean/            # Lean4 formal specification
├── cedar-lean-ffi/        # FFI bindings to call Lean from Rust
├── cedar-policy-compiler/ # Your WASM compiler
└── Dockerfile             # Container setup
```

## Docker Setup

### Building the Container

The Docker container includes:
- Amazon Linux 2023 base
- Rust toolchain (nightly for fuzzing)
- Lean4 theorem prover
- All Cedar dependencies
- Pre-built Lean libraries (compiled to C)
- cargo-fuzz installed

Build command:
```bash
cd /Users/lapwing/Desktop/cedar/cspec
docker build -f Dockerfile . -t cedar_drt --memory=8g
```

**Note**: Building takes ~15-20 minutes. The memory limit prevents OOM during compilation.

### Running the Container

Start a persistent container:
```bash
docker run -d --name thia_compiler --entrypoint tail cedar_drt -f /dev/null
```

This runs the container in the background with a process that keeps it alive.

### Container Management

```bash
# Start the container
docker start thia_compiler

# Stop the container
docker stop thia_compiler

# Remove the container (when done)
docker rm thia_compiler

# View logs
docker logs thia_compiler

# Copy files out of the container
docker cp thia_compiler:/opt/src/cedar-spec/cedar-drt/fuzz/artifacts ./artifacts
```

## Running Fuzz Tests

### 1. Enter the Container

```bash
docker exec -it thia_compiler /bin/bash
```

### 2. Set Up Environment

Every time you enter a new shell, run these commands:

```bash
# Load Rust toolchain into PATH
source /root/.profile

# Navigate to DRT directory
cd /opt/src/cedar-spec/cedar-drt

# Set Lean library paths
source ./set_env_vars.sh
```

**What `set_env_vars.sh` does**:
- Sets `LEAN_LIB_DIR` - Path to compiled Lean C libraries
- Sets `LD_LIBRARY_PATH` - Ensures Lean libraries can be loaded at runtime
- Required for the Lean FFI to work

### 3. Switch to Nightly Rust

Fuzzing requires nightly Rust (for sanitizers):

```bash
rustup default nightly
```

### 4. List Available Fuzz Targets

```bash
cargo fuzz list
```

Common targets:
- `abac` - Basic ABAC fuzzing (Rust vs Lean)
- `abac-compiler` - Three-way testing (Rust vs Lean vs WASM Compiler)
- `validation-drt` - Validator differential testing
- `eval-type-directed` - Type-directed evaluation testing

### 5. Run a Fuzz Target

```bash
# Run for 60 seconds
cargo fuzz run abac-compiler -- -max_total_time=60

# Run for 10 minutes
cargo fuzz run abac-compiler -- -max_total_time=600

# Run indefinitely (Ctrl+C to stop)
cargo fuzz run abac-compiler

# Run with verbose output
cargo fuzz run abac-compiler -- -max_total_time=60 -verbosity=2

# Use multiple cores
cargo fuzz run abac-compiler -- -jobs=4 -max_total_time=600
```

### 6. Understanding Fuzzer Output

```
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1789213583
INFO: Loaded 1 modules   (1650253 inline 8-bit counters)
INFO:        0 files found in /opt/src/cedar-spec/cedar-drt/fuzz/corpus/abac-compiler
#2      INITED cov: 8260 ft: 8226 corp: 1/1b exec/s: 0 rss: 240Mb
#3      NEW    cov: 8277 ft: 8286 corp: 2/3b lim: 4 exec/s: 0 rss: 241Mb L: 2/2 MS: 1 CrossOver-
```

- `cov` - Code coverage (number of code paths explored)
- `ft` - Features (unique behaviors discovered)
- `corp` - Corpus size (number of interesting test cases saved)
- `exec/s` - Executions per second
- `rss` - Memory usage
- `NEW` - Found a new interesting test case
- `REDUCE` - Simplified an existing test case

### 7. Handling Crashes/Mismatches

If the fuzzer finds a disagreement between implementations:

```bash
# Check for crashes
ls -la fuzz/artifacts/abac-compiler/

# View the failing input
cat fuzz/artifacts/abac-compiler/crash-<hash>

# Reproduce the crash
cargo fuzz run abac-compiler fuzz/artifacts/abac-compiler/crash-<hash>
```

The crash will show which implementations disagreed and what the inputs were.

## Environment Variables Reference

### Required Variables (set by `set_env_vars.sh`)

```bash
LEAN_LIB_DIR=/opt/src/cedar-spec/cedar-lean/build/lib
LD_LIBRARY_PATH=/opt/src/cedar-spec/cedar-lean/build/lib:$LD_LIBRARY_PATH
CEDAR_SPEC_ROOT=/opt/src/cedar-spec
```

### Optional Variables

```bash
# Dump failing test cases to files
export DUMP_TEST_NAME=my_test
export DUMP_TEST_DIR=/tmp/test_dumps

# Control Rust logging
export RUST_LOG=debug
export RUST_BACKTRACE=1
```

## Adding New Fuzz Targets

To create a new fuzz target:

### 1. Create the Source File

Create `fuzz/fuzz_targets/my-target.rs`:

```rust
#![no_main]
use cedar_drt::{
    logger::initialize_log,
    tests::run_three_way_auth_test,
    CedarLeanEngine,
    CedarCompilerEngine,
};

use cedar_drt_inner::{abac::FuzzTargetInput, fuzz_target};
use cedar_policy::{Policy, PolicySet, Request};

fuzz_target!(|input: FuzzTargetInput<false>| {
    initialize_log();

    // Set up policy set
    let mut policyset = PolicySet::new();
    let policy = Policy::from(input.policy);
    policyset.add(policy).unwrap();

    // Set up engines
    let lean_engine = CedarLeanEngine::new();
    let compiler_engine = CedarCompilerEngine::new();

    // Test each request
    for request in input.requests.into_iter().map(Request::from) {
        run_three_way_auth_test(
            &lean_engine,
            &compiler_engine,
            &request,
            &policyset,
            &input.entities,
        );
    }
});
```

### 2. Register in Cargo.toml

Add to `fuzz/Cargo.toml`:

```toml
[[bin]]
name = "my-target"
path = "fuzz_targets/my-target.rs"
test = false
doc = false
```

### 3. Build and Run

```bash
cargo fuzz build my-target
cargo fuzz run my-target -- -max_total_time=60
```

## Troubleshooting

### "cargo: command not found"

Solution: Run `source /root/.profile`

### "LEAN_LIB_DIR environment variable is not set"

Solution: Run `source ./set_env_vars.sh`

### "error: the option Z is only accepted on the nightly compiler"

Solution: Run `rustup default nightly`

### "no bin target named X"

Solution: Check that the `[[bin]]` entry exists in `fuzz/Cargo.toml`

### Container exits immediately

Solution: Use `--entrypoint tail cedar_drt -f /dev/null` to keep it running

### Out of memory during build

Solution: Increase Docker memory limit or set `CARGO_BUILD_JOBS=1`

## Quick Reference

```bash
# Complete workflow
docker start thia_compiler
docker exec -it thia_compiler /bin/bash
source /root/.profile
cd /opt/src/cedar-spec/cedar-drt
source ./set_env_vars.sh
rustup default nightly
cargo fuzz list
cargo fuzz run abac-compiler -- -max_total_time=60
```

## Further Reading

- [cargo-fuzz documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer options](https://llvm.org/docs/LibFuzzer.html#options)
- [Cedar policy language](https://docs.cedarpolicy.com/)
- [Lean4 theorem prover](https://lean-lang.org/)

## Support

For issues or questions:
- Check the Cedar repository: https://github.com/cedar-policy/cedar
- Check the Cedar spec repository: https://github.com/cedar-policy/cedar-spec
