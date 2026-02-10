# Cedar DRT Fuzzing Guide

This guide explains how to use the Cedar Differential Randomized Testing (DRT) fuzzer to test the Cedar WASM compiler against the production Rust implementation and the formally verified Lean specification. It also covers how to use the LLM-driven compiler loop that has Gemini 2.5 Flash iteratively write the compiler.

## Overview

### What is DRT?

DRT (Differential Randomized Testing) is a fuzzing technique that compares multiple implementations of the same specification. In this project, we test three implementations:

1. **Rust Implementation** - The production Cedar policy engine (`cedar-policy` crate)
2. **Lean Specification** - A formally verified mathematical specification of Cedar written in Lean4
3. **WASM Compiler** - A Cedar policy compiler that compiles policies to WebAssembly

For each randomly generated test case (policy + request + entities), the fuzzer runs all three implementations and ensures they produce identical results. If any mismatch is found, the fuzzer crashes and saves the failing test case.

### What is the LLM Compiler Loop?

Inspired by Anthropic's [building a C compiler with Claude](https://www.anthropic.com/engineering/building-c-compiler) approach, we use Gemini 2.5 Flash to iteratively write the Cedar-to-WASM compiler. The loop works like this:

1. Gemini writes (or fixes) the compiler code
2. The code is built with `cargo build`
3. If the build fails, the error is fed back to Gemini
4. If the build succeeds, the fuzzer runs and tests the compiler
5. If the fuzzer finds a mismatch, the failing test case is fed back to Gemini
6. Repeat until the fuzzer passes or we hit the iteration/token limit

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
│   │   ├── compiler_engine.rs  # WASM compiler wrapper (compiles + executes per policy)
│   │   └── tests.rs       # Test harness (run_three_way_auth_test)
│   ├── fuzz/
│   │   ├── Cargo.toml     # Fuzz target configuration
│   │   └── fuzz_targets/  # Individual fuzz target files
│   │       ├── abac.rs    # Basic ABAC fuzzing (Rust vs Lean)
│   │       ├── abac-compiler.rs  # Three-way fuzzing (Rust vs Lean vs Compiler)
│   │       └── ...        # Many other specialized targets
│   ├── build_lean_lib.sh  # Builds Lean libraries to static C libs
│   ├── set_env_vars.sh    # Sets LEAN_LIB_DIR, LD/DYLD_LIBRARY_PATH
│   └── Cargo.toml
├── cedar-lean/            # Lean4 formal specification
├── cedar-lean-ffi/        # FFI bindings to call Lean from Rust
├── cedar-policy-compiler/ # Cedar-to-WASM compiler crate
│   ├── src/lib.rs         # Compiler implementation (Gemini writes this)
│   ├── prompt.md          # System prompt for Gemini (the compiler spec)
│   └── Cargo.toml
├── cedar/                 # Clone of cedar-policy/cedar (not tracked in git)
├── llm_compiler.py        # Orchestration script for the Gemini loop
├── llm_compiler_logs/     # Per-iteration logs (not tracked in git)
└── Dockerfile             # Container setup
```

## Local Setup (macOS)

This section covers setting up the full DRT toolchain locally. If you prefer Docker, skip to [Docker Setup](#docker-setup).

### Prerequisites

You need:
- **Rust** (nightly toolchain for fuzzing)
- **Lean 4** (via elan)
- **protoc** (Protocol Buffers compiler)
- **cargo-fuzz**

### Step 1: Install Dependencies

```bash
# Install cargo-fuzz (if not already installed)
cargo install cargo-fuzz

# Install protoc (macOS)
brew install protobuf

# Install elan (Lean version manager) if not already installed
curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh
```

### Step 2: Clone the Cedar Repository

The DRT framework depends on a specific commit of the `cedar` repo. This must be cloned into the `cedar-spec/` root:

```bash
cd /path/to/cedar-spec
git clone https://github.com/cedar-policy/cedar
cd cedar && git checkout 09e6690
cd ..
```

### Step 3: Build the Lean Libraries

The Lean formal specification must be compiled to static C libraries so Rust can call it via FFI:

```bash
cd cedar-lean
lake update
lake build Cedar:static Protobuf:static CedarProto:static Cedar.SymCC:static CedarFFI:static Batteries:static
cd ..
```

This builds ~868 Lean modules and takes a while on first run. Subsequent builds are incremental.

### Step 4: Set Environment Variables

Before building or fuzzing, set the Lean library paths in your current shell:

```bash
cd cedar-drt
source ./set_env_vars.sh
```

This sets `LEAN_LIB_DIR` and `DYLD_LIBRARY_PATH` (macOS) / `LD_LIBRARY_PATH` (Linux) so the linker can find the Lean static libraries.

### Step 5: Build the Fuzz Target

```bash
cd cedar-drt
cargo fuzz build abac-compiler -s none
```

The `-s none` flag disables sanitizers (which require extra setup). Once this succeeds, the fuzzer binary is ready.

### Step 6: Run the Fuzzer

```bash
# Run for 30 seconds
cargo fuzz run abac-compiler -s none -- -max_total_time=30

# Run for 5 minutes
cargo fuzz run abac-compiler -s none -- -max_total_time=300

# Run indefinitely (Ctrl+C to stop)
cargo fuzz run abac-compiler -s none
```

If the compiler has bugs, the fuzzer will crash with a mismatch and save the failing input to `fuzz/artifacts/abac-compiler/`. The test case (policy, request, entities) is also written to `fuzz/artifacts/abac-compiler/last_test.txt` before each test runs.

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

## LLM Compiler Loop

The `llm_compiler.py` script builds and fuzzes the compiler in an automated loop, having an LLM write and fix the code. It supports two providers:

- **Claude** (`--provider claude`, default): Uses the `claude` CLI (Claude Code). No API key needed — uses your Max subscription.
- **Gemini** (`--provider gemini`): Uses Gemini 2.5 Flash via API with free-tier rate limiting and token tracking.

There's also a **manual mode** (`--manual`) that just builds + fuzzes without any LLM calls.

### Running with Claude Code (default)

No API key or package install needed — just have Claude Code installed:

```bash
# Run with Claude Sonnet (default)
python3 llm_compiler.py

# Use a different Claude model
python3 llm_compiler.py --model claude-opus-4-20250514

# Custom settings
python3 llm_compiler.py --max-iterations 30 --fuzz-timeout 20 --verbose
```

### Running with Gemini

```bash
pip install google-genai
export GEMINI_API_KEY=your_key_here

python3 llm_compiler.py --provider gemini
```

The Gemini provider enforces free-tier rate limits:
- **10 requests per minute** (7s sleep between calls)
- **250 requests per day** (`--max-requests`, default 200)

### Manual Mode (no LLM calls)

Edit `cedar-policy-compiler/src/lib.rs` yourself, then test:

```bash
python3 llm_compiler.py --manual
python3 llm_compiler.py --manual --fuzz-timeout 60
```

### CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `--manual` | off | Build + fuzz only, no LLM calls |
| `--provider` | `claude` | `claude` (via CLI) or `gemini` (via API) |
| `--model` | auto | `claude-sonnet-4-20250514` for claude, `gemini-2.5-flash` for gemini |
| `--max-iterations` | `50` | Max LLM improvement rounds |
| `--max-requests` | `200` | Hard stop on API calls (gemini only) |
| `--fuzz-timeout` | `30` | Seconds to fuzz per iteration |
| `--build-mode` | `local` | `local` or `docker` |
| `--docker-container` | `thia_compiler` | Docker container name (for docker mode) |
| `--log-dir` | `./llm_compiler_logs` | Where to save per-iteration artifacts |
| `--prompt-file` | `./cedar-policy-compiler/prompt.md` | System prompt for the LLM |
| `--compiler-dir` | `./cedar-policy-compiler` | Path to the compiler crate |
| `--verbose` | off | Print full prompts and responses |

### How the Automated Loop Works

Each iteration follows this cycle:

1. **Read** the current compiler source code
2. **Build a prompt** — on the first run, asks Gemini to implement the compiler from scratch. On subsequent runs, includes build errors or fuzz failure details
3. **Call Gemini** — sends the system prompt (`prompt.md`) and user message, tracks tokens
4. **Parse the response** — extracts ```rust and ```toml code blocks
5. **Write the code** to `cedar-policy-compiler/src/lib.rs` (and optionally `Cargo.toml`)
6. **Build** with `cargo build`
7. If build fails → go to step 2 with build errors
8. **Fuzz** with `cargo fuzz run abac-compiler`
9. If fuzz fails → go to step 2 with the mismatch details and failing test case
10. If fuzz passes → success!

### Iteration Logs

Every iteration saves artifacts to `llm_compiler_logs/iteration_NNN/`:

```
llm_compiler_logs/
├── iteration_001/
│   ├── prompt.txt         # What we sent to Gemini
│   ├── response.txt       # What Gemini returned
│   ├── lib.rs             # The generated compiler code
│   ├── cargo_toml.toml    # Generated Cargo.toml (if changed)
│   ├── build_output.txt   # Cargo build stdout/stderr
│   ├── fuzz_output.txt    # Fuzzer output (or "SKIPPED" if build failed)
│   └── token_info.json    # Token counts for this call
├── iteration_002/
│   └── ...
└── summary.json           # Cumulative token usage and final status
```

### Editing the Prompt

The system prompt that Gemini sees is at `cedar-policy-compiler/prompt.md`. This file defines:
- The Rust API contract (`Compiler::new()`, `compile_str()`)
- WASM module requirements (`evaluate() -> i64` export)
- Cedar language reference (policy syntax, operators, types)
- A working `wasm-encoder` example for generating WASM
- Output format instructions

You can edit this file to adjust the LLM's approach without modifying `llm_compiler.py`. For example, you might add more example policies, clarify edge cases, or suggest a different WASM generation strategy.

### Token Usage

The script prints token counts after each call and a cumulative summary at the end:

```
Iteration 5/50 — Phase: fuzz_fix
  Tokens this call: in=4,231 out=2,847 thinking=1,205
  Requests: 5/200 | Tokens in: 18,432 | Tokens out: 12,305 | Thinking: 5,890
```

A `summary.json` file is also written to the log directory with total counts.

### The Compiler Crate

The compiler crate at `cedar-policy-compiler/` starts as a stub that returns "not yet implemented". Gemini rewrites `src/lib.rs` (and sometimes `Cargo.toml`) each iteration. The crate must export:

```rust
pub struct Compiler;
impl Compiler {
    pub fn new() -> Self;
    pub fn compile_str(&self, policy_text: &str) -> Result<Vec<u8>, CompileError>;
}
```

The returned `Vec<u8>` is a WASM binary with an exported `evaluate()` function that returns:
- `1` = policy satisfied
- `0` = policy not satisfied
- `2` = evaluation error

The test harness (`compiler_engine.rs`) handles permit/forbid semantics — it compiles and runs each policy individually, then applies Cedar's authorization rules (forbid overrides permit, default deny).

## Further Reading

- [cargo-fuzz documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer options](https://llvm.org/docs/LibFuzzer.html#options)
- [Cedar policy language](https://docs.cedarpolicy.com/)
- [Lean4 theorem prover](https://lean-lang.org/)
- [Building a C compiler with Claude](https://www.anthropic.com/engineering/building-c-compiler) — the inspiration for this approach

## Support

For issues or questions:
- Check the Cedar repository: https://github.com/cedar-policy/cedar
- Check the Cedar spec repository: https://github.com/cedar-policy/cedar-spec
