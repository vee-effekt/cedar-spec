# Cedar Policy Compiler

A compiler for Cedar authorization policies, validated by differential testing against the Rust interpreter and Lean specification.

## Logging

### Harness log

Every call to `is_authorized` on the compiler engine is appended to a log file. This includes the policy text, request, entities, and decision.

- Default path: `compiler_harness.log` (relative to working directory)
- Override: `COMPILER_LOG=/path/to/log cargo fuzz run abac-compiler`

### Failure artifacts

When the compiler or Lean spec disagrees with the Rust interpreter, the failing test case is saved as a directory containing:

- `policy.cedar` -- the policy text
- `entities.json` -- entities in Cedar JSON format
- `test.json` -- request and expected decision in Cedar integration test format

Failure directories:

| Component | Default path | Env var override |
|-----------|-------------|-----------------|
| Compiler | `fuzz/failures/compiler/` | `COMPILER_FAILURES_DIR` |
| Lean | `fuzz/failures/lean/` | `LEAN_FAILURES_DIR` |

### Replaying failures

Re-run all saved compiler failures:

```
cargo test -p cedar-drt --test replay_compiler_failures
```

Or point to a specific directory:

```
COMPILER_FAILURES_DIR=path/to/failures cargo test -p cedar-drt --test replay_compiler_failures
```

## Token usage tracking

Claude Code token usage is tracked via OpenTelemetry. Metrics (input/output/cache tokens, cost per request) are written to local JSONL files.

### Setup

1. Install the OTel collector:

```
# macOS ARM64:
curl -LO https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.145.0/otelcol-contrib_0.145.0_darwin_arm64.tar.gz
tar xzf otelcol-contrib_0.145.0_darwin_arm64.tar.gz
mkdir -p ~/.local/bin && mv otelcol-contrib ~/.local/bin/
```

2. Start the collector:

```
cd cedar-policy-compiler
./start-otel.sh
```

3. Launch Claude Code with telemetry enabled:

```
source cedar-policy-compiler/claude-env.sh
claude
```

Metrics are written to `otel-metrics.jsonl` and logs to `otel-logs.jsonl` in the `cedar-policy-compiler/` directory.

### Managing the collector

```
./start-otel.sh status   # check if running
./start-otel.sh stop     # stop collector
```

### Quick check (no collector needed)

Inside a Claude Code session, run `/cost` to see token usage and cost for the current session.

## Running the fuzzer

```
cd cedar-drt
cargo fuzz run abac-compiler
```

With logging enabled:

```
COMPILER_LOG=compiler.log cargo fuzz run abac-compiler
```
