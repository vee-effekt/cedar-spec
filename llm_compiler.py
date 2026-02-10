#!/usr/bin/env python3
"""
LLM-driven Cedar-to-WASM compiler generator.

Uses an LLM to iteratively write a Cedar policy compiler,
validated by differential testing against the Cedar Rust interpreter
and Lean specification.

Supports two providers:
  - claude: Uses Claude Code CLI (no API key needed, uses Max subscription)
  - gemini: Uses Gemini 2.5 Flash with free-tier rate limiting

Usage:
    # With Claude Code (default — uses your Max subscription, no API key)
    python3 llm_compiler.py
    python3 llm_compiler.py --model claude-sonnet-4-20250514

    # With Gemini (free tier, tracks tokens)
    export GEMINI_API_KEY=your_key_here
    python3 llm_compiler.py --provider gemini

    # Manual mode — build+fuzz only, no LLM calls
    python3 llm_compiler.py --manual
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# LLM clients
# ---------------------------------------------------------------------------

class ClaudeCodeClient:
    """Uses the Claude Code CLI (`claude -p`). No API key needed — uses your
    Max subscription or whatever auth Claude Code already has."""

    def __init__(self, model: str):
        # Verify claude CLI is available
        try:
            result = subprocess.run(
                ["claude", "--version"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                print("ERROR: `claude --version` failed.")
                sys.exit(1)
        except FileNotFoundError:
            print("ERROR: `claude` CLI not found. Install Claude Code first.")
            sys.exit(1)

        self.model = model
        self.call_count = 0

    def generate(self, system_prompt: str, user_message: str) -> str:
        """Call Claude Code CLI and return the response text."""
        self.call_count += 1

        full_prompt = system_prompt + "\n\n" + user_message

        cmd = ["claude", "-p", full_prompt, "--model", self.model]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 min timeout for long responses
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"claude CLI exited with code {result.returncode}: {result.stderr[:500]}"
            )

        return result.stdout

    def print_status(self):
        print(f"  Claude Code calls: {self.call_count}")


class GeminiClient:
    """Gemini client with token tracking and free-tier rate limiting."""

    def __init__(self, model: str, max_requests: int):
        try:
            from google import genai
            from google.genai import types
        except ImportError:
            print("ERROR: google-genai package not installed.")
            print("  pip install google-genai")
            sys.exit(1)

        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            print("ERROR: GEMINI_API_KEY environment variable not set.")
            sys.exit(1)

        self._genai = genai
        self._types = types
        self.client = genai.Client(api_key=api_key)
        self.model = model
        self.max_requests = max_requests

        # Token tracking
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_thinking_tokens = 0
        self.call_count = 0
        self._last_call_time = 0.0

    def generate(self, system_prompt: str, user_message: str) -> str:
        """Call Gemini and return the response text.

        Enforces rate limiting (10 RPM) and request cap.
        """
        if self.call_count >= self.max_requests:
            raise RuntimeError(
                f"Reached max request limit ({self.max_requests}). "
                f"Stopping to stay within free tier (250 RPD)."
            )

        # Rate limit: at least 7 seconds between calls (< 10 RPM)
        elapsed = time.time() - self._last_call_time
        if elapsed < 7.0:
            sleep_time = 7.0 - elapsed
            print(f"  [rate limit] sleeping {sleep_time:.1f}s...")
            time.sleep(sleep_time)

        self._last_call_time = time.time()

        response = self.client.models.generate_content(
            model=self.model,
            contents=user_message,
            config=self._types.GenerateContentConfig(
                system_instruction=system_prompt,
                temperature=0.2,
                max_output_tokens=65536,
            ),
        )

        # Extract token counts
        usage = response.usage_metadata
        input_tokens = usage.prompt_token_count or 0
        output_tokens = usage.candidates_token_count or 0
        thinking_tokens = getattr(usage, "thinking_token_count", 0) or 0

        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.total_thinking_tokens += thinking_tokens
        self.call_count += 1

        print(f"  Tokens this call: in={input_tokens:,} "
              f"out={output_tokens:,} thinking={thinking_tokens:,}")

        return response.text

    def print_status(self):
        print(f"  Requests: {self.call_count}/{self.max_requests} | "
              f"Tokens in: {self.total_input_tokens:,} | "
              f"Tokens out: {self.total_output_tokens:,} | "
              f"Thinking: {self.total_thinking_tokens:,}")


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def parse_response(response_text: str) -> dict:
    """Extract code blocks from the LLM response."""
    result = {}

    # Find Cargo.toml block
    toml_match = re.search(r"```toml\s*\n(.*?)```", response_text, re.DOTALL)
    if toml_match:
        result["cargo_toml"] = toml_match.group(1).strip()

    # Find Rust code blocks
    rust_blocks = re.findall(r"```rust\s*\n(.*?)```", response_text, re.DOTALL)
    if rust_blocks:
        # First block is lib.rs by default
        result["lib_rs"] = rust_blocks[0].strip()

        # Additional blocks may specify their filename
        for block in rust_blocks[1:]:
            first_line = block.strip().split("\n")[0]
            file_match = re.match(r"//\s*(?:file:\s*)?(\S+\.rs)", first_line)
            if file_match:
                rel_path = file_match.group(1)
                # Remove the file path comment line from the content
                content = "\n".join(block.strip().split("\n")[1:])
                result.setdefault("extra_files", {})[rel_path] = content

    # Fallback: if no ```rust block found, look for unfenced Rust code
    if "lib_rs" not in result:
        # Check if response looks like raw Rust code
        stripped = response_text.strip()
        if stripped.startswith("use ") or stripped.startswith("pub ") or stripped.startswith("//"):
            result["lib_rs"] = stripped

    return result


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def read_compiler_source(compiler_dir: Path) -> dict:
    """Read all source files from the compiler crate."""
    sources = {}
    src_dir = compiler_dir / "src"
    if src_dir.exists():
        for rs_file in sorted(src_dir.rglob("*.rs")):
            rel_path = str(rs_file.relative_to(compiler_dir))
            sources[rel_path] = rs_file.read_text()

    cargo_toml = compiler_dir / "Cargo.toml"
    if cargo_toml.exists():
        sources["Cargo.toml"] = cargo_toml.read_text()

    return sources


def write_compiler_source(compiler_dir: Path, parsed: dict):
    """Write parsed LLM output to the compiler crate."""
    if "cargo_toml" in parsed:
        (compiler_dir / "Cargo.toml").write_text(parsed["cargo_toml"] + "\n")

    if "lib_rs" in parsed:
        src_dir = compiler_dir / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        (src_dir / "lib.rs").write_text(parsed["lib_rs"] + "\n")

    for rel_path, content in parsed.get("extra_files", {}).items():
        full_path = compiler_dir / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content + "\n")


# ---------------------------------------------------------------------------
# Build and fuzz runners
# ---------------------------------------------------------------------------

def run_command(cmd, cwd=None, timeout=120, mode="local", container=None):
    """Run a command locally or in Docker. Returns (returncode, stdout, stderr)."""
    if mode == "docker":
        docker_cmd = ["docker", "exec"]
        if cwd:
            docker_cmd += ["-w", cwd]
        docker_cmd += [container] + cmd
        actual_cmd = docker_cmd
        actual_cwd = None
    else:
        actual_cmd = cmd
        actual_cwd = cwd

    try:
        result = subprocess.run(
            actual_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=actual_cwd,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError as e:
        return -1, "", f"Command not found: {e}"


def sync_to_docker(compiler_dir: Path, container: str):
    """Copy local compiler crate into the Docker container."""
    remote_path = "/opt/src/cedar-spec/cedar-policy-compiler"
    subprocess.run(
        ["docker", "cp", str(compiler_dir) + "/.", f"{container}:{remote_path}"],
        check=True,
    )


def run_build(cedar_spec_root: Path, mode: str, container: str) -> tuple:
    """Build the compiler crate. Returns (success, output)."""
    if mode == "docker":
        cwd = "/opt/src/cedar-spec"
    else:
        cwd = str(cedar_spec_root)

    cmd = ["cargo", "build", "--manifest-path", "cedar-policy-compiler/Cargo.toml"]
    rc, stdout, stderr = run_command(cmd, cwd=cwd, timeout=120, mode=mode, container=container)

    output = (stdout + "\n" + stderr).strip()
    return rc == 0, output


def run_fuzz(cedar_spec_root: Path, fuzz_timeout: int, mode: str, container: str) -> tuple:
    """Run the abac-compiler fuzz target. Returns (passed, output)."""
    if mode == "docker":
        cwd = "/opt/src/cedar-spec/cedar-drt"
        cmd = [
            "bash", "-c",
            f"source /root/.profile && source ./set_env_vars.sh && "
            f"cargo fuzz run abac-compiler -s none -- -max_total_time={fuzz_timeout} 2>&1"
        ]
    else:
        cwd = str(cedar_spec_root / "cedar-drt")
        cmd = [
            "cargo", "fuzz", "run", "abac-compiler", "-s", "none",
            "--", f"-max_total_time={fuzz_timeout}",
        ]

    rc, stdout, stderr = run_command(
        cmd, cwd=cwd, timeout=fuzz_timeout + 120, mode=mode, container=container
    )
    output = (stdout + "\n" + stderr).strip()

    if rc == 0:
        return True, output

    # Extract failure info
    failure_info = extract_fuzz_failure(output, cedar_spec_root, mode, container)
    return False, failure_info


def extract_fuzz_failure(output: str, cedar_spec_root: Path, mode: str, container: str) -> str:
    """Parse fuzzer output to extract actionable failure information."""
    lines = output.split("\n")
    failure_lines = []

    # Look for key failure patterns
    capture = False
    for line in lines:
        if any(kw in line for kw in [
            "panicked at", "assertion", "Mismatch", "Compiler error",
            "SUMMARY: libFuzzer", "Failed to compile", "Failed to execute",
            "thread", "ERROR:",
        ]):
            capture = True
        if capture:
            failure_lines.append(line)
            if len(failure_lines) > 60:
                break

    # Read the last_test.txt artifact if available (local mode only)
    artifact_path = (
        cedar_spec_root / "cedar-drt" / "fuzz" / "artifacts"
        / "abac-compiler" / "last_test.txt"
    )
    if mode == "local" and artifact_path.exists():
        try:
            test_content = artifact_path.read_text()
            if test_content.strip():
                failure_lines.append("\n--- Last test case ---")
                failure_lines.append(test_content[:2000])
        except Exception:
            pass

    if failure_lines:
        return "\n".join(failure_lines)

    # Fallback: return tail of output
    return output[-3000:]


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def save_iteration(log_dir: Path, iteration: int, prompt: str, response: str,
                   parsed: dict, build_output: str, fuzz_output: str):
    """Save all artifacts for one iteration."""
    iter_dir = log_dir / f"iteration_{iteration:03d}"
    iter_dir.mkdir(parents=True, exist_ok=True)

    (iter_dir / "prompt.txt").write_text(prompt)
    (iter_dir / "response.txt").write_text(response)
    if "lib_rs" in parsed:
        (iter_dir / "lib.rs").write_text(parsed["lib_rs"])
    if "cargo_toml" in parsed:
        (iter_dir / "cargo_toml.toml").write_text(parsed["cargo_toml"])
    (iter_dir / "build_output.txt").write_text(build_output)
    (iter_dir / "fuzz_output.txt").write_text(fuzz_output)


def save_summary(log_dir: Path, client, final_iteration: int, final_phase: str):
    """Save cumulative summary."""
    summary = {
        "total_iterations": final_iteration,
        "final_phase": final_phase,
        "total_api_calls": client.call_count,
        "model": client.model,
        "timestamp": datetime.now().isoformat(),
    }
    # Add token info if available (Gemini)
    for attr in ("total_input_tokens", "total_output_tokens", "total_thinking_tokens"):
        if hasattr(client, attr):
            summary[attr] = getattr(client, attr)
    (log_dir / "summary.json").write_text(json.dumps(summary, indent=2))


# ---------------------------------------------------------------------------
# User message construction
# ---------------------------------------------------------------------------

def build_user_message(phase: str, current_sources: dict, error_context: str) -> str:
    """Build the user message for the current iteration."""
    parts = []

    if phase == "initial":
        parts.append(
            "Please implement the Cedar policy compiler.\n\n"
            "Start with the basics:\n"
            "1. Parse the policy effect: `permit` → the policy can permit, `forbid` → the policy can forbid\n"
            "2. Check for scope constraints (principal ==, in, is; action ==, in; resource ==, in, is)\n"
            "3. Check for `when` and `unless` clauses\n"
            "4. A policy with NO scope constraints and NO when/unless clauses is always satisfied → return 1\n"
            "5. For policies with scope constraints or conditions that reference runtime context "
            "(principal, action, resource, context), return 2 (error) since no context is available\n\n"
            "Use the `wasm-encoder` crate to generate valid WASM. "
            "See the prompt.md for a complete example of generating a constant-returning WASM module.\n"
        )
    elif phase == "build_fix":
        parts.append(
            "The previous code FAILED to compile. "
            "Please fix the build errors and provide the complete updated source.\n\n"
        )
        parts.append(error_context)
    elif phase == "fuzz_fix":
        parts.append(
            "The code compiled successfully, but the fuzzer found a MISMATCH between your "
            "compiler's output and the reference Cedar interpreter.\n\n"
            "Analyze the failure below. The test case shows the policy, request, and entities "
            "that caused the mismatch. Your compiler needs to produce the same authorization "
            "decision as the reference interpreter for this input.\n\n"
        )
        parts.append(error_context)

    # Always include current source
    parts.append("\n\n--- Current Source Code ---\n")
    for filename, content in sorted(current_sources.items()):
        parts.append(f"\n### {filename}\n```\n{content}\n```\n")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Manual mode
# ---------------------------------------------------------------------------

def run_manual(args):
    """Manual mode: build + fuzz the current compiler code, print results."""
    cedar_spec_root = Path(__file__).parent.resolve()
    compiler_dir = (cedar_spec_root / args.compiler_dir).resolve()

    print("=" * 70)
    print("Cedar Compiler — Manual Mode")
    print("=" * 70)
    print(f"  Compiler dir: {compiler_dir}")
    print(f"  Build mode:   {args.build_mode}")
    print(f"  Fuzz timeout: {args.fuzz_timeout}s")
    print()

    # Show current source files
    sources = read_compiler_source(compiler_dir)
    for filename, content in sorted(sources.items()):
        lines = content.count("\n")
        print(f"  {filename}: {lines} lines")
    print()

    # Docker sync
    if args.build_mode == "docker":
        try:
            sync_to_docker(compiler_dir, args.docker_container)
            print("  Synced to Docker container.")
        except subprocess.CalledProcessError as e:
            print(f"ERROR syncing to Docker: {e}")
            sys.exit(1)

    # Build
    print("Building...")
    build_success, build_output = run_build(
        cedar_spec_root, args.build_mode, args.docker_container
    )

    if not build_success:
        print("BUILD FAILED\n")
        print(build_output[-4000:])
        sys.exit(1)

    print("BUILD OK\n")

    # Fuzz
    print(f"Fuzzing for {args.fuzz_timeout}s...")
    fuzz_passed, fuzz_output = run_fuzz(
        cedar_spec_root, args.fuzz_timeout, args.build_mode, args.docker_container
    )

    if fuzz_passed:
        print(f"FUZZ PASSED ({args.fuzz_timeout}s)\n")
        print("The compiler survived the fuzzer. Try increasing --fuzz-timeout")
        print("for more confidence, or declare victory!")
        sys.exit(0)

    print("FUZZ FAILED — mismatch found\n")
    print(fuzz_output)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Automated mode
# ---------------------------------------------------------------------------

def run_auto(args):
    """Automated mode: LLM writes the compiler in a build/fuzz/fix loop."""
    cedar_spec_root = Path(__file__).parent.resolve()
    compiler_dir = (cedar_spec_root / args.compiler_dir).resolve()
    log_dir = (cedar_spec_root / args.log_dir).resolve()
    prompt_file = (cedar_spec_root / args.prompt_file).resolve()

    log_dir.mkdir(parents=True, exist_ok=True)

    # Load system prompt
    if not prompt_file.exists():
        print(f"ERROR: Prompt file not found: {prompt_file}")
        sys.exit(1)
    system_prompt = prompt_file.read_text()

    # Initialize LLM client
    if args.provider == "claude":
        client = ClaudeCodeClient(model=args.model)
    else:
        client = GeminiClient(model=args.model, max_requests=args.max_requests)

    print("=" * 70)
    print("Cedar-to-WASM Compiler Generator")
    print("=" * 70)
    print(f"  Provider:       {args.provider}")
    print(f"  Model:          {args.model}")
    print(f"  Max iterations: {args.max_iterations}")
    print(f"  Fuzz timeout:   {args.fuzz_timeout}s")
    print(f"  Build mode:     {args.build_mode}")
    print(f"  Log dir:        {log_dir}")
    print(f"  Compiler dir:   {compiler_dir}")
    print()

    # State
    phase = "initial"
    error_context = ""
    consecutive_build_failures = 0
    final_phase = "not_started"
    iteration = 0

    for iteration in range(1, args.max_iterations + 1):
        print(f"\n{'=' * 70}")
        print(f"  Iteration {iteration}/{args.max_iterations} — Phase: {phase}")
        print(f"{'=' * 70}")

        # 1. Read current source
        current_sources = read_compiler_source(compiler_dir)

        # 2. Build user message
        user_message = build_user_message(phase, current_sources, error_context)
        if args.verbose:
            print(f"\n--- USER MESSAGE ---\n{user_message[:2000]}...\n")

        # 3. Call LLM
        try:
            response_text = client.generate(system_prompt, user_message)
        except RuntimeError as e:
            print(f"\n  STOPPED: {e}")
            final_phase = "rate_limited"
            save_summary(log_dir, client, iteration, final_phase)
            break

        client.print_status()

        if args.verbose:
            print(f"\n--- RESPONSE ---\n{response_text[:2000]}...\n")

        # 4. Parse response
        parsed = parse_response(response_text)
        if not parsed.get("lib_rs"):
            print("  WARNING: No Rust code found in response. Retrying...")
            error_context = (
                "Your previous response did not contain a ```rust code block. "
                "Please provide the COMPLETE src/lib.rs source code in a ```rust block."
            )
            phase = "build_fix"
            save_iteration(log_dir, iteration, user_message, response_text,
                           parsed, "NO_CODE_FOUND", "SKIPPED")
            continue

        # 5. Write code
        write_compiler_source(compiler_dir, parsed)
        print("  Wrote compiler source.")

        # 6. Docker sync
        if args.build_mode == "docker":
            try:
                sync_to_docker(compiler_dir, args.docker_container)
                print("  Synced to Docker container.")
            except subprocess.CalledProcessError as e:
                print(f"  ERROR syncing to Docker: {e}")
                final_phase = "docker_error"
                save_iteration(log_dir, iteration, user_message, response_text,
                               parsed, f"Docker sync failed: {e}", "SKIPPED")
                break

        # 7. Build
        print("  Building...")
        build_success, build_output = run_build(
            cedar_spec_root, args.build_mode, args.docker_container
        )

        if not build_success:
            consecutive_build_failures += 1
            print(f"  BUILD FAILED (consecutive: {consecutive_build_failures})")

            # Truncate build errors for the prompt
            error_lines = build_output[-4000:]
            if consecutive_build_failures >= 5:
                error_context = (
                    f"BUILD HAS FAILED {consecutive_build_failures} TIMES IN A ROW. "
                    f"Please carefully read the error, simplify your approach if needed, "
                    f"and provide working code.\n\n"
                    f"Build error:\n{error_lines}"
                )
            else:
                error_context = f"Build error:\n{error_lines}"

            phase = "build_fix"
            save_iteration(log_dir, iteration, user_message, response_text,
                           parsed, build_output, "SKIPPED")
            continue

        print("  BUILD OK")
        consecutive_build_failures = 0

        # 8. Run fuzzer
        print(f"  Fuzzing for {args.fuzz_timeout}s...")
        fuzz_passed, fuzz_output = run_fuzz(
            cedar_spec_root, args.fuzz_timeout, args.build_mode, args.docker_container
        )

        if fuzz_passed:
            print(f"  FUZZ PASSED ({args.fuzz_timeout}s)")
            final_phase = "success"
            save_iteration(log_dir, iteration, user_message, response_text,
                           parsed, "BUILD_OK", fuzz_output)

            print(f"\n{'=' * 70}")
            print(f"  SUCCESS at iteration {iteration}!")
            print(f"{'=' * 70}")
            client.print_status()
            save_summary(log_dir, client, iteration, final_phase)
            break
        else:
            print("  FUZZ FAILED — mismatch found")
            if args.verbose:
                print(f"  {fuzz_output[:500]}...")

            error_context = f"Fuzz test failure:\n{fuzz_output[-4000:]}"
            phase = "fuzz_fix"
            save_iteration(log_dir, iteration, user_message, response_text,
                           parsed, "BUILD_OK", fuzz_output)
    else:
        final_phase = "max_iterations"
        save_summary(log_dir, client, iteration, final_phase)

    # Final summary
    print(f"\n{'=' * 70}")
    print("FINAL SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Provider:         {args.provider}")
    print(f"  Model:            {args.model}")
    print(f"  Iterations:       {iteration}")
    print(f"  Final state:      {final_phase}")
    client.print_status()
    print(f"  Logs:             {log_dir}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

PROVIDER_DEFAULTS = {
    "claude": "claude-sonnet-4-20250514",
    "gemini": "gemini-2.5-flash",
}


def main():
    parser = argparse.ArgumentParser(
        description="LLM-driven Cedar-to-WASM compiler generator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--manual", action="store_true",
                        help="Manual mode: just build + fuzz, no API calls. "
                             "Edit src/lib.rs yourself, then run this to test.")
    parser.add_argument("--provider", choices=["claude", "gemini"], default="claude",
                        help="LLM provider: claude (via Claude Code CLI) or gemini (via API)")
    parser.add_argument("--model", default=None,
                        help="Model ID (default: claude-sonnet-4-20250514 for claude, "
                             "gemini-2.5-flash for gemini)")
    parser.add_argument("--max-iterations", type=int, default=50,
                        help="Maximum LLM improvement iterations")
    parser.add_argument("--max-requests", type=int, default=200,
                        help="Hard stop on API requests (gemini free tier only)")
    parser.add_argument("--fuzz-timeout", type=int, default=30,
                        help="Seconds to run the fuzzer per iteration")
    parser.add_argument("--build-mode", choices=["local", "docker"], default="local",
                        help="Run cargo builds locally or via docker exec")
    parser.add_argument("--docker-container", default="thia_compiler",
                        help="Docker container name (for docker mode)")
    parser.add_argument("--log-dir", default="./llm_compiler_logs",
                        help="Directory for per-iteration logs")
    parser.add_argument("--prompt-file", default="./cedar-policy-compiler/prompt.md",
                        help="Path to the system prompt file")
    parser.add_argument("--compiler-dir", default="./cedar-policy-compiler",
                        help="Path to the compiler crate")
    parser.add_argument("--verbose", action="store_true",
                        help="Print full prompts and responses")
    args = parser.parse_args()

    # Set default model based on provider if not specified
    if args.model is None:
        args.model = PROVIDER_DEFAULTS[args.provider]

    if args.manual:
        run_manual(args)
    else:
        run_auto(args)


if __name__ == "__main__":
    main()
