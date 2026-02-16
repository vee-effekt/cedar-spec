#!/usr/bin/env bash
# Start the OpenTelemetry collector to capture Claude Code token usage.
#
# Usage:
#   ./start-otel.sh          # start collector in background
#   ./start-otel.sh stop     # stop collector
#   ./start-otel.sh status   # check if running
#
# Metrics are written to otel-metrics.jsonl and otel-logs.jsonl
# in the cedar-policy-compiler directory.
#
# After starting the collector, launch Claude Code with:
#   source claude-env.sh && claude

set -euo pipefail
cd "$(dirname "$0")"

PIDFILE=".otel-collector.pid"

case "${1:-start}" in
  start)
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "OTel collector already running (pid $(cat "$PIDFILE"))"
      exit 0
    fi

    if command -v otelcol-contrib &>/dev/null; then
      OTELCOL=otelcol-contrib
    elif [ -x "$HOME/.local/bin/otelcol-contrib" ]; then
      OTELCOL="$HOME/.local/bin/otelcol-contrib"
    elif command -v otelcol &>/dev/null; then
      OTELCOL=otelcol
    else
      echo "otelcol-contrib not found. Install it:"
      echo "  # Download binary (macOS ARM64):"
      echo "  curl -LO https://github.com/open-telemetry/opentelemetry-collector-releases/releases/latest/download/otelcol-contrib_0.145.0_darwin_arm64.tar.gz"
      echo "  tar xzf otelcol-contrib_0.145.0_darwin_arm64.tar.gz"
      echo "  mkdir -p ~/.local/bin && mv otelcol-contrib ~/.local/bin/"
      exit 1
    fi

    echo "Starting OTel collector..."
    $OTELCOL --config otel-collector-config.yaml &
    echo $! > "$PIDFILE"
    echo "OTel collector started (pid $(cat "$PIDFILE"))"
    echo "Metrics → otel-metrics.jsonl"
    echo "Logs    → otel-logs.jsonl"
    ;;

  stop)
    if [ -f "$PIDFILE" ]; then
      kill "$(cat "$PIDFILE")" 2>/dev/null && echo "Stopped" || echo "Already stopped"
      rm -f "$PIDFILE"
    else
      echo "No PID file found"
    fi
    ;;

  status)
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "Running (pid $(cat "$PIDFILE"))"
    else
      echo "Not running"
    fi
    ;;

  *)
    echo "Usage: $0 {start|stop|status}"
    exit 1
    ;;
esac
