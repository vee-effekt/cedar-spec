# Source this before running Claude Code to enable token tracking.
#   source claude-env.sh && claude

export CLAUDE_CODE_ENABLE_TELEMETRY=1
export OTEL_METRICS_EXPORTER=otlp
export OTEL_LOGS_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_PROTOCOL=grpc
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
export OTEL_METRIC_EXPORT_INTERVAL=10000   # 10 seconds
export OTEL_LOGS_EXPORT_INTERVAL=5000      # 5 seconds

# Uncomment to see telemetry in terminal:
# export OTEL_METRICS_EXPORTER=console,otlp
# export OTEL_LOGS_EXPORTER=console,otlp
