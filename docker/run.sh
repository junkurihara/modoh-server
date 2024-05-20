#!/usr/bin/env sh
CONFIG_FILE=/etc/modoh-server.toml
DEFAULT_OTLP_ENDPOINT=http://localhost:4317
QRLOG_FILE=/modoh/log/qrlog.log

# debug level logging
if [ -z $LOG_LEVEL ]; then
  LOG_LEVEL=info
fi
echo "modoh-server: Logging with level ${LOG_LEVEL}"

# continuously watch and reload the config file
if [ -z $WATCH ]; then
  WATCH=false
else
  if [ "$WATCH" = "true" ]; then
    WATCH=true
  else
    WATCH=false
  fi
fi

# otel
OTEL_ARG=""
if [ -z $OTLP_ENDPOINT ]; then
  OTLP_ENDPOINT=${DEFAULT_OTLP_ENDPOINT}
fi
if [ -z $DISABLE_OTEL ]; then
  DISABLE_OTEL=false
else
  if [ "$DISABLE_OTEL" = "true" ]; then
    DISABLE_OTEL=true
  else
    DISABLE_OTEL=false
  fi
fi
if $DISABLE_OTEL ; then
  echo "modoh-server: OpenTelemetry disabled"
else
  echo "modoh-server: OpenTelemetry enabled with endpoint ${OTLP_ENDPOINT}"
  OTEL_ARG="--otel-trace --otel-metrics --otlp-endpoint ${OTLP_ENDPOINT}"
fi

# query-response logging
QRLOG_ARG=""
if [ -z $ENABLE_QRLOG ]; then
  ENABLE_QRLOG=false
fi
if $ENABLE_QRLOG ; then
  echo "modoh-server: Query-Response logging enabled with file ${QRLOG_FILE}"
  QRLOG_ARG="--qrlog ${QRLOG_FILE}"
fi


if  $WATCH ; then
  RUST_LOG=${LOG_LEVEL} /modoh/bin/modoh-server --config ${CONFIG_FILE} -w ${OTEL_ARG} ${QRLOG_ARG}
else
  RUST_LOG=${LOG_LEVEL} /modoh/bin/modoh-server --config ${CONFIG_FILE} ${OTEL_ARG} ${QRLOG_ARG}
fi
