#!/usr/bin/env sh
CONFIG_FILE=/etc/modoh-server.toml
DEFAULT_OTLP_ENDPOINT=http://localhost:4317

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
  if [ -z $OTEL_PRODUCTION ]; then
    OTEL_PRODUCTION=false
  else
    if [ "$OTEL_PRODUCTION" = "true" ]; then
      OTEL_PROD_STR="--otel-prod"
    else
      OTEL_PROD_STR=""
    fi
  fi

  if [ -z $OTEL_HOSTNAME ]; then
    echo "modoh-server: OpenTelemetry enabled with endpoint ${OTLP_ENDPOINT} with default hostname: production=${OTEL_PRODUCTION}"
    OTEL_ARG="--otel --otlp-endpoint ${OTLP_ENDPOINT} ${OTEL_PROD_STR}"
  else
    echo "modoh-server: OpenTelemetry enabled with endpoint ${OTLP_ENDPOINT} and hostname ${OTEL_HOSTNAME}: production=${OTEL_PRODUCTION}"
    OTEL_ARG="--otel --otlp-endpoint ${OTLP_ENDPOINT} --otel-hostname ${OTEL_HOSTNAME} ${OTEL_PROD_STR}"
  fi
fi

if  $WATCH ; then
  RUST_LOG=${LOG_LEVEL} /modoh/bin/modoh-server --config ${CONFIG_FILE} -w ${OTEL_ARG}
else
  RUST_LOG=${LOG_LEVEL} /modoh/bin/modoh-server --config ${CONFIG_FILE} ${OTEL_ARG}
fi
