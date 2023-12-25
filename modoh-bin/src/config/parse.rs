use crate::trace::TraceConfig;
use clap::{Arg, ArgAction};

#[cfg(any(feature = "otel-trace", feature = "otel-metrics"))]
use crate::constants::DEFAULT_OTLP_ENDPOINT;
#[cfg(any(feature = "otel-trace", feature = "otel-metrics"))]
use crate::trace::OtelConfig;
#[cfg(any(feature = "otel-trace", feature = "otel-metrics"))]
use clap::builder::ArgPredicate;

/// Parsed options
pub struct Opts {
  pub config_file_path: String,
  pub watch: bool,
  pub trace_config: TraceConfig<String>,
}

/// Parse arg values passed from cli
pub fn parse_opts() -> Result<Opts, anyhow::Error> {
  let _ = include_str!("../../Cargo.toml");
  let options = clap::command!()
    .arg(
      Arg::new("config_file")
        .long("config")
        .short('c')
        .value_name("FILE")
        .required(true)
        .help("Configuration file path like ./config.toml"),
    )
    .arg(
      Arg::new("watch")
        .long("watch")
        .short('w')
        .action(ArgAction::SetTrue)
        .help("Activate dynamic reloading of the config file via continuous monitoring"),
    );
  #[cfg(feature = "otel-trace")]
  let options = options.arg(
    Arg::new("otel_trace")
      .long("otel-trace")
      .short('t')
      .action(ArgAction::SetTrue)
      .help("Enable opentelemetry for trace. Unless explicitly specified with '-e', collector endpoint is 'http://localhost:4317'."),
  );
  #[cfg(feature = "otel-metrics")]
  let options = options.arg(
    Arg::new("otel_metrics")
      .long("otel-metrics")
      .short('m')
      .action(ArgAction::SetTrue)
      .help("Enable opentelemetry for metrics. Unless explicitly specified with '-e', collector endpoint is 'http://localhost:4317'."),
  );
  #[cfg(any(feature = "otel-trace", feature = "otel-metrics"))]
  let options = options.arg(
    Arg::new("otlp_endpoint")
      .long("otlp-endpoint")
      .short('e')
      .value_name("ENDPOINT_URL")
      .default_value_ifs([
        ("otel_trace", ArgPredicate::IsPresent, DEFAULT_OTLP_ENDPOINT),
        ("otel_metrics", ArgPredicate::IsPresent, DEFAULT_OTLP_ENDPOINT),
      ])
      .help("Opentelemetry collector endpoint url connected via gRPC"),
  );

  let matches = options.get_matches();

  ///////////////////////////////////
  let config_file_path = matches.get_one::<String>("config_file").unwrap().to_owned();
  let watch = matches.get_one::<bool>("watch").unwrap().to_owned();
  let trace_config = TraceConfig::<String> {
    #[cfg(any(feature = "otel-trace", feature = "otel-metrics"))]
    otel_config: if matches.get_flag("otel_trace") || matches.get_flag("otel_metrics") {
      Some(OtelConfig {
        otlp_endpoint: matches.get_one::<String>("otlp_endpoint").unwrap().to_owned(),
        #[cfg(feature = "otel-trace")]
        trace_enabled: matches.get_flag("otel_trace"),
        #[cfg(feature = "otel-metrics")]
        metrics_enabled: matches.get_flag("otel_metrics"),
        #[cfg(feature = "otel-instance-id")]
        service_instance_id: uuid::Uuid::new_v4().to_string(),
      })
    } else {
      None
    },
    _marker: std::marker::PhantomData,
  };

  Ok(Opts {
    config_file_path,
    watch,
    trace_config,
  })
}
