use crate::trace::TraceConfig;
use clap::{Arg, ArgAction};

#[cfg(feature = "otel")]
use crate::constants::DEFAULT_OTLP_ENDPOINT;
#[cfg(feature = "otel")]
use crate::trace::OtelConfig;
#[cfg(feature = "otel")]
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
  #[cfg(feature = "otel")]
  let options = options.arg(
    Arg::new("otel")
      .long("otel")
      .short('o')
      .action(ArgAction::SetTrue)
      .help("Enable opentelemetry for metrics and traces. Unless explicitly specified with '-e', collector endpoint is 'http://localhost:4317'."),
  ).arg(
    Arg::new("otlp_endpoint")
        .long("otlp-endpoint")
        .short('e')
        .value_name("ENDPOINT_URL")
        .default_value_if("otel", ArgPredicate::IsPresent, DEFAULT_OTLP_ENDPOINT)
        .help("Opentelemetry collector endpoint url connected via gRPC"),
  ).arg(
    Arg::new("otel_hostname")
        .long("otel-hostname")
        .short('n')
        .value_name("OTEL_HOSTNAME")
        .default_value_if("otel", ArgPredicate::IsPresent, None)
        .help("Opentelemetry collector endpoint url connected via gRPC [default: hostname]"),
  ).arg(
    Arg::new("otel_prod")
        .long("otel-prod")
        .short('p')
        .action(ArgAction::SetTrue)
        .default_value_if("otel", ArgPredicate::IsPresent, "false")
        .help("Opentelemetry deployment environment"),
  );

  let matches = options.get_matches();

  ///////////////////////////////////
  let config_file_path = matches.get_one::<String>("config_file").unwrap().to_owned();
  let watch = matches.get_one::<bool>("watch").unwrap().to_owned();
  let trace_config = TraceConfig::<String> {
    #[cfg(feature = "otel")]
    otel_config: if matches.get_flag("otel") {
      Some(OtelConfig {
        otlp_endpoint: matches.get_one::<String>("otlp_endpoint").unwrap().to_owned(),
        hostname: matches
          .get_one::<String>("otel_hostname")
          .map(|v| v.to_owned())
          .unwrap_or_else(|| gethostname::gethostname().into_string().unwrap_or("none".to_string()))
          .to_owned(),
        deployment_environment: if matches.get_flag("otel_prod") {
          "production".to_string()
        } else {
          "develop".to_string()
        },
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
