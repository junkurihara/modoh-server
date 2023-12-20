use clap::{Arg, ArgAction};

#[cfg(feature = "otel")]
use crate::constants::DEFAULT_OTLP_ENDPOINT;
#[cfg(feature = "otel")]
use clap::builder::ArgPredicate;

/// Parsed options
pub struct Opts {
  pub config_file_path: String,
  pub watch: bool,
  #[cfg(feature = "otel")]
  pub otlp_endpoint: Option<String>,
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
  );

  let matches = options.get_matches();

  ///////////////////////////////////
  let config_file_path = matches.get_one::<String>("config_file").unwrap().to_owned();
  let watch = matches.get_one::<bool>("watch").unwrap().to_owned();

  Ok(Opts {
    config_file_path,
    watch,
    #[cfg(feature = "otel")]
    otlp_endpoint: {
      if matches.get_flag("otel") {
        Some(matches.get_one::<String>("otlp_endpoint").unwrap().to_owned())
      } else {
        None
      }
    },
  })
}
