#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod config;
mod constants;
mod error;
mod trace;

#[cfg(any(feature = "otel-trace", feature = "otel-metrics"))]
mod otel;

use crate::{
  config::{parse_opts, ConfigReloader, TargetConfig},
  constants::CONFIG_WATCH_DELAY_SECS,
  trace::*,
};
use hot_reload::{ReloaderReceiver, ReloaderService};
use modoh_server_lib::{entrypoint, ServiceConfig};

fn main() {
  let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
  runtime_builder.enable_all();
  runtime_builder.thread_name("modoh-server");
  let runtime = runtime_builder.build().unwrap();

  runtime.block_on(async {
    // Initially load options
    let Ok(parsed_opts) = parse_opts() else {
      eprintln!("Invalid toml file");
      std::process::exit(1);
    };

    // Initialize tracing subscriber
    let trace_config = parsed_opts.trace_config;
    let qrlog_config = parsed_opts.qrlog_config;
    let _gurad = init_tracing_subscriber(&trace_config, &qrlog_config);

    if !parsed_opts.watch {
      if let Err(e) = relay_service_without_watcher(&parsed_opts.config_file_path, runtime.handle().clone()).await {
        error!("MODoH service existed: {e}");
        std::process::exit(1);
      }
    } else {
      let (config_service, config_rx) =
        ReloaderService::<ConfigReloader, TargetConfig>::new(&parsed_opts.config_file_path, CONFIG_WATCH_DELAY_SECS, false)
          .await
          .unwrap();

      tokio::select! {
        Err(e) = config_service.start() => {
          error!("config reloader service exited: {e}");
          std::process::exit(1);
        }
        Err(e) = relay_service_with_watcher(config_rx, runtime.handle().clone()) => {
          error!("MODoH service existed: {e}");
          std::process::exit(1);
        }
      }
    }
  });
}

async fn relay_service_without_watcher(
  config_file_path: &str,
  runtime_handle: tokio::runtime::Handle,
) -> Result<(), anyhow::Error> {
  info!("Start MODoH service");
  let config = match TargetConfig::new(config_file_path).await {
    Ok(v) => v,
    Err(e) => {
      error!("Invalid toml file: {e}");
      std::process::exit(1);
    }
  };

  let relay_conf = match (&config).try_into() as Result<ServiceConfig, anyhow::Error> {
    Ok(v) => v,
    Err(e) => {
      error!("Invalid configuration: {e}");
      return Err(anyhow::anyhow!(e));
    }
  };

  entrypoint(&relay_conf, &runtime_handle, None)
    .await
    .map_err(|e| anyhow::anyhow!(e))
}

async fn relay_service_with_watcher(
  mut config_rx: ReloaderReceiver<TargetConfig>,
  runtime_handle: tokio::runtime::Handle,
) -> Result<(), anyhow::Error> {
  info!("Start MODoH service with dynamic config reloader");
  // Initial loading
  config_rx.changed().await?;
  let reloaded = config_rx.borrow().clone().unwrap();
  let mut relay_conf = match (&reloaded).try_into() as Result<ServiceConfig, anyhow::Error> {
    Ok(v) => v,
    Err(e) => {
      error!("Invalid configuration: {e}");
      return Err(anyhow::anyhow!(e));
    }
  };

  // Notifier for relay service termination
  let term_notify = std::sync::Arc::new(tokio::sync::Notify::new());

  // Continuous monitoring
  loop {
    tokio::select! {
      res = entrypoint(&relay_conf, &runtime_handle, Some(term_notify.clone())) => {
        if let Err(e) = res {
          error!("MODoH service exited: {e}")
        } else {
          error!("MODoH service entrypoint exited");
        }
        break;
      }
      _ = config_rx.changed() => {
        if config_rx.borrow().is_none() {
          error!("Something wrong in config reloader receiver");
          break;
        }
        let config_toml = config_rx.borrow().clone().unwrap();
        match (&config_toml).try_into() as Result<ServiceConfig, anyhow::Error> {
          Ok(p) => {
            relay_conf = p
          },
          Err(e) => {
            error!("Invalid configuration. Configuration does not updated: {e}");
            continue;
          }
        };
        info!("Configuration updated. Terminate all spawned services and force to re-bind TCP/UDP sockets");
        term_notify.notify_waiters();
      }
      else => break
    }
  }

  Err(anyhow::anyhow!(
    "http routing service or continuous monitoring service exited"
  ))
}
