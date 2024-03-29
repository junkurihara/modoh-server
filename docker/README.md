# Docker container of `modoh-server`

## Environment Variables

We have several container-specific environment variables, which doesn't relates the behavior of `modoh-server`.

- `HOST_USER` (default: `user`): User name executing `rpxy` inside the container.
- `HOST_UID` (default: `900`): `UID` of `HOST_USER`.
- `HOST_GID` (default: `900`): `GID` of `HOST_USER`
- `LOG_LEVEL=debug|info|warn|error` (default: `info`): Log level
- `LOG_TO_FILE=true|false` (default: `false`): Enable logging to the log file `/modoh/log/modoh-server.log` using `logrotate`. You should mount `/modoh/log` via docker volume option if enabled. The log dir and file will be owned by the `HOST_USER` with `HOST_UID:HOST_GID` on the host machine. Hence, `HOST_USER`, `HOST_UID` and `HOST_GID` should be the same as ones of the user who executes the `modoh-server` container on the host.
- `OTEL_ENDPOINT`: If set, `--trace` and `--metrics` are enabled in the execute option. Set the gRPC endpoint of `opentelemetry-collector`.

See [`./docker-compose.yml`](./docker-compose.yml) for the detailed configuration of the above environment variables.

## Volumes

At least, the configured `config.toml` file (or its contained directory) must be mounted:

- case 1: only `config.toml` is directly mounted as `/etc/modoh-server.toml`. Then, the *hot-reload function is disabled* due to the limitation of docker.
- case 2: `path/to/config_dir/` containing `config.toml` is mounted as `/modoh/config`. Then `modoh-server` can tracks changes of the configuration file.

In addition to the configuration file/directory, the list of up-to-date CDN IP addresses should be mounted and set in the `config.toml`. See [`../modoh-server.toml`](../modoh-server.toml) and [`./docker-compose.yml`](./docker-compose.yml).

You may also need to mount the log directory (`/modoh/log`).
