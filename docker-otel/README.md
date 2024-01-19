# Example Construction of Opentelemetry and its related servers for Observability

Here is an example of docker containers for the observability of `modoh-server`, conjunctively configured with its container in [`../docker/`](../docker/) directory.

![Example for Observability](../assets/observability.jpg)

This example consists of the following containers:

- [`opentelemetry-collector`](https://github.com/open-telemetry/opentelemetry-collector): Receives and aggregates OTLP gRPC messages from `modoh-server`. In this example, it is collocated with `modoh-server` in a virtual local network.
- [`Jaeger`](https://www.jaegertracing.io/): Received trace information via OTLP gRPC from `opentelemetry-collector`, and visualize the trace on the web ([`http://localhost:16686`](http://localhost:16686)).
- [`Grafana mimir`](https://github.com/grafana/mimir): Receives metrics information via Prometheus Remote Write protocol from `opentelemetry-collector`. This is responsible to aggregate and store the metric information in a long-term storage like object storage services.
- [`Grafana`](https://grafana.com/): Retrieves Prometheus metrics from `Grafana mimir` and visualize the metrics information on the web ([`http://localhost:3000`](http://localhost:3000)).
- [`Rclone`](https://rclone.org/): Serves an S3 compatible object storage backed by a certain cloud storage service like Dropbox. This is connected from `Grafana mimir` to store the metrics data. `rclone.conf` requires to be configured. (See the [Rclone docs](https://rclone.org/docs/))

For the detailed configurations for these containers, please refer to [`./docker-compose.yml`](./docker-compose.yml) and its mounting configuration files.
