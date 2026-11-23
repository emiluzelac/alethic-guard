# Alethic Guard

Alethic Guard is an experimental Linux companion to the [Alethic kernel](https://github.com/emiluzelac/alethic). It enrolls dedicated KVM guests, manages their lifecycle from the host, and links grounded execution records to Alethic governance decisions.

The offline profile creates a NIC-free guest with an isolated disk overlay and optional read-only inputs. The mediated preview adds a dedicated channel for a single synthetic TLS collector operation. Host policy, live grant redemption, and the broker's network namespace govern that operation.

See the [deployment instructions](docs/DEPLOY_LINUX.md), [threat model](docs/THREAT_MODEL.md), and [guarantee matrix](docs/GUARANTEE_MATRIX.md) before running the lab. Use synthetic inputs on an isolated qualification host.

## Development

Install Python 3.11 or later, uv, and Rust for Linux.

```sh
uv run --locked --extra controller --extra test python -m pytest
cargo test --manifest-path daemon/Cargo.toml --locked
cargo test --manifest-path gateway/Cargo.toml --locked
```

The optional controller dependency pins the published `alethic-kernel==0.4.0` wheel. [Release qualification](docs/TEST_PLAN.md) covers the installed package and the measured runtime configuration.
