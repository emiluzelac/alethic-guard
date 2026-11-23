# Alethic Guard

Alethic Guard is an experimental Linux companion to the [Alethic kernel](https://github.com/emiluzelac/alethic). It enrolls dedicated KVM guests, manages their lifecycle from the host, and links grounded execution records to Alethic governance decisions.

The offline profile creates a NIC-free guest with an isolated disk overlay and optional read-only inputs. The mediated preview adds a dedicated channel for a typed HTTPS collector operation. The release evidence collector records an approved Git commit, artifact SHA-256, and test verdict and returns a durable receipt. Host policy, live grant redemption, and the broker's network namespace govern that operation.

Version 0.3.0 is a lab preview for the [qualified Ubuntu/KVM configuration](docs/GUARANTEE_MATRIX.md). Start with an isolated host and public release metadata or synthetic inputs. [Download for Linux x86-64](https://github.com/emiluzelac/alethic-guard/tree/release-assets/v0.3.0). See the [Linux deployment instructions](docs/DEPLOY_LINUX.md), [policy enforcement matrix](docs/POLICY_SPEC.md), [qualification results](docs/QUALIFICATION.md), and [threat model](docs/THREAT_MODEL.md).

The emergency shutdown command uses the dedicated host-root socket while ordinary operator requests are queued. The local-model lab tests a small CPU model with a synthetic document, scoped broker requests, and a separately observed VM shutdown. [Lab evidence](https://github.com/emiluzelac/alethic-guard/tree/release-assets/v0.3.0)

## Development

Install Python 3.11 or later, uv, and Rust for Linux.

```sh
uv run --locked --extra controller --extra test python -m pytest
cargo test --manifest-path daemon/Cargo.toml --locked
cargo test --manifest-path gateway/Cargo.toml --locked
```

The optional controller dependency pins the published `alethic-kernel==0.4.0` wheel. [Release qualification](docs/TEST_PLAN.md) covers the installed package and the measured runtime configuration.
