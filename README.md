# Alethic Guard

Alethic Guard enforces execution boundaries for enrolled KVM workloads from the Linux host. It uses the [Alethic kernel](https://github.com/emiluzelac/alethic) to evaluate broker requests and links host execution records to those governance decisions.

Use the kernel in a trusted application to govern proposals and committed state.
Use Guard to isolate enrolled workloads and control their external operations
from a supported host. [Explore the Alethic ecosystem](https://alethic.dev/).

The offline profile provides a NIC-free guest with an isolated disk overlay and optional read-only inputs. The mediated profile adds a dedicated channel for a typed HTTPS collector operation. The release evidence collector records an approved Git commit, artifact SHA-256, and test verdict and returns a durable receipt. Host policy, live grant redemption, and the broker's network namespace govern that operation.

Version 0.4.0 supports the documented Ubuntu 24.04 x86-64 KVM configuration. Verify the archive checksum, then use the installer to set up Guard and its systemd services. [Download for Linux x86-64](https://github.com/emiluzelac/alethic-guard/tree/release-assets/v0.4.0). See the [deployment guide](docs/DEPLOY_LINUX.md), [supported configurations](docs/GUARANTEE_MATRIX.md), and [threat model](docs/THREAT_MODEL.md).

The root operator can stop an enrolled VM while ordinary requests are queued and recover it from the host when both Guard services are stopped. [Revocation and recovery](docs/REVOCATION.md) · [Qualification results](docs/QUALIFICATION.md)

See the [contribution guide](CONTRIBUTING.md) for starter issues, installation
reports, and independent evidence verification.

## Development

Install Python 3.11 or later, uv, and Rust for Linux.

```sh
uv run --locked --extra controller --extra test python -m pytest
cargo test --manifest-path daemon/Cargo.toml --locked
cargo test --manifest-path gateway/Cargo.toml --locked
```

The optional controller dependency pins the published `alethic-kernel==0.4.0` wheel. [Release qualification](docs/TEST_PLAN.md) covers the installed package and the measured runtime configuration.
