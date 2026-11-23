# Contributing to Alethic Guard

Help us improve installation instructions, reproduce published qualification,
and make the enforcement boundary easier to evaluate. [Start with a focused
issue](https://github.com/emiluzelac/alethic-guard/labels/good%20first%20issue)
or [share a deployment report](https://github.com/emiluzelac/alethic-guard/issues).

## Reproduce a release

Use a dedicated test host or disposable KVM environment and synthetic inputs.
Review the [supported configuration](docs/GUARANTEE_MATRIX.md) and
[threat model](docs/THREAT_MODEL.md). Download the release archive and
evidence package, verify both checksums, then follow the [installation
guide](docs/DEPLOY_LINUX.md) and [qualification procedures](docs/TEST_PLAN.md).

Include the exact release and archive digest, OS and kernel, QEMU and libvirt
versions, steps, and expected and observed results. Report normal installation
and documentation findings in a public issue. Use
[private vulnerability reporting](SECURITY.md) for suspected security issues.

## Develop and submit a change

Fork the public repository and work on a focused branch. Run the project tests
with Python 3.11 or later, uv, and Rust for Linux.

```sh
uv run --locked --extra controller --extra test python -m pytest
cargo test --manifest-path daemon/Cargo.toml --locked
cargo test --manifest-path gateway/Cargo.toml --locked
```

Describe the behavior and test results in your pull request. The maintainer
reviews public pull requests on GitHub and applies accepted changes to the
canonical Forgejo repository with attribution. The mirror carries the accepted
changes back to GitHub.
