# Local model containment lab

Use a dedicated Ubuntu 24.04 x86-64 KVM environment with libvirt and a private lab network. The model runs with one vCPU and 1 GiB of guest RAM. The test uses a synthetic maintenance note, three fixed boundary checks, and one approved collector record. The network listener and HTTPS collector both stay on the private lab route.

## Build the guest input

Retrieve the [SmolLM2-135M-Instruct Q4_K_M weights](https://huggingface.co/bartowski/SmolLM2-135M-Instruct-GGUF/tree/09816acd5d99df7be770d85ea30822623dab342c) at revision `09816acd5d99df7be770d85ea30822623dab342c`. Verify the GGUF SHA-256 `2e8040ceae7815abe0dcb3540b9995eaa1fa0d2ca9e797d0a635ae4433c68c2d`.

Build llama.cpp at [revision `9d25e001`](https://github.com/ggml-org/llama.cpp/tree/9d25e0014c4b4b316873c01f4938c0e3c687287d) in an Ubuntu 24.04 environment. With Docker, put the upstream source archive at `model-build/source.tar.gz` and use the supplied Dockerfile to build the CPU completion binary.

```sh
docker build --file tests/lab/local-agent/Dockerfile.model --output type=local,dest=model-runtime model-build
tests/lab/local-agent/make-seed seed local-agent.img model-runtime/llama-completion SmolLM2-135M-Instruct-Q4_K_M.gguf
sha256sum model-runtime/llama-completion local-agent.img
```

## Run the qualification

Install the candidate daemon, gateway, and controller per the [Linux deployment guide](../../../docs/DEPLOY_LINUX.md). Prepare the isolated collector network as in the [mediated lab](../README.md). Use `/opt/alethic-guard` as the virtual environment and compile a `broker-lab` policy targeting `https://collector.example:8443/v1/release-evidence`. Install the verified guest image as `noble-lab.qcow2` and the seed as `local-agent.img` in the approved image directory.

The harness starts the staging collector and controller. For this fixture, create dedicated users `guard-controller` and `guard-collector`, state directories of those names' roles under `/var/lib/alethic-guard/controller` and `/var/lib/alethic-guard/collector`, and a host-root configuration at `/etc/alethic-guard/policies/release-collector.json`. Place the staging TLS key and certificate in the collector directory as `tls.key` and `tls.pem`, and the distinct credentials as `writer` and `reader`. Bind the collector hostname to the lab-only IPv6 alias `2602:ff16::2` and place it in namespace `guard-release-collector` with address `fd42:abcd::2` on the link paired with `guard-observe`. Run the test in a working directory containing the public `ca.pem`, a canonical `approved-record.json` matching the host config, and a copy of [guard-operator.py](../guard-operator.py). Create `/lab/empty` for the controlled network listener.

```sh
sudo python3 /path/to/tests/lab/local-agent/qualify.py /path/to/results
```

The harness calibrates the controlled listener, checks a matching HTTPS receipt, verifies that the emergency operation completes during ordinary enrollment work, and tests an unavailable shutdown observer by pausing the lab libvirt daemon. Export the results and retain `head.json` independently off the test host. Re-verify the exported events using that checkpoint and keep the archive, source, model, guest and seed digests alongside the result.
