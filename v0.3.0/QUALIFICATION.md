# Alethic Guard v0.3.0 lab qualification

This replay installed the checksummed Linux x86-64 release archive built from `5db9cfc0414e736289c6642f8fada93a14738511`. The candidate used Ubuntu 24.04.5, Linux 7.0.0-42-generic, physical Intel KVM, libvirt 10.0.0-2ubuntu8.19, and QEMU 1:8.2.2+ds-0ubuntu1.18. The host test used disposable Ubuntu userspace with private networking, a container-level AppArmor override for namespace mounts, and resource limits. The enrolled guest used one vCPU and 1 GiB of RAM.

The pinned SmolLM2 CPU model answered from a synthetic maintenance note. The fixed tests denied an unmounted input, an undeclared broker operation, and direct connection to the calibrated lab listener. The host-approved record returned a matching HTTPS receipt. Emergency VM shutdown verified in 394 ms while a normal enrollment and a second status request were pending. A separate process observed the same domain UUID and QEMU process before the stop and confirmed their absence after it. Restart remained fenced when the shutdown observer was unavailable.

The packet capture contains a single calibrated host SYN for the lab listener and zero guest SYNs. The journal head checkpoint was retained off-host. The serial file contains synthetic test markers. Recompute the journal hashes, receipt digest, capture count, and shutdown checks with the included verifier.

```sh
python3 verify-artifacts.py model-results observer.json retained-checkpoint.json require-queue-check
```

Use the [lab procedure](https://github.com/emiluzelac/alethic-guard/tree/v0.3.0/tests/lab/local-agent) for an independent replay. The measured Noble guest image SHA-256 was `89b9f9c17ddf521b31504b8fee5c74dc2bdbb9f4f990500043a8a811a13bc71a`. The model weights SHA-256 was `2e8040ceae7815abe0dcb3540b9995eaa1fa0d2ca9e797d0a635ae4433c68c2d`. The measured NoCloud seed SHA-256 was `f60010490d1edf750d03eb08cecb9045df37aa64cac15037131db582cf119b7b`.
