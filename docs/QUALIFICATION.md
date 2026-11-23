# Alethic Guard release qualification

## Version 0.4.0

Use the v0.4.0 evidence package to match the qualified archive SHA-256, source commit, runtime, and guest digests. The package includes the recorded shutdown distribution, installed-service and recovery observations, controlled local-model results, and instructions for checking the retained journal checkpoint. [v0.4.0 evidence](https://github.com/emiluzelac/alethic-guard/tree/release-assets/v0.4.0)

## Version 0.3.0

The local-agent lab uses physical Intel KVM with Ubuntu 24.04.5 x86-64, Linux `7.0.0-42-generic`, libvirt `10.0.0-2ubuntu8.19`, and QEMU `1:8.2.2+ds-0ubuntu1.18`. The test runs in disposable Ubuntu userspace with private networking and an AppArmor override for container namespace mounts. The enrolled guest uses one CPU and 1 GiB of RAM.

The release candidate at `f47726f1782403f95a2205296abd50fae67cc445` ran the pinned SmolLM2 model against a synthetic maintenance note. The calibrated lab listener saw zero guest connection attempts. The host authorized one release evidence record and the collector returned its matching receipt. The emergency stop reported verified shutdown while an enrollment and a separate status request were still pending. A separate process confirmed the domain and its QEMU process were absent. Pausing the libvirt observer produced `UNKNOWN` for shutdown and the restart probe confirmed the fence before ordinary cleanup.

The [release download and evidence directory](https://github.com/emiluzelac/alethic-guard/tree/release-assets/v0.3.0) contains the archive checksums, the replay record for the released bits, a checkpoint retained off the KVM host, and a verifier for the raw observations. See the [local-agent procedure](../tests/lab/local-agent/README.md).

## Version 0.2.0

The release evidence collector and broker were live-qualified on Ubuntu 24.04.5 x86-64, Linux `7.0.0-42-generic`, and physical Intel KVM. libvirt `10.0.0-2ubuntu8.19` and QEMU `1:8.2.2+ds-0ubuntu1.18` ran inside disposable Ubuntu userspace using the physical host kernel. The lab used private networking, an AppArmor override for namespace mounts, and outer container resource limits. The released 0.1.0 binaries also passed the NIC-free offline guest probe in that environment.

| Check | Observation |
| --- | --- |
| Approved delivery | A NIC-free guest requested the real 0.1.0 release record using the typed channel. The exact canonical release record reached the IPv6 HTTPS collector and the returned receipt matched its SHA-256. |
| Scope and duplicates | Guard denied a role field, a selector outside the configured mode, and a replay of the guest request ID. The collector denied the wrong credential on each endpoint. Repeating the same body and idempotency key returned the existing receipt. Changing the body for that key returned HTTP 409. |
| Emergency cutoff | After the collector committed the record, the host verified cutoff and refused to start the workload with the cutoff latched. A trusted operator retrieved the existing receipt over HTTPS and reconciled the outcome. |
| Process recovery | Guard and the collector were killed after database commit and before acknowledgment. The recovered workload stayed stopped and the effect required receipt reconciliation. A retry after restart returned the same receipt with no additional database row. |

The staging test retained the SQLite filesystem across process restarts. See the [guarantee matrix](GUARANTEE_MATRIX.md) and [deployment guide](DEPLOY_LINUX.md) for the applicable scope.

The live collector run used implementation commit `03a5ad2e12981cb59845f79d246b757d421a1e96`. The v0.2.0 tag, `79fada9ff0c4fdd6dfceb53650de95d2c796a34f`, passed Forgejo CI for Python 3.11, Python 3.12, and Rust and a separate check against the published kernel wheel. The release archive passed a clean Ubuntu installation check. Its checksum is in the [public SHA256SUMS file](https://github.com/emiluzelac/alethic-guard/blob/release-assets/v0.2.0/SHA256SUMS). [Tagged source](https://github.com/emiluzelac/alethic-guard/tree/v0.2.0)

## Version 0.1.0

The qualification used an isolated Ubuntu 24.04.5 x86-64 host with nested KVM and synthetic inputs. The live controller used the published `alethic-kernel==0.4.0` wheel. The [guarantee matrix](GUARANTEE_MATRIX.md) identifies the tested packages, firmware and guest image.

| Check | Observation |
| --- | --- |
| Offline guest and clean installation | The installed daemon started through its packaged systemd unit. The active domain had zero NICs. The guest-root IPv4 and IPv6 probes saw only loopback, and the installed CLI verified containment and termination. |
| Paused-start configuration drift | A restart-policy change, disconnected interface, substituted read-only input, and empty read-only host mount were observed in real paused libvirt domains. Guard refused startup and verified cleanup in each case. An unenrolled libvirt domain reported `UNMANAGED`. |
| Live observation unavailable | A running real KVM workload lost its live XML observation under the test fixture. Guard reported `UNKNOWN`, recorded the observation in its journal, and verified that the workload stopped. |
| Enrollment integrity | Changing the approved image digests and changing the installed compiled policy were tested independently. The prior enrollment refused start and release. A new enrollment under each intended revision verified start and termination. |
| Mediated host stack | The packaged gateway, controller and daemon completed one synthetic TLS operation with one matching receipt. The guest remained NIC-free. The repeated request was denied. |
| Permit expiry and controller incarnation | The daemon refused a valid grant after its ten-second allowance elapsed. It also refused an unexpired grant from a replaced controller incarnation. The collector capture showed zero traffic and the registry recorded zero effects in both cases. |
| Transport restrictions | Unknown issuer and wrong certificate name produced zero HTTP requests. The same-origin redirect target received zero requests. An unapproved resolver answer produced zero TCP connections and zero effects. |
| Cutoff and shutdown | Both sides of the dispatch race were exercised. Packet captures showed zero forwarded broker traffic after the verified cutoff. Daemon restart and marker-removal fault checks preserved the stopped lifecycle. |
| Uncertain delivery and recovery | After a dropped acknowledgment, gateway crash, or daemon crash, Guard rejected retries of the same request ID. Each effect remained unknown until a matching collector receipt was reconciled. An injected journal write failure produced zero effects and zero collector connections. |
| Unsupported host | The installed daemon refused the guest launch on the Ubuntu fixture with nested virtualization disabled and `/dev/kvm` absent. The managed guest remained stopped. |
| Evidence | The installed CLI exported metadata-only records and verified the journal hash chain. The collector request body and TLS key material were absent from the exports. |

The offline and mediated installation checks were repeated on the installed candidate from an independent agent session. The [lab procedures](../tests/lab/README.md) describe the synthetic test inputs and packet capture setup. The [test plan](TEST_PLAN.md) records the qualification criteria.
