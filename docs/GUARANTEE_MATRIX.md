# Guarantee matrix

| Profile | Verified boundary | Release scope |
| --- | --- | --- |
| `offline-strict` | NIC-free dedicated domain, no tool channel, host-managed lifecycle | Qualified on the measured host using a pinned Ubuntu guest and synthetic input. |
| `allowlisted-api` | Same guest boundary plus one typed operation and host-controlled broker network | Qualified for the `public-demo` synthetic fixture at the exact HTTPS collector path. The release-candidate transport and cutoff tests used IPv6. |
| `supervised-transfer` | Explicit authenticated approval of an exact transfer | Future work. |
| `monitor-only` | Observation status for workloads without enforcement | Future work. |

Version 0.1.0 was qualified on Ubuntu 24.04.5 LTS x86-64 with nested AMD-V KVM, Linux `6.8.0-147-generic`, the Ubuntu libvirt `10.0.0-2ubuntu8.19` and QEMU `1:8.2.2+ds-0ubuntu1.18` packages, SeaBIOS `1.16.3-2`, AppArmor, and POSIX ACLs. The measured guest was an approved Ubuntu Noble cloud-image derivative with SHA-256 `89b9f9c17ddf521b31504b8fee5c74dc2bdbb9f4f990500043a8a811a13bc71a`. Treat other runtime versions and environments as new qualification targets. [Test results](QUALIFICATION.md)

The trusted host, operator, hypervisor and broker enforce the measured boundaries. An acknowledged cutoff fences the broker's host network path. An already-dispatched effect may have reached the collector and stays `OUTCOME_UNKNOWN` until receipt reconciliation. [Revocation and recovery](REVOCATION.md)
