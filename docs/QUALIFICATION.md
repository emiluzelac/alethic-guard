# Release qualification for version 0.1.0

The qualification used an isolated Ubuntu 24.04.5 x86-64 host with nested KVM and synthetic inputs. The live controller used the published `alethic-kernel==0.4.0` wheel. The [guarantee matrix](GUARANTEE_MATRIX.md) identifies the tested packages, firmware and guest image.

| Check | Observation |
| --- | --- |
| Offline guest and clean installation | The installed daemon started through its packaged systemd unit. The active domain had zero NICs. The guest-root IPv4 and IPv6 probes saw only loopback, and the installed CLI verified containment and termination. |
| Paused-start configuration drift | A restart-policy change, disconnected interface, substituted read-only input, and empty read-only host mount were observed in real paused libvirt domains. Guard refused startup and verified cleanup in each case. An unenrolled libvirt domain reported `UNMANAGED`. |
| Enrollment integrity | Changing the approved image digests and changing the installed compiled policy were tested independently. The prior enrollment refused start and release. A new enrollment under each intended revision verified start and termination. |
| Mediated host stack | The packaged gateway, controller and daemon completed one synthetic TLS operation with one matching receipt. The guest remained NIC-free. The repeated request was denied. |
| Permit expiry and controller incarnation | The daemon refused a valid grant after its ten-second allowance elapsed. It also refused an unexpired grant from a replaced controller incarnation. The collector capture showed zero traffic and the registry recorded zero effects in both cases. |
| Transport restrictions | Unknown issuer and wrong certificate name produced zero HTTP requests. The same-origin redirect target received zero requests. An unapproved resolver answer produced zero TCP connections and zero effects. |
| Cutoff and shutdown | Both sides of the dispatch race were exercised. Packet captures showed zero forwarded broker traffic after the verified cutoff. Daemon restart and marker-removal fault checks preserved the stopped lifecycle. |
| Uncertain delivery and recovery | After a dropped acknowledgment, gateway crash, or daemon crash, Guard rejected retries of the same request ID. Each effect remained unknown until a matching collector receipt was reconciled. An injected journal write failure produced zero effects and zero collector connections. |
| Unsupported host | The installed daemon refused to launch on the Ubuntu fixture with the nested virtualization CPU capability disabled. The managed guest remained stopped. |
| Evidence | The installed CLI exported metadata-only records and verified the journal hash chain. The collector request body and TLS key material were absent from the exports. |

The offline and mediated installation checks were repeated on the installed candidate from an independent agent session. The [lab procedures](../tests/lab/README.md) describe the synthetic test inputs and packet capture setup. The [test plan](TEST_PLAN.md) records the qualification criteria.
