# Guarantee matrix

| Profile | Proposed boundary | Qualification |
| --- | --- | --- |
| `offline-strict` | NIC-free dedicated domain, no tool channel, host-managed lifecycle | Requires lab validation of the exact Linux, libvirt, QEMU, KVM, and guest image configuration. |
| `allowlisted-api` | Same guest boundary plus one typed operation and host-controlled broker network | Requires the offline qualification, collector evidence, and revocation and recovery tests. |
| `supervised-transfer` | Explicit authenticated approval of an exact transfer | Future work. |
| `monitor-only` | Observation status for workloads without enforcement | Future work. |

The release target is Ubuntu 24.04 LTS x86-64 with hardware KVM. The runtime and packet evidence for a specific configuration determine the support claim.
