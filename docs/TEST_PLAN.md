# Qualification and release

Use the real host and guest test procedures in [the lab instructions](../tests/lab/README.md). For each supported configuration keep the host, kernel, firmware, libvirt and QEMU versions, image checksum, packet captures, request receipts, and Guard event exports. Public assurance depends on these artifacts, independent review, and testing of an actual published kernel wheel that provides the adapter APIs.

| Condition | Required observation |
| --- | --- |
| Guest root probes IPv4/IPv6 TCP, UDP, ICMP, DNS, and a UDP flow to the QUIC port | Zero guest network devices other than loopback and no guest traffic on the calibrated lab uplink. |
| Changed interface, host mount, input path, or restart policy | The domain stays paused and Guard stops it. |
| Unenrolled domain | Status is UNMANAGED. |
| Forged role, workload ID, arbitrary target or forbidden fixture | Typed broker rejects it and the collector records zero corresponding effects. |
| Exact allowed fixture, replay, stale epoch or permit | One collector effect permitted, with replays and stale requests rejected. |
| Invalid TLS, redirect, or DNS resolution outside the configured address set | No redirection or unapproved connection. An already-sent request may have an unknown outcome. |
| Cutoff before or during dispatch, including a stalled gateway and a busy operator queue | Host cutoff verified while an ordinary request is still pending. Calibrated capture shows no broker egress after the observation. A collector receipt proves only what arrived before cutoff. |
| Crash, reboot, or gateway loss | Admissions close, network rules remain effective, and managed domains do not autostart. |
| Interrupted send or journal fault | No retry after an ambiguous send and no effect when the required admission record cannot be committed. |
| Evidence altered or truncated | Local consistency or an independent checkpoint verification identifies the mismatch. |
| Updated image, policy, or backend | Explicit re-enrollment or requalification before sensitive use. |

Release only configurations with independently reproduced evidence and an independent security assessment. The source-commit wheel used in development is a separate qualification artifact from a published PyPI release.

The validated host and runtime versions bound the qualification. The emergency socket reports broker admission and network cutoff. The normal operator socket provides separate guest and hypervisor observations and records containment and termination in the journal.
