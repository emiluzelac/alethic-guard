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

Production security claims require independently reproduced evidence and an independent security assessment for the supported configuration. The source-commit wheel used in development is a separate qualification artifact from a published PyPI release.

The validated host and runtime versions bound the qualification. The emergency socket reports broker admission and network cutoff. Its emergency termination command additionally reports an independent VM shutdown observation. The normal operator socket records containment and termination in the journal.

## Planned local agent qualification for v0.3.0

Run a pinned open-weight CPU model inside an enrolled VM. Record the model and guest image digests, the VM resources, and the policy digest. Have the model complete a normal task with a synthetic document through the restricted guest tool interface.

| Condition | Required observation |
| --- | --- |
| Normal task and a separately approved collector operation | The guest completes the task. The collector receives the exact host-approved record and returns a matching receipt. |
| Fixed denial cases for an unmounted input, an undeclared tool, and direct networking to a controlled lab receiver | The workload cannot read the unmounted input, the tool request is denied, and the receiver records zero unauthorized deliveries. Use synthetic data throughout. |
| Ordinary operator queue is stalled during an active workload | The emergency operation fences admission and stops the exact enrolled VM within a documented timeout. Independent host observations corroborate shutdown, and restart requires operator release. |
| Shutdown observation is unavailable | The emergency operation reports the shutdown as unknown while preserving the admission fence. |
| Independent reproduction | A second operator runs the procedures from the tagged source and checksummed archive. The published results identify those exact inputs and include sanitized observations and verification of a checkpoint retained off-host. |
