# Revocation and recovery

Pause stops admission, invalidates grants, suspends the VM, and closes any gateway. Resume requires an operator, verified domain configuration, and a fresh gateway binding.

Run `sudo alethic-guard workload cutoff ID` to fence broker admissions and cut broker networking through the dedicated host-root socket. Its listener runs on a separate thread in the Guard daemon. Guard tracks broker links before creating them, so this path can identify the link while the ordinary registry or hypervisor is busy. Guard lowers the host link if present, installs and verifies deny rules, and durably latches the cutoff before acknowledging success. The response records host wall-clock and monotonic observation times. Use `contain` or `terminate` for VM inspection and cleanup. Those commands try the dedicated cutoff before joining the ordinary operator queue for their VM operations.

Run `sudo alethic-guard workload emergency-terminate ID` to request immediate VM shutdown on the same root-only socket. Guard first attempts the admission and network fence. It uses bounded libvirt commands to identify the enrolled transient domain by name and UUID, stop it, and observe whether the domain is still listed. It also checks host process state for a matching QEMU instance. `shutdown: VERIFIED` means both observers confirm absence at the time of the report, including when a retry finds the VM already stopped. A racing guest transition or unavailable observation yields `shutdown: UNKNOWN`. A domain or emulator that remains present yields `shutdown: FAILED`. The response reports the broker fence and shutdown observations independently.

When the ordinary operator queue is available again, run `workload terminate ID` to reconcile the registry, gateway state, and journal. Once shutdown is verified and recorded, `workload release ID` clears the durable fence. The emergency listener and the ordinary queue both run inside the Guard daemon, so both require the host daemon process.

## Recovery with the daemon stopped

On the Guard host, stop `alethic-guardd.service` if the service manager is trying to restart it or the process is hung. Run the installed daemon binary directly as root.

```sh
sudo systemctl stop alethic-guardd.service
sudo /opt/alethic-guard/current/bin/alethic-guardd --recover WORKLOAD_ID
```

For a custom deployment, use its installed binary and supply the absolute data directory as the last argument. Recovery takes the same exclusive state lock as the daemon. It reads the existing enrollment, latches the admission fence, cuts the registered broker network, and uses libvirt and process observations to verify shutdown of the enrolled transient domain. Recovery works without either Guard socket or the Python controller.

The JSON response reports admission fence persistence, broker cutoff, VM shutdown, and registry and journal persistence independently. Exit status zero requires all four to be `VERIFIED`. A partial result requires investigation and a retry after restoring the failed dependency. If libvirt is unavailable, restore the hypervisor service and repeat recovery. Once recovery is verified, start Guard and check workload status. A new launch requires an explicit `workload release`.

Contain durably marks a workload as containing and advances its epoch. For an offline VM its verified absence of network interfaces supplies the guest boundary. For the mediated profile the daemon independently installs a host deny, lowers the host veth, stops gateway processes, and verifies the link is gone. It can perform this path while a gateway is stalled. A new launch requires verified shutdown and an explicit operator release.

If the response to an operator release is lost, query `workload status ID` to observe the recorded lifecycle before attempting a fresh start. Starting also requires an open emergency fence. A workload whose installed image or policy has changed requires a new enrollment with the intended artifacts.

Terminate applies containment and asks the hypervisor to stop the VM. Guard checks both the hypervisor and host process state before reporting shutdown. If an observer fails or a transition is interrupted, Guard keeps the durable containment state and reports the affected boundary as unknown.

A gateway rechecks authority before opening the TLS connection and before writing the authorized request. The revocation barrier is the verified host cutoff after fencing. Data already past that boundary may reach the collector. The `cutoff` response records the network observation. The `emergency-terminate` response also records the VM shutdown observation. Ordinary termination reconciles the registry and journal afterward.

An effect journal entry records the durable redemption transaction. A transaction already underway can commit while cutoff installs the host deny. Guard checks the fence again before returning transport authority, and the host network cutoff covers a request that already had authority.

An unfinished admitted effect may still show `STARTED` after `cutoff`. Complete `contain` or `terminate` with verified broker cutoff to recover unfinished effects. Daemon crash recovery also moves incomplete admitted effects to `OUTCOME_UNKNOWN`. Use `workload effect-status ID --request REQUEST_ID` to confirm that outcome and obtain the collector idempotency key. Retrieve the matching receipt over the collector's independently authorized operator channel, then use `workload reconcile-receipt ID --request REQUEST_ID --receipt RECEIPT.json`. The daemon checks that the trusted operator's receipt matches the exact admitted key and payload digest. A matching receipt confirms collector acknowledgment. Capture timing establishes when the effect crossed the host boundary.
