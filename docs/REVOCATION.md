# Revocation and recovery

Pause stops admission, invalidates grants, suspends the VM, and closes any gateway. Resume requires an operator, verified domain configuration, and a fresh gateway binding.

Run `sudo alethic-guard workload cutoff ID` to fence broker admissions and cut broker networking through the dedicated host-root socket. Guard tracks broker links before creating them, so this path can identify the link while the ordinary registry or hypervisor is busy. Guard lowers the host link if present, installs and verifies deny rules, and durably latches the cutoff before acknowledging success. The response records host wall-clock and monotonic observation times. Run `contain` or `terminate` afterward for VM inspection and cleanup. Those commands also try the dedicated cutoff before joining the ordinary operator queue.

Contain durably marks a workload as containing and advances its epoch. For an offline VM its verified absence of network interfaces supplies the guest boundary. For the mediated profile the daemon independently installs a host deny, lowers the host veth, stops gateway processes, and verifies the link is gone. It can perform this path while a gateway is stalled. A new launch requires verified shutdown and an explicit operator release.

Terminate applies containment and asks the hypervisor to stop the VM. Guard checks both the hypervisor and host process state before reporting shutdown. If an observer fails or a transition is interrupted, Guard keeps the durable containment state and reports the affected boundary as unknown.

A gateway rechecks authority before opening the TLS connection and before writing the authorized request. The revocation barrier is the verified host cutoff after fencing. Data already past that boundary may reach the collector. Use the emergency response for the host network observation and the normal containment or termination response for the hypervisor observation.

An effect journal entry records the durable redemption transaction. A transaction already underway can commit while cutoff installs the host deny. Guard checks the fence again before returning transport authority, and the host network cutoff covers a request that already had authority.

Crash recovery changes any incomplete admitted effect to `OUTCOME_UNKNOWN`. Use `workload effect-status ID --request REQUEST_ID` to obtain the collector idempotency key. Retrieve the matching receipt over the collector's independently authorized operator channel, then use `workload reconcile-receipt ID --request REQUEST_ID --receipt RECEIPT.json`. The daemon checks that the trusted operator's receipt matches the exact admitted key and payload digest. A missing response remains unknown.
