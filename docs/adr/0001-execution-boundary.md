# ADR 0001 — Separate governance and execution

Use a companion repository and release for Rust host services, policy, and operator packaging. Embed the public Python Alethic kernel in a dedicated controller only when governed actions are introduced.

Preserve percepts, beliefs, constraints, plans, evidence, predictions, and actions and the existing PROPOSE and COMMIT behavior. Use the public action API at Alethic commit a8fc86bf39f1286d9f7471ae4e8100b96bab3d30 for development. The initial adapter will need a separately published compatible wheel for release.

The daemon manages dedicated libvirt/QEMU/KVM domains. Offline domains have zero NICs and no tool channel. A mediated domain may have one dedicated virtio-serial endpoint backed by a host-owned Unix socket. The operator and Guard host services authenticate over host Unix sockets using credentials derived by the host. Runtime identity includes the enrollment and launch generation. Governance, admission, dispatch, and observed results are different events.
