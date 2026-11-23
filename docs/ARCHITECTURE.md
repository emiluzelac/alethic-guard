# Runtime architecture

The Linux host daemon starts transient KVM domains paused, verifies their active device definition, and resumes them only after inspection. The VM sees a private writable overlay, approved read-only inputs, and, for the mediated profile, one dedicated virtio-serial port. Its libvirt management interface stays on the host.

Each mediated launch has a separate unprivileged gateway UID and network namespace. The daemon passes the gateway an already connected QEMU Unix socket. The guest supplies a request UUID, a typed operation name, and a fixture selector. The host derives the workload identity and generation from the bound gateway's kernel peer credentials. It constructs exact public fixture bytes and pins the destination to a host-approved TLS endpoint.

The unprivileged controller owns the writable Alethic kernel and its separate governance store. It evaluates a bounded in-process validator against an immutable policy snapshot. The daemon binds a one-use grant to the workload, generation, policy digest, epoch, action, controller incarnation, gateway identity, and a short monotonic expiry. It consumes the grant and journals admission in the same database transaction. The gateway checks again before connecting and before writing the HTTPS request.

The gateway veth supplies a separate host cutoff even when the gateway cannot cooperate. The daemon records the cutoff and the collector's acknowledgment as separate events. A containment result concerns the local boundary. Acknowledgment or reconciliation establishes the collector result.
