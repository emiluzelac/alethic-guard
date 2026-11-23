# Threat model

The boundary covers explicitly enrolled VMs on a qualified Linux host. Treat all guest programs, model output, and guest administrator accounts as untrusted. Trust the operator, the host kernel and hardware, libvirt and QEMU, and the host Guard services and state. An unenrolled domain has no Guard assurance.

The offline profile removes guest networking and host data-sharing devices. Source data arrives on an approved read-only block volume. The guest runs on its own private writable disk overlay. The host domain definition and VM status are the sources of truth for this boundary. Guest activity remains possible inside the VM, including use of a local shell. The tool policy governs host-mediated operations.

The mediated profile exposes one narrow per-domain channel to a host gateway. Access to the host management socket, writable Alethic instance, and authority to issue execution grants is restricted to host principals. Treat already-sent effects as a separate remote state. The host cannot recall delivered data or prove a third party canceled a request without independent confirmation.

Both profiles expose a serial console to the host through libvirt. Guest code can write arbitrary text to it. Treat console captures as potentially sensitive guest output and handle them separately from the Guard evidence journal.

Host compromise, hypervisor escape, hardware side channels, and covert channels fall outside the guarantee. A broker-approved recipient may receive whatever the operator approved for that operation.
