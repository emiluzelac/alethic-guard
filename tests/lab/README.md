# Lab procedures

Use a disposable Ubuntu 24.04 host or nested KVM guest with a signed cloud image. Install cloud-image utilities, the Guard packages, and tcpdump. Keep the host disconnected from production networks. Prepare a collector namespace with a veth named `guard-observe` on the lab host. The probe fixtures use `198.18.0.2` and `fd42:abcd::2` in that namespace. For the mediated test, assign the fixed lab address aliases used by `qualify.sh` inside the same isolated namespace. Map the collector hostname to the appropriate address in lab DNS. Route these addresses only to the controlled namespace.

Build a synthetic NoCloud input image with `guest/image/make-probe-input SCRATCH OUTPUT [offline|broker]`. Use the signed image and the probe image to enroll the workload under the matching profile. Run the TLS test collector in its own namespace with `collector.py PORT CERT KEY RECEIPT_DIR`. Keep the generated lab key in the lab.

Run `qualify.sh offline ID EVIDENCE_DIR` and `qualify.sh broker ID EVIDENCE_DIR`. The script saves the active XML, interface list, guest serial output, calibrated packet capture, operator reports and evidence journal. Read the packet capture alongside the positive controls and the observed collector receipts. Repeat the broker test with each address family and an independently captured race around host cutoff. Perform the reboot test on the disposable lab host and confirm that workloads still require explicit release.

The packet tests intentionally use synthetic markers. A UDP probe on port 443 verifies the path at the transport layer. It does not exercise a full QUIC handshake.
