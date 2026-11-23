# Production qualification fixtures

Use a dedicated Ubuntu 24.04 x86-64 KVM host with a fresh, disposable Guard state directory and no existing managed workloads. Install the archive following the [deployment guide](../../../docs/DEPLOY_LINUX.md). Stop the Guard systemd service before running these procedures. The scripts start and deliberately interrupt their own daemon processes.

Stage the qualified `noble-lab.qcow2` image and a small QCOW2 volume named `minimal.qcow2` in the approved image directory. Create the small volume with `qemu-img create -f qcow2 minimal.qcow2 16M`. Compile the `offline-research` policy with an empty `spec.filesystem.inputs` list and install it as `offline-research.json`. Make both images and the installed policy root-owned and read-only.

```sh
sudo install -d -m 0700 /run/alethic-guard
sudo python3 tests/lab/production/recovery.py > recovery.jsonl
sudo python3 tests/lab/production/repeat-shutdown.py 100 > repeated-shutdown.jsonl
```

Recovery starts the Ubuntu guest and a second KVM domain, then checks administrative ownership, the durable fence, shutdown with Guard down, and service reconciliation. The repeated test uses the small volume as a firmware-only KVM fixture so the timings measure shutdown under the listed conditions. It checks libvirt and QEMU process state independently after each shutdown. Retain the raw samples, counts, latency percentiles, and host configuration with the archive checksum.
