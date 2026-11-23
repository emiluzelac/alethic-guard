# Alethic Guard v0.3.0

Linux x86-64 lab preview for Ubuntu 24.04 with KVM. The archive includes the host daemon, gateway, Python wheel, policy examples, and local-model lab procedure. The emergency socket can stop an enrolled VM while ordinary operator requests are queued.

- [Download the Linux archive](alethic-guard-0.3.0-linux-x86_64.tar.gz) · [SHA-256 checksum](SHA256SUMS)
- [Install guide](https://github.com/emiluzelac/alethic-guard/blob/v0.3.0/docs/DEPLOY_LINUX.md) · [Tested configurations](https://github.com/emiluzelac/alethic-guard/blob/v0.3.0/docs/GUARANTEE_MATRIX.md)
- [Read the replay results](QUALIFICATION.md) · [Download lab evidence and verifier](alethic-guard-v0.3.0-lab-evidence.tar.gz) · [Evidence checksum](EVIDENCE-SHA256)

Save the Linux archive and `SHA256SUMS` in the same directory, then run `sha256sum -c SHA256SUMS` before unpacking. Use `sha256sum -c EVIDENCE-SHA256` to verify the separate evidence archive.
