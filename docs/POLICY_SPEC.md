# Workload policy

The schema at [policy/schema-v1.json](../policy/schema-v1.json) specifies version `guard.alethic.dev/v1`. `spec.profile` selects the behavior. A backend must advertise the necessary capabilities before a profile can compile. The policy digest hashes canonical JSON after validation. Unknown fields, duplicate keys, tag directives, anchor and alias tokens, overlapping guest paths, and unsupported features cause a validation error.

Filesystem entries describe the image's guest mount convention. The host supplies at most one read-only input device plus a private writable VM disk. It does not attest to the guest's mount table. The tools list identifies the image's expected tools and potential broker operations. The host enforces the absence of a broker shell or generic HTTP operation.
