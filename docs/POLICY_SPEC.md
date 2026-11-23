# Workload policy

The schema at [policy/schema-v1.json](../policy/schema-v1.json) specifies version `guard.alethic.dev/v1`. `spec.profile` selects the behavior. A backend must advertise the necessary capabilities before a profile can compile. The policy digest hashes canonical JSON after validation. Unknown fields, duplicate keys, tag directives, anchor and alias tokens, overlapping guest paths, and unsupported features cause a validation error.

The matrix describes enforcement in the current Linux backend. Host-enforced fields describe an observed VM boundary or a check Guard performs. Guest-dependent fields describe behavior supplied by the guest image. Descriptive fields identify or constrain how Guard interprets the policy document.

| Policy field | Enforcement | What the field means |
| --- | --- | --- |
| `api_version`, `kind`, `metadata.name` | Descriptive, schema-validated | Identify the policy format and the installed policy selected for enrollment. |
| `spec.profile` | Host-enforced | The backend admits `offline-strict` or `allowlisted-api`. A mediated launch requires the supported broker configuration and an exact collector destination. |
| `spec.isolation`, `spec.enforce`, `spec.default_action` | Host-enforced | Require the supported VM boundary and a deny-by-default broker. Guard verifies the active VM device definition before start. |
| `filesystem.inputs[].access` | Host-enforced | Guard attaches at most one approved input as a read-only block device. |
| `filesystem.inputs[].path` | Guest-dependent | Identifies where the image expects to mount the input. The guest controls its mount table and file permissions. |
| `filesystem.outputs[].path`, `filesystem.outputs[].access` | Guest-dependent | Describe the output directory and expected access inside the guest. Guard provides a private writable disk, and the guest chooses where on that disk to write. |
| `filesystem.host_home_mount`, `filesystem.shared_clipboard`, `filesystem.sync_services` | Host-enforced at the host boundary | Guard's verified device definition excludes host file sharing and clipboard integration. A guest can run local processes, including sync software. |
| `network.guest_direct_egress`, `network.guest_inbound`, `network.dns`, `network.ipv6` | Host-enforced | The guest has no NIC, so it has no direct network path to external services. Guest loopback and the host broker's approved IPv6 route are separate. |
| `network.approved_broker_destinations` | Host-enforced | The mediated profile authorizes one exact HTTPS URL. The broker enforces a host-approved address set and verifies TLS. |
| `tools.allowed` for `collector.publish` | Host-enforced | This typed operation requires the mediated profile and an active host grant. |
| `tools.allowed` for `local_inference`, `local_read`, `local_write_results` | Guest-dependent | Identify expected guest capabilities. The image and its applications implement them. |
| `tools.shell`, `tools.external_http` | Host-enforced at the broker | The broker exposes neither a shell nor a generic HTTP operation. An administrator can still use a shell inside the guest. |
| `emergency.on_policy_engine_unavailable`, `emergency.on_controller_unavailable` | Host-enforced | New broker effects require current checks against the installed policy and a responsive controller. |
| `emergency.restart_after_containment` | Host-enforced | A contained workload needs a verified shutdown and explicit operator release before a fresh start. |
| `evidence.host_side_events`, `evidence.include_sensitive_payloads` | Host-enforced for the Guard journal | Required journal events record operational metadata and digests. Guest documents and request bodies stay outside the journal. Guest disk and console output are separate. |
