use alethic_guardd::policy::validate_compiled;
use serde_json::{Value, json};

fn offline() -> Value {
    json!({
        "api_version": "guard.alethic.dev/v1",
        "kind": "WorkloadPolicy",
        "metadata": {"name": "offline-research"},
        "spec": {
            "profile": "offline-strict", "isolation": "vm-isolated",
            "enforce": true, "default_action": "deny",
            "filesystem": {
                "inputs": [{"path": "/data/approved", "access": "read_only"}],
                "outputs": [], "host_home_mount": "deny", "shared_clipboard": "deny",
                "sync_services": "deny"
            },
            "network": {
                "guest_direct_egress": "deny_all", "guest_inbound": "deny_all",
                "dns": "deny", "ipv6": "deny", "approved_broker_destinations": []
            },
            "tools": {"allowed": ["local_read"], "shell": "deny", "external_http": "deny"},
            "emergency": {
                "on_controller_unavailable": "deny_new_effects",
                "on_policy_engine_unavailable": "deny_new_effects",
                "restart_after_containment": "require_manual_release"
            },
            "evidence": {"host_side_events": "required", "include_sensitive_payloads": false}
        }
    })
}

fn validate(document: &Value) -> bool {
    validate_compiled(&serde_json::to_vec(document).unwrap(), "offline-research").is_ok()
}

#[test]
fn installed_policy_rejects_unsupported_keys_and_ambiguous_paths() {
    let mut policy = offline();
    assert!(validate(&policy));
    policy["spec"]["network"]["unsupported"] = json!(true);
    assert!(!validate(&policy));

    let mut policy = offline();
    policy["spec"]["filesystem"]["inputs"][0]["path"] = json!("/data/../approved");
    assert!(!validate(&policy));
}

#[test]
fn compiler_tool_and_destination_rules_are_rechecked_on_host() {
    let mut policy = offline();
    policy["spec"]["tools"]["allowed"] = json!(["collector.publish"]);
    assert!(!validate(&policy));

    policy["spec"]["profile"] = json!("allowlisted-api");
    assert!(!validate(&policy));
    policy["spec"]["network"]["approved_broker_destinations"] =
        json!(["https://collector.example/v1/fixture"]);
    assert!(validate(&policy));

    policy["spec"]["tools"]["allowed"] = json!(["local_read"]);
    assert!(!validate(&policy));
}

#[test]
fn installed_policy_rejects_noncanonical_or_duplicate_json() {
    let policy = offline();
    let pretty = serde_json::to_vec_pretty(&policy).unwrap();
    assert!(validate_compiled(&pretty, "offline-research").is_err());
    let canonical = serde_json::to_string(&policy).unwrap();
    let duplicate = canonical.replacen("\"enforce\":true", "\"enforce\":false,\"enforce\":true", 1);
    assert_ne!(duplicate, canonical);
    assert!(validate_compiled(duplicate.as_bytes(), "offline-research").is_err());
}
