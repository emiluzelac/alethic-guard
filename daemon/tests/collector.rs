use alethic_guardd::collector::{Collector, GuestRequest, public_ip};
use std::net::{IpAddr, SocketAddr};
use uuid::Uuid;

#[test]
fn test_rejected_destination_and_redirect_have_no_side_effect() {
    for target in [
        "https://user@collector.example/v1/fixture",
        "http://collector.example/v1/fixture",
        "https://collector.example/v1/../fixture",
        "https://collector.example/v1/fixture?next=/other",
        "https://collector.example/v1/%2e%2e/fixture",
        "https://COLLECTOR.example/v1/fixture",
        "https://127.0.0.1/v1/fixture",
    ] {
        assert!(Collector::parse_url(target).is_err(), "{target}");
    }
    let parsed = Collector::parse_url("https://collector.example:8443/v1/fixture").unwrap();
    assert_eq!(parsed.host, "collector.example");
    assert_eq!(parsed.port, 8443);
    assert_eq!(parsed.path, "/v1/fixture");
}

#[test]
fn collector_never_pins_local_or_unapproved_addresses() {
    for address in [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.1.2",
        "100.64.1.2",
        "::1",
        "fd00::1",
        "::ffff:8.8.8.8",
    ] {
        assert!(!public_ip(address.parse::<IpAddr>().unwrap()));
    }
    let c = Collector::parse_url("https://collector.example/v1/fixture").unwrap();
    assert!(
        c.validate_resolved(
            &["45.91.11.1".parse().unwrap()],
            ["45.91.11.1:443", "127.0.0.1:443"].map(|ip| ip.parse::<SocketAddr>().unwrap()),
        )
        .is_err()
    );
}

#[test]
fn test_guest_cannot_supply_role_workload_labels_or_target() {
    let request = format!(
        r#"{{"request_id":"{}","operation":"collector.publish","fixture_id":"public-demo"}}"#,
        Uuid::new_v4()
    );
    let valid: GuestRequest = serde_json::from_str(&request).unwrap();
    assert!(valid.payload().is_ok());
    for field in ["role", "workload_id", "data_labels", "target", "payload"] {
        assert!(
            serde_json::from_str::<GuestRequest>(&format!(
                r#"{},"{field}":"forbidden"}}"#,
                request.trim_end_matches('}')
            ))
            .is_err()
        );
    }
    let invalid: GuestRequest =
        serde_json::from_str(&request.replace("public-demo", "private-canary")).unwrap();
    assert!(invalid.payload().is_err());
}

#[test]
fn release_evidence_uses_only_the_host_approved_record_and_selector() {
    let digest = "a".repeat(64);
    let commit = "b".repeat(40);
    let token = "c".repeat(32);
    let config = serde_json::from_value::<alethic_guardd::collector::CollectorConfig>(
        serde_json::json!({
            "target": "https://collector.example/v1/release-evidence",
            "addresses": ["45.91.11.1"],
            "gateway": "/usr/local/bin/gateway",
            "controller_socket": "/run/controller.sock",
            "controller_uid": 1000,
            "release_evidence": {
                "record": {"artifact_sha256": digest, "commit": commit, "verdict": "pass", "version": 1},
                "writer_token": token,
            }
        }),
    )
    .unwrap();
    let mut request = GuestRequest {
        request_id: Uuid::new_v4(),
        operation: "collector.publish".to_owned(),
        fixture_id: "release-evidence".to_owned(),
    };
    let delivery = config.delivery(&request).unwrap().unwrap();
    let expected = format!(
        r#"{{"artifact_sha256":"{digest}","commit":"{commit}","verdict":"pass","version":1}}"#
    );
    assert_eq!(delivery.body().unwrap(), expected.as_bytes());
    request.fixture_id = "public-demo".to_owned();
    assert!(config.delivery(&request).is_err());

    let mut invalid = config;
    invalid
        .release_evidence
        .as_mut()
        .unwrap()
        .writer_token
        .push('\n');
    request.fixture_id = "release-evidence".to_owned();
    assert!(invalid.delivery(&request).is_err());
    invalid.release_evidence = None;
    assert!(invalid.delivery(&request).is_err());
    request.fixture_id = "public-demo".to_owned();
    assert!(invalid.delivery(&request).unwrap().is_none());
}
