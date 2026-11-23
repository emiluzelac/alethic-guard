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
