use alethic_guard_gateway::receipt::verify_receipt;
use std::io::Cursor;
use uuid::Uuid;

#[test]
fn test_collector_receipt_requires_exact_effect_and_no_redirect() {
    let key = Uuid::parse_str("7503c88c-ee56-49a3-8ca0-96956d727158").unwrap();
    let body = format!(r#"{{"idempotency_key":"{key}","payload_sha256":"expected"}}"#);
    let response = |status| {
        format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    assert!(verify_receipt(Cursor::new(response("200 OK")), key, "expected").is_ok());
    assert!(
        verify_receipt(
            Cursor::new(response("307 Temporary Redirect")),
            key,
            "expected"
        )
        .is_err()
    );
    assert!(verify_receipt(Cursor::new(response("200 OK")), key, "different").is_err());
    assert!(
        verify_receipt(
            Cursor::new("HTTP/1.1 200 OK\r\nContent-Length: 12000\r\n\r\n"),
            key,
            "expected"
        )
        .is_err()
    );
}
