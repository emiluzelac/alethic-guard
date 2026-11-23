use alethic_guardd::GuardResult;
use serde::Deserialize;
use std::io::{BufRead, BufReader, Read};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    idempotency_key: Uuid,
    payload_sha256: String,
}

pub fn verify_receipt(stream: impl Read, key: Uuid, digest: &str) -> GuardResult<()> {
    let mut input = BufReader::new(stream.take(4096));
    let mut line = String::new();
    input.read_line(&mut line)?;
    let status = line
        .trim_end_matches("\r\n")
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    if status.first() != Some(&"HTTP/1.1") || !matches!(status.get(1), Some(&"200" | &"201")) {
        return Err("collector did not acknowledge the effect".into());
    }
    let mut content_length = None;
    loop {
        line.clear();
        input.read_line(&mut line)?;
        if line == "\r\n" {
            break;
        }
        if !line.ends_with("\r\n") {
            return Err("incomplete collector response".into());
        }
        let (name, value) = line.split_once(':').ok_or("invalid collector header")?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("collector returned unsupported transfer encoding".into());
        }
        if name.eq_ignore_ascii_case("content-length") {
            let length: usize = value.trim().parse()?;
            if length > 1024 || content_length.replace(length).is_some() {
                return Err("invalid collector response length".into());
            }
        }
    }
    let mut payload = vec![0; content_length.ok_or("missing response length")?];
    input.read_exact(&mut payload)?;
    let receipt: Receipt = serde_json::from_slice(&payload)?;
    if receipt.idempotency_key != key || receipt.payload_sha256 != digest {
        return Err("collector receipt differs from the admitted effect".into());
    }
    Ok(())
}
