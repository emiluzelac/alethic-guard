//! Validate the same schema at compilation and at the root authority boundary.

use crate::{GuardResult, collector::Collector};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub const MAX_POLICY_BYTES: usize = 65_536;

pub struct ApprovedPolicy {
    pub digest: String,
    pub has_input: bool,
    pub collector_target: Option<String>,
}

fn guest_path(path: &str) -> GuardResult<&str> {
    let rest = path
        .strip_prefix("/data/")
        .ok_or("guest volume must be under /data")?;
    if !rest.split('/').all(|part| {
        !part.is_empty()
            && !matches!(part, "." | "..")
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    }) {
        return Err("ambiguous guest volume path".into());
    }
    Ok(path)
}

pub fn validate_compiled(document: &[u8], name: &str) -> GuardResult<ApprovedPolicy> {
    static VALIDATOR: OnceLock<Result<jsonschema::Validator, String>> = OnceLock::new();

    if document.len() > MAX_POLICY_BYTES {
        return Err("policy exceeds maximum size".into());
    }
    let policy: Value = serde_json::from_slice(document)?;
    if serde_json::to_vec(&policy)? != document {
        return Err("expected JSON produced by the policy compiler".into());
    }
    let validator = VALIDATOR.get_or_init(|| {
        let schema = serde_json::from_str(include_str!("../../policy/schema-v1.json"))
            .map_err(|error| error.to_string())?;
        jsonschema::validator_for(&schema).map_err(|error| error.to_string())
    });
    let validator = validator
        .as_ref()
        .map_err(|_| "invalid embedded policy schema")?;
    if !validator.is_valid(&policy) || policy["metadata"]["name"] != name {
        return Err("unsupported policy fields or mismatched policy name".into());
    }
    let spec = &policy["spec"];
    let destinations = spec["network"]["approved_broker_destinations"]
        .as_array()
        .ok_or("missing approved destinations")?;
    let tools = spec["tools"]["allowed"]
        .as_array()
        .ok_or("missing tool allowlist")?;
    let collector_enabled = tools.iter().any(|tool| tool == "collector.publish");
    let collector_target = match (
        spec["profile"].as_str(),
        destinations.as_slice(),
        collector_enabled,
    ) {
        (Some("offline-strict"), [], false) => None,
        (Some("allowlisted-api"), [target], true) => {
            let target = target.as_str().ok_or("invalid collector target")?;
            Collector::parse_url(target)?;
            Some(target.to_owned())
        }
        _ => return Err("unsupported profile or inconsistent broker authorization".into()),
    };
    let volume = |role: &str| -> GuardResult<Option<&str>> {
        spec["filesystem"][role]
            .as_array()
            .ok_or("missing guest volume list")?
            .first()
            .map(|value| guest_path(value["path"].as_str().ok_or("missing guest path")?))
            .transpose()
    };
    let input = volume("inputs")?;
    let output = volume("outputs")?;
    if let (Some(input), Some(output)) = (input, output) {
        let a = std::path::Path::new(input);
        let b = std::path::Path::new(output);
        if a.starts_with(b) || b.starts_with(a) {
            return Err("input and output volumes overlap".into());
        }
    }
    Ok(ApprovedPolicy {
        digest: format!("sha256:{:x}", Sha256::digest(document)),
        has_input: input.is_some(),
        collector_target,
    })
}
