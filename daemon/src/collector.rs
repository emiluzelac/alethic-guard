use crate::GuardResult;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use uuid::Uuid;

pub const FIXTURE: &[u8] = br#"{"kind":"alethic-guard-synthetic","value":1}"#;
pub const RELEASE_EVIDENCE_PATH: &str = "/v1/release-evidence";
pub const BROKER_GROUP: u32 = 300_000;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuestRequest {
    pub request_id: Uuid,
    pub operation: String,
    pub fixture_id: String,
}

impl GuestRequest {
    pub fn payload(&self) -> GuardResult<&'static [u8]> {
        if self.operation != "collector.publish" || self.fixture_id != "public-demo" {
            return Err("unknown operation or public fixture".into());
        }
        Ok(FIXTURE)
    }

    pub fn selects_release_evidence(&self) -> bool {
        self.operation == "collector.publish" && self.fixture_id == "release-evidence"
    }

    pub fn payload_digest(&self) -> GuardResult<String> {
        Ok(format!("{:x}", Sha256::digest(self.payload()?)))
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorConfig {
    pub target: String,
    pub addresses: Vec<IpAddr>,
    #[serde(default)]
    pub gateway: PathBuf,
    pub controller_socket: PathBuf,
    pub controller_uid: u32,
    pub ca_file: Option<PathBuf>,
    pub release_evidence: Option<ReleaseDelivery>,
}

impl CollectorConfig {
    pub fn delivery(&self, request: &GuestRequest) -> GuardResult<Option<&ReleaseDelivery>> {
        if let Some(delivery) = &self.release_evidence {
            if request.selects_release_evidence()
                && Collector::parse_url(&self.target)?.path == RELEASE_EVIDENCE_PATH
            {
                delivery.body()?;
                return Ok(Some(delivery));
            }
            return Err("unapproved release evidence request or destination".into());
        }
        request.payload()?;
        Ok(None)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseDelivery {
    pub record: ReleaseEvidence,
    pub writer_token: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseEvidence {
    artifact_sha256: String,
    commit: String,
    verdict: Verdict,
    version: u8,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Verdict {
    Pass,
    Fail,
}

impl ReleaseDelivery {
    pub fn body(&self) -> GuardResult<Vec<u8>> {
        let lowercase_hex = |value: &str, length| {
            value.len() == length
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if self.record.version != 1
            || !lowercase_hex(&self.record.artifact_sha256, 64)
            || !lowercase_hex(&self.record.commit, 40)
            || !(32..=128).contains(&self.writer_token.len())
            || !self
                .writer_token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        {
            return Err("invalid release evidence record or credential".into());
        }
        // The HTTPS receiver verifies these exact canonical bytes.
        Ok(serde_json::to_vec(&self.record)?)
    }
}

#[derive(Clone, Debug)]
pub struct Collector {
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Collector {
    pub fn parse_url(target: &str) -> GuardResult<Self> {
        let rest = target
            .strip_prefix("https://")
            .ok_or("collector requires HTTPS")?;
        let (authority, raw_path) = rest
            .split_once('/')
            .ok_or("collector requires an explicit path")?;
        let (host, port) = if let Some((name, raw_port)) = authority.split_once(':') {
            let port = raw_port.parse::<u16>()?;
            if port == 0 || port == 443 || port.to_string() != raw_port {
                return Err("noncanonical collector port".into());
            }
            (name, port)
        } else {
            (authority, 443)
        };
        let mut labels = host.split('.').peekable();
        if host.len() > 253
            || !host.contains('.')
            || !labels.all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
            || !host
                .rsplit('.')
                .next()
                .unwrap_or("")
                .bytes()
                .all(|b| b.is_ascii_lowercase())
        {
            return Err("noncanonical collector hostname".into());
        }
        if raw_path.len() > 200
            || !raw_path.split('/').all(|part| {
                !part.is_empty()
                    && !matches!(part, "." | "..")
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            })
        {
            return Err("noncanonical collector path".into());
        }
        Ok(Self {
            host: host.into(),
            port,
            path: format!("/{raw_path}"),
        })
    }

    pub fn validate_resolved(
        &self,
        addresses: &[IpAddr],
        resolved: impl IntoIterator<Item = SocketAddr>,
    ) -> GuardResult<Vec<SocketAddr>> {
        let allowed: BTreeSet<_> = addresses.iter().copied().collect();
        if allowed.is_empty()
            || allowed.len() != addresses.len()
            || allowed.len() > 16
            || allowed.iter().any(|ip| !public_ip(*ip))
        {
            return Err("collector requires distinct global unicast IP addresses".into());
        }
        let resolved: BTreeSet<_> = resolved.into_iter().collect();
        if resolved.is_empty()
            || resolved
                .iter()
                .any(|address| address.port() != self.port || !allowed.contains(&address.ip()))
        {
            return Err("collector DNS returned an empty or out-of-policy address set".into());
        }
        Ok(resolved.into_iter().collect())
    }

    pub fn resolve(&self, addresses: &[IpAddr]) -> GuardResult<Vec<SocketAddr>> {
        let output = crate::vm::command_with_timeout(
            "3s",
            "/usr/bin/getent",
            &[OsStr::new("ahosts"), OsStr::new(&self.host)],
            None,
        )?;
        let resolved = output
            .lines()
            .map(|line| {
                let value = line
                    .split_whitespace()
                    .next()
                    .ok_or("invalid resolver response")?;
                Ok::<_, Box<dyn std::error::Error>>(SocketAddr::new(value.parse()?, self.port))
            })
            .collect::<GuardResult<Vec<_>>>()?;
        self.validate_resolved(addresses, resolved)
    }
}

pub fn public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            a != 0
                && a != 127
                && a < 224
                && !ip.is_private()
                && !ip.is_link_local()
                && !ip.is_documentation()
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 198 && (18..=19).contains(&b))
                && !(a == 192 && ((b == 0 && c == 0) || (b == 88 && c == 99)))
        }
        IpAddr::V6(ip) => {
            let [a, b, ..] = ip.segments();
            (0x2000..0x4000).contains(&a)
                && a != 0x3fff
                && !(a == 0x2001 && (b == 0xdb8 || b < 0x0200))
                && a != 0x2002
        }
    }
}
