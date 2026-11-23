//! The host veth is the only egress path for an unprivileged gateway instance.
use crate::{GuardResult, collector::public_ip, vm::command};
use serde_json::{Value, json};
use std::{ffi::OsStr, net::IpAddr};

const IP: &str = "/usr/sbin/ip";
const NFT: &str = "/usr/sbin/nft";

#[cfg(test)]
mod tests;

fn invoke(program: &str, args: &[&str], input: Option<&[u8]>) -> GuardResult<String> {
    let args: Vec<_> = args.iter().map(OsStr::new).collect();
    command(program, &args, input)
}

fn comparison(left: Value, right: Value) -> Value {
    json!({"match": {"op": "==", "left": left, "right": right}})
}

fn payload(protocol: &str, field: &str, value: Value) -> Value {
    comparison(
        json!({"payload": {"protocol": protocol, "field": field}}),
        value,
    )
}

fn expression_matches(actual: &Value, expected: &Value) -> bool {
    if expected.get("counter").is_some() {
        return actual.as_object().is_some_and(|entry| entry.len() == 1)
            && actual["counter"]
                .as_object()
                .is_some_and(|counts| counts.len() == 2)
            && actual["counter"]["packets"].is_u64()
            && actual["counter"]["bytes"].is_u64();
    }
    if actual == expected {
        return true;
    }
    if expected.get("masquerade").is_some() {
        return actual == &json!({"masquerade": {}});
    }

    // nft can report membership as an anonymous set or a conntrack bitmask list.
    if !actual.as_object().is_some_and(|entry| entry.len() == 1)
        || !actual["match"]
            .as_object()
            .is_some_and(|entry| entry.len() == 3)
    {
        return false;
    }
    let actual = &actual["match"];
    let expected = &expected["match"];
    let left = &expected["left"];
    if actual["left"] != *left {
        return false;
    }
    let right = &actual["right"];
    let op = actual["op"].as_str();
    let conntrack = left["ct"]["key"] == "state";
    if let Some(members) = expected["right"]["set"].as_array() {
        let observed = match op {
            Some("==" | "in") if right.as_object().is_some_and(|set| set.len() == 1) => {
                right["set"].as_array()
            }
            Some("in") if conntrack => right.as_array(),
            _ => None,
        };
        return observed.is_some_and(|values| {
            values.len() == members.len() && members.iter().all(|member| values.contains(member))
        });
    }
    conntrack && op == Some("in") && *right == expected["right"]
}

#[derive(Clone, Copy, Debug)]
pub struct Sandbox {
    slot: u16,
}

impl Sandbox {
    pub fn new(slot: u16) -> GuardResult<Self> {
        if (1..=4094).contains(&slot) {
            Ok(Self { slot })
        } else {
            Err("gateway slot outside reserved range".into())
        }
    }

    pub fn namespace(self) -> String {
        format!("aleg{}", self.slot)
    }
    fn host_link(self) -> String {
        format!("agw{}", self.slot)
    }
    fn peer_link(self) -> String {
        format!("age{}", self.slot)
    }
    fn table(self) -> String {
        format!("alethic_guard_{}", self.slot)
    }

    pub fn rules(self, addresses: &[IpAddr], port: u16) -> GuardResult<String> {
        if !addresses.is_empty() && (port == 0 || addresses.iter().any(|ip| !public_ip(*ip))) {
            return Err("refusing non-public collector address or missing port".into());
        }
        let link = self.host_link();
        let table = self.table();
        let allow = addresses.iter().map(|addr| {
            let family = if addr.is_ipv4() { "ip" } else { "ip6" };
            format!(
                "iifname \"{link}\" {family} daddr {addr} tcp dport {port} ct state {{ new, established }} accept;\n\
                 oifname \"{link}\" {family} saddr {addr} tcp sport {port} ct state established accept;\n"
            )
        }).collect::<String>();
        let nat = addresses
            .iter()
            .map(|addr| {
                let family = if addr.is_ipv4() { "ip" } else { "ip6" };
                format!("iifname \"{link}\" {family} daddr {addr} tcp dport {port} masquerade;\n")
            })
            .collect::<String>();
        let neighbor = if addresses.iter().any(IpAddr::is_ipv6) {
            format!(
                "iifname \"{link}\" ip6 hoplimit 255 icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} accept;"
            )
        } else {
            String::new()
        };
        Ok(format!(
            "add table inet {table}\nflush table inet {table}\n\
             table inet {table} {{\n\
               chain input {{ type filter hook input priority -250; policy accept;\n\
                 {neighbor}\n iifname \"{link}\" counter drop; }}\n\
               chain forward {{ type filter hook forward priority -10; policy accept;\n\
                 {allow} iifname \"{link}\" counter drop; oifname \"{link}\" counter drop; }}\n\
               chain postrouting {{ type nat hook postrouting priority srcnat; policy accept;\n\
                 {nat} }}\n}}\n"
        ))
    }

    fn install(self, addresses: &[IpAddr], port: u16) -> GuardResult<()> {
        invoke(
            NFT,
            &["-f", "-"],
            Some(self.rules(addresses, port)?.as_bytes()),
        )?;
        let active = invoke(NFT, &["-j", "list", "table", "inet", &self.table()], None)?;
        let active: Value = serde_json::from_str(&active)?;
        self.verify_readback(&active, addresses, port)
    }

    fn verify_readback(self, active: &Value, addresses: &[IpAddr], port: u16) -> GuardResult<()> {
        let list = active["nftables"]
            .as_array()
            .ok_or("invalid nft ruleset observation")?;
        let table = self.table();
        let link = self.host_link();
        let interface = |direction| comparison(json!({"meta": {"key": direction}}), json!(link));
        let drop = |direction| {
            vec![
                interface(direction),
                json!({"counter": null}),
                json!({"drop": null}),
            ]
        };
        let mut input = Vec::new();
        let mut forward = Vec::new();
        let mut postrouting = Vec::new();
        if addresses.iter().any(IpAddr::is_ipv6) {
            input.push(vec![
                interface("iifname"),
                payload("ip6", "hoplimit", json!(255)),
                payload(
                    "icmpv6",
                    "type",
                    json!({"set": ["nd-neighbor-solicit", "nd-neighbor-advert"]}),
                ),
                json!({"accept": null}),
            ]);
        }
        input.push(drop("iifname"));
        for address in addresses {
            let family = if address.is_ipv4() { "ip" } else { "ip6" };
            let outbound = vec![
                interface("iifname"),
                payload(family, "daddr", json!(address.to_string())),
                payload("tcp", "dport", json!(port)),
            ];
            let mut allow = outbound.clone();
            allow.extend([
                comparison(
                    json!({"ct": {"key": "state"}}),
                    json!({"set": ["new", "established"]}),
                ),
                json!({"accept": null}),
            ]);
            forward.push(allow);
            forward.push(vec![
                interface("oifname"),
                payload(family, "saddr", json!(address.to_string())),
                payload("tcp", "sport", json!(port)),
                comparison(json!({"ct": {"key": "state"}}), json!("established")),
                json!({"accept": null}),
            ]);
            let mut nat = outbound;
            nat.push(json!({"masquerade": null}));
            postrouting.push(nat);
        }
        forward.extend([drop("iifname"), drop("oifname")]);

        let mut chains = [
            ("input", "filter", -250, input),
            ("forward", "filter", -10, forward),
            ("postrouting", "nat", 100, postrouting),
        ]
        .map(|(name, kind, priority, rules)| (name, kind, priority, false, rules.into_iter()));
        let mut table_seen = false;
        for row in list {
            let (kind, item) = row
                .as_object()
                .filter(|row| row.len() == 1)
                .and_then(|row| row.iter().next())
                .ok_or("invalid nft table entry")?;
            if kind == "metainfo" && item.is_object() {
                continue;
            }
            if item["family"] != "inet" {
                return Err("unexpected nft table family".into());
            }
            if kind == "table" {
                if table_seen
                    || item["name"] != table
                    || item.get("flags").is_some_and(|flags| flags != &json!([]))
                {
                    return Err("gateway table readback does not identify one active table".into());
                }
                table_seen = true;
                continue;
            }
            if item["table"] != table {
                return Err("unexpected nft table entry".into());
            }
            match kind.as_str() {
                "chain" => {
                    let (name, chain_type, priority, seen, _) = chains
                        .iter_mut()
                        .find(|(name, ..)| item["name"] == *name)
                        .ok_or("unexpected gateway chain")?;
                    if *seen
                        || item["type"] != *chain_type
                        || item["hook"] != *name
                        || item["prio"] != *priority
                        || item["policy"] != "accept"
                    {
                        return Err(format!("gateway {name} base chain readback mismatch").into());
                    }
                    *seen = true;
                }
                "rule" => {
                    let (name, _, _, _, rules) = chains
                        .iter_mut()
                        .find(|(name, ..)| item["chain"] == *name)
                        .ok_or("unexpected gateway rule chain")?;
                    let expected = rules
                        .next()
                        .ok_or_else(|| format!("unexpected rule in gateway {name} chain"))?;
                    if !item["expr"].as_array().is_some_and(|actual| {
                        actual.len() == expected.len()
                            && actual
                                .iter()
                                .zip(&expected)
                                .all(|(actual, expected)| expression_matches(actual, expected))
                    }) {
                        return Err(format!("gateway {name} rule readback mismatch").into());
                    }
                }
                _ => return Err("unexpected nft table entry".into()),
            }
        }
        if !table_seen
            || chains
                .iter()
                .any(|(_, _, _, seen, rules)| !seen || rules.len() != 0)
        {
            return Err("incomplete gateway table readback".into());
        }
        Ok(())
    }

    pub fn link_present(self) -> GuardResult<bool> {
        let links: Value = serde_json::from_str(&invoke(IP, &["-j", "link", "show"], None)?)?;
        self.observed_link_present(&links)
    }

    fn observed_link_present(self, links: &Value) -> GuardResult<bool> {
        let links = links.as_array().ok_or("invalid link observation")?;
        let host_link = self.host_link();
        if links.iter().any(|row| row["ifname"] == host_link) {
            return Ok(true);
        }
        if links
            .iter()
            .any(|row| row["ifname"].as_str().is_none_or(str::is_empty))
        {
            return Err("incomplete host link observation".into());
        }
        Ok(false)
    }

    pub fn ensure_clean(self) -> GuardResult<()> {
        let exists = invoke(IP, &["netns", "list"], None)?
            .lines()
            .any(|line| line.split_whitespace().next() == Some(self.namespace().as_str()));
        let tables: Value = serde_json::from_str(&invoke(NFT, &["-j", "list", "tables"], None)?)?;
        let configured = tables["nftables"]
            .as_array()
            .ok_or("invalid nft table list")?
            .iter()
            .any(|row| row["table"]["family"] == "inet" && row["table"]["name"] == self.table());
        if exists || configured || self.link_present()? {
            return Err("gateway network slot is already in use".into());
        }
        Ok(())
    }

    pub fn create(self) -> GuardResult<()> {
        self.ensure_clean()?;
        self.install(&[], 0)?;
        let ns = self.namespace();
        let host = self.host_link();
        let peer = self.peer_link();
        invoke(IP, &["netns", "add", &ns], None)?;
        invoke(
            IP,
            &[
                "link", "add", &host, "type", "veth", "peer", "name", &peer, "netns", &ns,
            ],
            None,
        )?;
        invoke(IP, &["link", "set", &host, "up"], None)?;
        invoke(IP, &["-n", &ns, "link", "set", &peer, "up"], None)?;
        let [b, c] = (self.slot * 4).to_be_bytes();
        let gw4 = format!("10.254.{b}.{}", c + 1);
        let peer4 = format!("10.254.{b}.{}", c + 2);
        let gw6 = format!("fd42:a1e7:{:x}::1", self.slot);
        let peer6 = format!("fd42:a1e7:{:x}::2", self.slot);
        for (family, gateway, ip, cidr) in [("-4", gw4, peer4, "30"), ("-6", gw6, peer6, "64")] {
            let extras = if family == "-6" {
                vec!["nodad"]
            } else {
                vec![]
            };
            let host_address = format!("{gateway}/{cidr}");
            let peer_address = format!("{ip}/{cidr}");
            let mut host_command = vec![family, "addr", "add", &host_address, "dev", &host];
            host_command.extend(&extras);
            let mut peer_command = vec![
                "-n",
                &ns,
                family,
                "addr",
                "add",
                &peer_address,
                "dev",
                &peer,
            ];
            peer_command.extend(&extras);
            invoke(IP, &host_command, None)?;
            invoke(IP, &peer_command, None)?;
            invoke(
                IP,
                &[
                    "-n", &ns, family, "route", "add", "default", "via", &gateway, "dev", &peer,
                ],
                None,
            )?;
        }
        Ok(())
    }

    pub fn enable(self, addresses: &[IpAddr], port: u16) -> GuardResult<()> {
        if !self.link_present()? || addresses.is_empty() {
            return Err("gateway link or approved collector addresses missing".into());
        }
        self.install(addresses, port)
    }

    pub fn seal(self) -> GuardResult<()> {
        let filter = self.install(&[], 0);
        let link = self.host_link();
        if self.link_present()? {
            invoke(IP, &["link", "set", &link, "down"], None)?;
            let observed: Value =
                serde_json::from_str(&invoke(IP, &["-j", "link", "show", "dev", &link], None)?)?;
            let flags = observed[0]["flags"]
                .as_array()
                .ok_or("cannot verify gateway link state")?;
            if flags.iter().any(|flag| flag == "UP") {
                return Err("gateway host link is still up".into());
            }
        }
        filter
    }
}

impl Sandbox {
    pub fn stop_helpers(self) -> GuardResult<()> {
        self.stop_helpers_with(
            std::path::Path::new("/run/netns")
                .join(self.namespace())
                .try_exists()?,
            Self::link_present,
        )
    }

    fn stop_helpers_with(
        self,
        namespace_present: bool,
        link_present: impl Fn(Self) -> GuardResult<bool>,
    ) -> GuardResult<()> {
        if !namespace_present {
            if link_present(self)? {
                return Err("gateway namespace name is missing while its host link remains".into());
            }
            return Ok(());
        }
        let ns = self.namespace();
        for item in invoke(IP, &["netns", "pids", &ns], None)?.lines() {
            let pid = item.trim().parse::<i32>()?;
            if pid <= 1 {
                return Err("invalid gateway process identity".into());
            }
            let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            if descriptor < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ESRCH) {
                    continue;
                }
                return Err(err.into());
            }
            use std::os::{
                fd::{AsRawFd, FromRawFd, OwnedFd},
                unix::fs::MetadataExt,
            };
            let fd = unsafe { OwnedFd::from_raw_fd(descriptor as i32) };
            let handle = std::fs::metadata(format!("/run/netns/{ns}"))?;
            let process = match std::fs::metadata(format!("/proc/{pid}/ns/net")) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if (process.ino(), process.dev()) != (handle.ino(), handle.dev()) {
                continue;
            }
            let issued = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if issued < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                return Err(std::io::Error::last_os_error().into());
            }
            let mut event = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut event, 1, 1000) } <= 0 {
                return Err("gateway process exit not observed".into());
            }
        }
        if !invoke(IP, &["netns", "pids", &ns], None)?.trim().is_empty() {
            return Err("gateway namespace still contains processes".into());
        }
        if link_present(self)? {
            invoke(IP, &["link", "delete", &self.host_link()], None)?;
        }
        invoke(IP, &["netns", "delete", &ns], None)?;
        if link_present(self)? {
            return Err("gateway link remains attached".into());
        }
        Ok(())
    }
}
