//! The host veth is the only egress path for an unprivileged gateway instance.
use crate::{GuardResult, collector::public_ip, vm::command};
use serde_json::Value;
use std::{ffi::OsStr, net::IpAddr};

const IP: &str = "/usr/sbin/ip";
const NFT: &str = "/usr/sbin/nft";

fn invoke(program: &str, args: &[&str], input: Option<&[u8]>) -> GuardResult<String> {
    let args: Vec<_> = args.iter().map(OsStr::new).collect();
    command(program, &args, input)
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
        let list = active["nftables"]
            .as_array()
            .ok_or("invalid nft ruleset observation")?;
        for (chain, direction) in [
            ("input", "iifname"),
            ("forward", "iifname"),
            ("forward", "oifname"),
        ] {
            let covered = list
                .iter()
                .filter_map(|value| value.get("rule"))
                .any(|rule| {
                    rule["chain"] == chain
                        && rule["expr"].as_array().is_some_and(|expressions| {
                            expressions.iter().any(|entry| {
                                entry["match"]["left"]["meta"]["key"] == direction
                                    && entry["match"]["right"] == self.host_link()
                            }) && expressions.iter().any(|entry| entry.get("drop").is_some())
                        })
                });
            if !covered {
                return Err("gateway default-deny rule readback failed".into());
            }
        }
        if addresses.is_empty()
            && list
                .iter()
                .filter_map(|value| value.get("rule"))
                .any(|rule| {
                    rule["expr"].as_array().is_some_and(|items| {
                        items.iter().any(|entry| {
                            entry.get("accept").is_some() || entry.get("masquerade").is_some()
                        })
                    })
                })
        {
            return Err("gateway cutoff still allows traffic".into());
        }
        Ok(())
    }

    pub fn link_present(self) -> GuardResult<bool> {
        let links: Value = serde_json::from_str(&invoke(IP, &["-j", "link", "show"], None)?)?;
        Ok(links
            .as_array()
            .ok_or("invalid link observation")?
            .iter()
            .any(|row| row["ifname"] == self.host_link()))
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
        let ns = self.namespace();
        if !std::path::Path::new("/run/netns").join(&ns).exists() {
            return Ok(());
        }
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
        if self.link_present()? {
            invoke(IP, &["link", "delete", &self.host_link()], None)?;
        }
        invoke(IP, &["netns", "delete", &ns], None)?;
        if self.link_present()? {
            return Err("gateway link remains attached".into());
        }
        Ok(())
    }
}
