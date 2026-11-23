use crate::GuardResult;
use roxmltree::{Document, Node};
use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct DomainSpec {
    pub id: Uuid,
    pub overlay: PathBuf,
    pub base: PathBuf,
    pub broker: bool,
    pub input: Option<PathBuf>,
}

impl DomainSpec {
    pub fn name(&self) -> String {
        format!("guard-{}", self.id)
    }

    pub fn xml(&self) -> GuardResult<String> {
        fn escaped(path: &Path) -> GuardResult<String> {
            Ok(path
                .to_str()
                .ok_or("domain path must be UTF-8")?
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('\'', "&apos;"))
        }
        let base = escaped(&self.base)?;
        let overlay = escaped(&self.overlay)?;
        let root = format!(
            "<disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='{overlay}'/>\
             <backingStore type='file'><format type='qcow2'/><source file='{base}'>\
             <seclabel model='dac' relabel='no'/></source><backingStore/></backingStore>\
             <target dev='vda' bus='virtio'/></disk>"
        );
        let input = if let Some(path) = &self.input {
            let source = escaped(path)?;
            format!(
                "<disk type='file' device='disk'><driver name='qemu' type='raw'/>\
                 <source file='{source}'><seclabel model='dac' relabel='no'/></source>\
                 <target dev='vdb' bus='virtio'/><readonly/></disk>"
            )
        } else {
            String::new()
        };
        let channel = if self.broker {
            "<channel type='unix'><target type='virtio' name='dev.alethic.guard.1'/></channel>"
        } else {
            ""
        };
        Ok(format!(
            "<domain type='kvm'><name>{}</name><uuid>{}</uuid>\
             <memory unit='MiB'>1024</memory><vcpu>1</vcpu>\
             <os><type arch='x86_64' machine='q35'>hvm</type><boot dev='hd'/></os>\
             <features><acpi/></features><cpu mode='host-passthrough'/>\
             <on_poweroff>destroy</on_poweroff><on_reboot>destroy</on_reboot><on_crash>destroy</on_crash>\
             <devices>{root}{input}{channel}<controller type='usb' model='none'/>\
             <serial type='pty'><target port='0'/></serial>\
             <watchdog model='itco' action='poweroff'/><memballoon model='none'/></devices></domain>",
            self.name(),
            self.id
        ))
    }
}

fn children<'a, 'i>(node: Node<'a, 'i>) -> impl Iterator<Item = Node<'a, 'i>> {
    node.children().filter(Node::is_element)
}

fn child<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Option<Node<'a, 'i>> {
    children(node).find(|item| item.has_tag_name(name))
}

fn attribute<'a>(node: Option<Node<'a, '_>>, key: &str) -> Option<&'a str> {
    node.and_then(|item| item.attribute(key))
}

// Each listed child is optional here and may occur at most once. Callers
// check the required fields and the shapes of children they admit.
fn has_shape(node: Node<'_, '_>, attrs: &[&str], fields: &[&str]) -> bool {
    node.attributes()
        .all(|attr| attr.namespace().is_none() && attrs.contains(&attr.name()))
        && node.children().all(|item| {
            if item.is_element() {
                fields.contains(&item.tag_name().name())
            } else {
                !item.is_text() || item.text().is_some_and(|text| text.trim().is_empty())
            }
        })
        && fields.iter().all(|name| {
            children(node)
                .filter(|item| item.has_tag_name(*name))
                .nth(1)
                .is_none()
        })
}

fn device_metadata(device: Node<'_, '_>) -> bool {
    child(device, "alias")
        .is_none_or(|alias| has_shape(alias, &["name"], &[]) && alias.attribute("name").is_some())
        && child(device, "address").is_none_or(|address| {
            if device.has_tag_name("channel") {
                has_shape(address, &["type", "controller", "bus", "port"], &[])
                    && address.attribute("type") == Some("virtio-serial")
                    && address.attribute("controller") == Some("0")
                    && address.attribute("bus") == Some("0")
                    && address.attribute("port") == Some("1")
            } else {
                has_shape(
                    address,
                    &["type", "domain", "bus", "slot", "function", "multifunction"],
                    &[],
                ) && address.attribute("type") == Some("pci")
            }
        })
}

fn file_source(node: Node<'_, '_>, expected: &Path) -> bool {
    has_shape(node, &["file", "index"], &["seclabel"])
        && expected
            .to_str()
            .is_some_and(|path| node.attribute("file") == Some(path))
        && child(node, "seclabel").is_none_or(|label| {
            has_shape(label, &["model", "relabel"], &[])
                && label.attribute("model") == Some("dac")
                && label.attribute("relabel") == Some("no")
        })
}

fn verified_disk(device: Node<'_, '_>, spec: &DomainSpec) -> Option<&'static str> {
    if !has_shape(
        device,
        &["type", "device"],
        &[
            "driver",
            "source",
            "target",
            "readonly",
            "alias",
            "address",
            "backingStore",
        ],
    ) || device.attribute("type") != Some("file")
        || device.attribute("device") != Some("disk")
    {
        return None;
    }
    let target = child(device, "target")?;
    let driver = child(device, "driver")?;
    let source = child(device, "source")?;
    if !has_shape(target, &["dev", "bus"], &[])
        || target.attribute("bus") != Some("virtio")
        || !has_shape(driver, &["name", "type"], &[])
        || driver.attribute("name") != Some("qemu")
    {
        return None;
    }
    let readonly = child(device, "readonly");
    let backing = child(device, "backingStore");
    match target.attribute("dev")? {
        "vda"
            if driver.attribute("type") == Some("qcow2")
                && readonly.is_none()
                && file_source(source, &spec.overlay)
                && backing.is_some_and(|store| {
                    has_shape(
                        store,
                        &["type", "index"],
                        &["format", "source", "backingStore"],
                    ) && store.attribute("type") == Some("file")
                        && child(store, "source").is_some_and(|node| file_source(node, &spec.base))
                        && child(store, "format").is_some_and(|format| {
                            has_shape(format, &["type"], &[])
                                && format.attribute("type") == Some("qcow2")
                        })
                        && child(store, "backingStore").is_none_or(|end| has_shape(end, &[], &[]))
                }) =>
        {
            Some("vda")
        }
        "vdb"
            if driver.attribute("type") == Some("raw")
                && readonly.is_some_and(|node| has_shape(node, &[], &[]))
                && spec
                    .input
                    .as_deref()
                    .is_some_and(|path| file_source(source, path))
                && backing.is_none_or(|end| has_shape(end, &[], &[])) =>
        {
            Some("vdb")
        }
        _ => None,
    }
}

fn decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn channel_path(path: &str, domain: Node<'_, '_>, spec: &DomainSpec) -> bool {
    let Some(id) = domain.attribute("id").filter(|id| decimal(id)) else {
        return false;
    };
    let short: String = spec.name().chars().take(20).collect();
    path == format!("/run/libvirt/qemu/channel/{id}-{short}/dev.alethic.guard.1")
}

fn verified_channel(channel: Node<'_, '_>, domain: Node<'_, '_>, spec: &DomainSpec) -> bool {
    spec.broker
        && has_shape(
            channel,
            &["type"],
            &["source", "target", "alias", "address"],
        )
        && channel.attribute("type") == Some("unix")
        && child(channel, "target").is_some_and(|target| {
            has_shape(target, &["type", "name", "state"], &[])
                && target.attribute("type") == Some("virtio")
                && target.attribute("name") == Some("dev.alethic.guard.1")
                && matches!(
                    target.attribute("state"),
                    None | Some("connected" | "disconnected")
                )
        })
        && match child(channel, "source") {
            Some(source) => {
                has_shape(source, &["mode", "path"], &[])
                    && source.attribute("mode") == Some("bind")
                    && source
                        .attribute("path")
                        .is_some_and(|path| channel_path(path, domain, spec))
            }
            None => domain.attribute("id").is_none(),
        }
}

fn pty_path<'a>(node: Node<'a, '_>) -> Option<&'a str> {
    attribute(child(node, "source"), "path")
}

fn verified_pty(device: Node<'_, '_>, active: bool) -> bool {
    let console = device.has_tag_name("console");
    let attrs: &[&str] = if console { &["type", "tty"] } else { &["type"] };
    if !has_shape(device, attrs, &["source", "target", "alias"])
        || device.attribute("type") != Some("pty")
    {
        return false;
    }
    let valid_source = match child(device, "source") {
        Some(source) => {
            has_shape(source, &["path"], &[])
                && source
                    .attribute("path")
                    .and_then(|value| value.strip_prefix("/dev/pts/"))
                    .is_some_and(decimal)
        }
        None => !active && !console,
    };
    if !valid_source {
        return false;
    }
    let Some(target) = child(device, "target") else {
        return false;
    };
    if target.attribute("port") != Some("0") {
        return false;
    }
    if console {
        return device.attribute("tty") == pty_path(device)
            && has_shape(target, &["type", "port"], &[])
            && target.attribute("type") == Some("serial");
    }
    has_shape(target, &["type", "port"], &["model"])
        && matches!(target.attribute("type"), None | Some("isa-serial"))
        && child(target, "model").is_none_or(|model| {
            target.attribute("type") == Some("isa-serial")
                && has_shape(model, &["name"], &[])
                && model.attribute("name") == Some("isa-serial")
        })
}

fn verified_controller(device: Node<'_, '_>, kind: &str, index: u32, broker: bool) -> bool {
    match (kind, device.attribute("model")) {
        ("usb", Some("none")) | ("pci", Some("pcie-root")) => {
            index == 0 && has_shape(device, &["type", "index", "model"], &["alias"])
        }
        ("sata", None) | ("virtio-serial", None) => {
            (kind == "sata" || broker)
                && index == 0
                && has_shape(device, &["type", "index"], &["alias", "address"])
        }
        ("pci", Some("pcie-root-port")) => {
            index > 0
                && has_shape(
                    device,
                    &["type", "index", "model"],
                    &["model", "target", "alias", "address"],
                )
                && child(device, "model").is_some_and(|model| {
                    has_shape(model, &["name"], &[])
                        && model.attribute("name") == Some("pcie-root-port")
                })
                && child(device, "target").is_some_and(|target| {
                    has_shape(target, &["chassis", "port"], &[])
                        && target.attribute("chassis").is_some()
                        && target.attribute("port").is_some()
                })
        }
        _ => false,
    }
}

pub fn broker_socket(xml: &str, domain: &DomainSpec) -> GuardResult<PathBuf> {
    verify_domain(xml, domain)?;
    let document = Document::parse(xml)?;
    let devices = child(document.root_element(), "devices").ok_or("missing devices")?;
    let channel = child(devices, "channel").ok_or("missing broker channel")?;
    let path =
        attribute(child(channel, "source"), "path").ok_or("missing active channel socket")?;
    Ok(PathBuf::from(path))
}

pub fn verify_domain(xml: &str, spec: &DomainSpec) -> GuardResult<()> {
    let document = Document::parse(xml)?;
    let domain = document.root_element();
    if !domain.has_tag_name("domain") || domain.attribute("type") != Some("kvm") {
        return Err("expected a KVM domain".into());
    }
    if domain
        .descendants()
        .filter(Node::is_element)
        .any(|n| n.tag_name().namespace().is_some())
    {
        return Err("unexpected namespaced domain extension".into());
    }
    if child(domain, "name").and_then(|n| n.text()) != Some(&spec.name())
        || child(domain, "uuid").and_then(|n| n.text()) != Some(&spec.id.to_string())
    {
        return Err("domain identity does not match enrollment".into());
    }
    for event in ["on_poweroff", "on_reboot", "on_crash"] {
        if child(domain, event).and_then(|node| node.text()) != Some("destroy") {
            return Err(format!("non-destroy lifecycle policy: {event}").into());
        }
    }
    for name in ["hostdev", "launchSecurity", "sysinfo", "idmap"] {
        if child(domain, name).is_some() {
            return Err(format!("unexpected domain feature: {name}").into());
        }
    }
    let os = child(domain, "os").ok_or("missing OS definition")?;
    for device in children(os) {
        if !matches!(device.tag_name().name(), "type" | "boot" | "bootmenu") {
            return Err("unexpected domain boot source".into());
        }
    }
    let mut device_lists = children(domain).filter(|node| node.has_tag_name("devices"));
    let devices = device_lists.next().ok_or("missing domain devices")?;
    if device_lists.next().is_some() {
        return Err("duplicate domain devices list".into());
    }
    let active = domain.attribute("id").is_some();
    let mut seen = HashSet::new();
    for device in children(devices) {
        let tag = device.tag_name().name();
        let (kind, index) = match tag {
            "disk" => (
                verified_disk(device, spec).ok_or("unexpected disk configuration")?,
                0,
            ),
            "controller" => {
                let kind = device.attribute("type").ok_or("missing controller type")?;
                let index = device.attribute("index").unwrap_or("0").parse()?;
                if !verified_controller(device, kind, index, spec.broker) {
                    return Err("unexpected controller configuration".into());
                }
                (kind, index)
            }
            "channel" if verified_channel(device, domain, spec) => ("", 0),
            "serial" if verified_pty(device, active) => ("", 0),
            "console"
                if verified_pty(device, active)
                    && pty_path(device) == child(devices, "serial").and_then(pty_path) =>
            {
                ("", 0)
            }
            "input"
                if has_shape(device, &["type", "bus"], &["alias"])
                    && device.attribute("bus") == Some("ps2") =>
            {
                match device.attribute("type") {
                    Some(kind @ ("mouse" | "keyboard")) => (kind, 0),
                    _ => return Err("unexpected PS/2 input type".into()),
                }
            }
            "audio"
                if has_shape(device, &["id", "type"], &[])
                    && device.attribute("id") == Some("1")
                    && device.attribute("type") == Some("none") =>
            {
                ("", 0)
            }
            "memballoon"
                if has_shape(device, &["model"], &[])
                    && device.attribute("model") == Some("none") =>
            {
                ("", 0)
            }
            "watchdog"
                if has_shape(device, &["model", "action"], &["alias"])
                    && device.attribute("model") == Some("itco")
                    && device.attribute("action") == Some("poweroff") =>
            {
                ("", 0)
            }
            "emulator"
                if device.attributes().len() == 0
                    && device.children().count() == 1
                    && device.text() == Some("/usr/bin/qemu-system-x86_64") =>
            {
                ("", 0)
            }
            _ => return Err(format!("unexpected domain device: {tag}").into()),
        };
        if !device_metadata(device) {
            return Err(format!("unexpected alias or address for domain device: {tag}").into());
        }
        if !seen.insert((tag, kind, index)) {
            return Err(format!("duplicate domain device: {tag}").into());
        }
    }
    // Generated XML leaves the emulator implicit. Live XML reports its path.
    if !seen.contains(&("disk", "vda", 0))
        || seen.contains(&("disk", "vdb", 0)) != spec.input.is_some()
        || seen.contains(&("channel", "", 0)) != spec.broker
        || (active && !seen.contains(&("emulator", "", 0)))
    {
        return Err("missing expected disk, broker channel, or emulator".into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmState {
    Absent,
    Paused,
    Running,
    Other,
}

pub trait Hypervisor {
    fn create_paused(&self, domain: &DomainSpec) -> GuardResult<()>;
    fn active_xml(&self, id: Uuid) -> GuardResult<String>;
    fn is_transient(&self, id: Uuid) -> GuardResult<bool>;
    fn state(&self, id: Uuid) -> GuardResult<VmState>;
    fn suspend(&self, id: Uuid) -> GuardResult<()>;
    fn resume(&self, id: Uuid) -> GuardResult<()>;
    fn destroy(&self, id: Uuid) -> GuardResult<()>;
    fn verify_absent(&self, id: Uuid) -> GuardResult<bool> {
        Ok(self.state(id)? == VmState::Absent)
    }
}

pub struct Libvirt;

pub fn command(program: &str, args: &[&OsStr], input: Option<&[u8]>) -> GuardResult<String> {
    command_with_timeout("30s", program, args, input)
}

pub fn command_with_timeout(
    timeout: &str,
    program: &str,
    args: &[&OsStr],
    input: Option<&[u8]>,
) -> GuardResult<String> {
    let mut process = Command::new("/usr/bin/timeout")
        .args(["--kill-after=1s", timeout, program])
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(bytes) = input {
        process
            .stdin
            .take()
            .ok_or("missing command stdin")?
            .write_all(bytes)?;
    }
    let output = process.wait_with_output()?;
    if !output.status.success() {
        return Err(format!(
            "{program}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn virsh(args: &[&str], input: Option<&[u8]>) -> GuardResult<String> {
    virsh_with_timeout("30s", args, input)
}

fn virsh_with_timeout(timeout: &str, args: &[&str], input: Option<&[u8]>) -> GuardResult<String> {
    let args: Vec<&OsStr> = ["-c", "qemu:///system"]
        .into_iter()
        .chain(args.iter().copied())
        .map(OsStr::new)
        .collect();
    command_with_timeout(timeout, "/usr/bin/virsh", &args, input)
}

impl Libvirt {
    pub fn emergency_shutdown(id: Uuid) -> GuardResult<bool> {
        let uuid = id.to_string();
        let listed = || -> GuardResult<bool> {
            let list = virsh_with_timeout("2s", &["list", "--all", "--uuid"], None)?;
            Ok(list.lines().any(|line| line.trim() == uuid))
        };
        if listed()? {
            let info = virsh_with_timeout("2s", &["dominfo", &uuid], None)?;
            let name = format!("guard-{uuid}");
            let matches = |key, expected| {
                info.lines().any(|line| {
                    line.split_once(':')
                        .is_some_and(|(label, value)| label == key && value.trim() == expected)
                })
            };
            if !matches("Name", name.as_str())
                || !matches("UUID", uuid.as_str())
                || !matches("Persistent", "no")
            {
                return Err("cannot verify the managed transient VM identity".into());
            }
            let _ = virsh_with_timeout("3s", &["destroy", &uuid], None);
            if listed()? {
                return Ok(false);
            }
        }
        qemu_process_absent(id)
    }
}

impl Hypervisor for Libvirt {
    fn create_paused(&self, domain: &DomainSpec) -> GuardResult<()> {
        virsh(
            &["create", "/dev/stdin", "--paused", "--validate"],
            Some(domain.xml()?.as_bytes()),
        )?;
        Ok(())
    }

    fn active_xml(&self, id: Uuid) -> GuardResult<String> {
        virsh(&["dumpxml", &id.to_string()], None)
    }

    fn is_transient(&self, id: Uuid) -> GuardResult<bool> {
        let info = virsh(&["dominfo", &id.to_string()], None)?;
        Ok(info.lines().any(|line| {
            line.split_once(':')
                .is_some_and(|(label, value)| label == "Persistent" && value.trim() == "no")
        }))
    }

    fn state(&self, id: Uuid) -> GuardResult<VmState> {
        let list = virsh(&["list", "--all", "--uuid"], None)?;
        if !list.lines().any(|line| line.trim() == id.to_string()) {
            return Ok(VmState::Absent);
        }
        let actual = virsh(&["domstate", &id.to_string()], None)?;
        Ok(match actual.trim() {
            "running" => VmState::Running,
            "paused" => VmState::Paused,
            _ => VmState::Other,
        })
    }

    fn suspend(&self, id: Uuid) -> GuardResult<()> {
        virsh(&["suspend", &id.to_string()], None).map(|_| ())
    }
    fn resume(&self, id: Uuid) -> GuardResult<()> {
        virsh(&["resume", &id.to_string()], None).map(|_| ())
    }
    fn destroy(&self, id: Uuid) -> GuardResult<()> {
        virsh(&["destroy", &id.to_string()], None).map(|_| ())
    }

    fn verify_absent(&self, id: Uuid) -> GuardResult<bool> {
        if self.state(id)? != VmState::Absent {
            return Ok(false);
        }
        qemu_process_absent(id)
    }
}

fn qemu_process_absent(id: Uuid) -> GuardResult<bool> {
    let uuid = id.to_string();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        if !entry
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        let cmd = match std::fs::read(entry.path().join("cmdline")) {
            Ok(buf) => buf,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };
        let args: Vec<_> = cmd.split(|byte| *byte == 0).collect();
        if args.first().is_some_and(|path| {
            path.rsplit(|byte| *byte == b'/').next() == Some(b"qemu-system-x86_64")
        }) && args
            .windows(2)
            .any(|arg| arg == [b"-uuid", uuid.as_bytes()])
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn validate_base_image(path: &Path) -> GuardResult<()> {
    let info = command(
        "/usr/bin/qemu-img",
        &[
            OsStr::new("info"),
            OsStr::new("--output=json"),
            path.as_os_str(),
        ],
        None,
    )?;
    let value: serde_json::Value = serde_json::from_str(&info)?;
    if value["format"] != "qcow2"
        || value.get("backing-filename").is_some()
        || value["format-specific"]["data"].get("data-file").is_some()
        || value["format-specific"]["data"]["corrupt"] == true
        || value["encrypted"] == true
    {
        return Err("expected a standalone, unencrypted qcow2 image".into());
    }
    Ok(())
}

pub fn create_overlay(path: &Path, base: &Path) -> GuardResult<()> {
    if path.try_exists()? {
        return Err("overlay already exists".into());
    }
    command(
        "/usr/bin/qemu-img",
        &[
            OsStr::new("create"),
            OsStr::new("-q"),
            OsStr::new("-f"),
            OsStr::new("qcow2"),
            OsStr::new("-F"),
            OsStr::new("qcow2"),
            OsStr::new("-b"),
            base.as_os_str(),
            path.as_os_str(),
        ],
        None,
    )?;
    Ok(())
}
