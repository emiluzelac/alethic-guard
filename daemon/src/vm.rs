use crate::GuardResult;
use roxmltree::{Document, Node};
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

fn channel_path(path: &str, domain: Node<'_, '_>, spec: &DomainSpec) -> bool {
    let Some(id) = domain
        .attribute("id")
        .filter(|id| id.bytes().all(|b| b.is_ascii_digit()))
    else {
        return false;
    };
    let short: String = spec.name().chars().take(20).collect();
    path == format!("/run/libvirt/qemu/channel/{id}-{short}/dev.alethic.guard.1")
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
    let devices = child(domain, "devices").ok_or("missing domain devices")?;
    let mut root_count = 0;
    let mut input_count = 0;
    let mut channel_count = 0;
    for device in children(devices) {
        let tag = device.tag_name().name();
        match tag {
            "disk" => {
                let target = child(device, "target");
                let path = attribute(child(device, "source"), "file");
                let readonly = child(device, "readonly").is_some();
                let driver = attribute(child(device, "driver"), "type");
                if device.attribute("type") != Some("file")
                    || device.attribute("device") != Some("disk")
                    || attribute(target, "bus") != Some("virtio")
                    || children(device).any(|field| {
                        !matches!(
                            field.tag_name().name(),
                            "driver"
                                | "source"
                                | "target"
                                | "readonly"
                                | "alias"
                                | "address"
                                | "backingStore"
                        )
                    })
                {
                    return Err("unexpected disk configuration".into());
                }
                match attribute(target, "dev") {
                    Some("vda")
                        if path == spec.overlay.to_str()
                            && !readonly
                            && driver == Some("qcow2")
                            && child(device, "backingStore").is_some_and(|backing| {
                                backing.attribute("type") == Some("file")
                                    && attribute(child(backing, "source"), "file")
                                        == spec.base.to_str()
                                    && attribute(child(backing, "format"), "type") == Some("qcow2")
                                    && child(backing, "backingStore")
                                        .is_none_or(|next| children(next).next().is_none())
                            }) =>
                    {
                        root_count += 1
                    }
                    Some("vdb")
                        if spec.input.is_some()
                            && path == spec.input.as_deref().and_then(Path::to_str)
                            && readonly
                            && driver == Some("raw") =>
                    {
                        input_count += 1
                    }
                    _ => return Err("disk failed source, format, or access verification".into()),
                }
            }
            "channel"
                if spec.broker
                    && device.attribute("type") == Some("unix")
                    && attribute(child(device, "target"), "type") == Some("virtio")
                    && attribute(child(device, "target"), "name")
                        == Some("dev.alethic.guard.1")
                    && match child(device, "source") {
                        Some(src) => {
                            src.attribute("mode") == Some("bind")
                                && src
                                    .attribute("path")
                                    .is_some_and(|path| channel_path(path, domain, spec))
                        }
                        None => domain.attribute("id").is_none(),
                    } =>
            {
                channel_count += 1;
            }
            "controller" if spec.broker && device.attribute("type") == Some("virtio-serial") => {}
            "serial" | "console" if device.attribute("type") == Some("pty") => {}
            "controller"
                if matches!(device.attribute("type"), Some("pci" | "sata"))
                    || (device.attribute("type") == Some("usb")
                        && device.attribute("model") == Some("none")) => {}
            "input" if device.attribute("bus") == Some("ps2") => {}
            "audio" if device.attribute("type") == Some("none") => {}
            "memballoon" if device.attribute("model") == Some("none") => {}
            "watchdog"
                if device.attribute("model") == Some("itco")
                    && device.attribute("action") == Some("poweroff") => {}
            "emulator" => {}
            _ => return Err(format!("unexpected domain device: {tag}").into()),
        }
    }
    if root_count != 1
        || input_count != usize::from(spec.input.is_some())
        || channel_count != usize::from(spec.broker)
    {
        return Err("missing or duplicate approved disks".into());
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
    let args: Vec<&OsStr> = ["-c", "qemu:///system"]
        .into_iter()
        .chain(args.iter().copied())
        .map(OsStr::new)
        .collect();
    command("/usr/bin/virsh", &args, input)
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
