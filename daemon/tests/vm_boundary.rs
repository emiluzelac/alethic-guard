use alethic_guardd::vm::{DomainSpec, broker_socket, verify_domain};
use std::path::PathBuf;
use uuid::Uuid;

fn spec() -> DomainSpec {
    DomainSpec {
        id: Uuid::new_v4(),
        base: PathBuf::from("/var/lib/alethic-guard/images/base.qcow2"),
        broker: false,
        overlay: PathBuf::from("/var/lib/alethic-guard/run/overlay.qcow2"),
        input: Some(PathBuf::from("/var/lib/alethic-guard/images/synthetic.img")),
    }
}

#[test]
fn verifies_generated_definition() {
    for input in [None, spec().input] {
        let domain = DomainSpec { input, ..spec() };
        verify_domain(&domain.xml().unwrap(), &domain).unwrap();
    }
}

#[test]
fn test_start_refuses_interfaces_mounts_or_autostart() {
    let domain = spec();
    let clean = domain.xml().unwrap();
    for device in [
        "<interface type='user'/>",
        "<filesystem type='mount'><source dir='/etc'/><target dir='share'/></filesystem>",
        "<channel type='unix'><target type='virtio' name='org.qemu.guest_agent.0'/></channel>",
        "<vsock model='virtio'/>",
        "<hostdev mode='subsystem' type='usb'/>",
        "<redirdev bus='usb' type='spicevmc'/>",
    ] {
        let modified = clean.replace("</devices>", &format!("{device}</devices>"));
        assert!(verify_domain(&modified, &domain).is_err(), "{device}");
    }
    assert!(
        verify_domain(
            &clean.replace("<on_reboot>destroy", "<on_reboot>restart"),
            &domain
        )
        .is_err()
    );
}

#[test]
fn denies_changes_to_disk_source_and_permissions() {
    let domain = spec();
    let clean = domain.xml().unwrap();
    assert!(verify_domain(&clean.replace("<readonly/>", ""), &domain).is_err());
    assert!(verify_domain(&clean.replace("synthetic.img", "other.img"), &domain).is_err());
}

const EMULATOR: &str = "<emulator>/usr/bin/qemu-system-x86_64</emulator>";
const SERIAL: &str = "<serial type='pty'><target port='0'/></serial>";
const LIVE_SERIAL: &str = "<serial type='pty'><source path='/dev/pts/2'/>\
    <target type='isa-serial' port='0'><model name='isa-serial'/></target>\
    <alias name='serial0'/></serial>";
const LIVE_CONSOLE: &str = "<console type='pty' tty='/dev/pts/2'><source path='/dev/pts/2'/>\
    <target type='serial' port='0'/><alias name='serial0'/></console>";
const LIVE_DEFAULTS: &str = "<controller type='sata' index='0'><alias name='ide'/>\
    <address type='pci' domain='0x0000' bus='0x00' slot='0x1f' function='0x2'/></controller>\
    <controller type='pci' index='0' model='pcie-root'><alias name='pcie.0'/></controller>\
    <controller type='pci' index='1' model='pcie-root-port'><model name='pcie-root-port'/>\
    <target chassis='1' port='0x8'/><alias name='pci.1'/>\
    <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x0' multifunction='on'/>\
    </controller><input type='mouse' bus='ps2'><alias name='input0'/></input>\
    <input type='keyboard' bus='ps2'><alias name='input1'/></input><audio id='1' type='none'/>";

fn live_definition(domain: &DomainSpec) -> (String, String) {
    let socket = format!(
        "/run/libvirt/qemu/channel/8-{}/dev.alethic.guard.1",
        &domain.name()[..20]
    );
    let xml = domain
        .xml()
        .unwrap()
        .replace("<domain type='kvm'>", "<domain type='kvm' id='8'>")
        .replace("<devices>", &format!("<devices>{EMULATOR}{LIVE_DEFAULTS}"))
        .replace(SERIAL, &format!("{LIVE_SERIAL}{LIVE_CONSOLE}"))
        .replace(
            "<channel type='unix'>",
            &format!("<channel type='unix'><source mode='bind' path='{socket}'/>"),
        )
        .replace(
            "</channel>",
            "<alias name='channel0'/><address type='virtio-serial' controller='0' bus='0' port='1'/>\
             </channel><controller type='virtio-serial' index='0'><alias name='virtio-serial0'/>\
             </controller>",
        )
        .replace(
            "<target type='virtio' name='dev.alethic.guard.1'/>",
            "<target type='virtio' name='dev.alethic.guard.1' state='disconnected'/>",
        );
    (xml, socket)
}

#[test]
fn generated_and_live_broker_definitions_allow_the_expected_channel() {
    let domain = DomainSpec {
        broker: true,
        ..spec()
    };
    verify_domain(&domain.xml().unwrap(), &domain).unwrap();
    let (live, socket) = live_definition(&domain);
    assert_eq!(
        broker_socket(&live, &domain).unwrap(),
        PathBuf::from(socket)
    );
    verify_domain(&live.replace("'disconnected'", "'connected'"), &domain).unwrap();
}

#[test]
fn requires_the_lab_emulator_in_live_xml() {
    let domain = spec();
    let (live, _) = live_definition(&domain);
    verify_domain(&live, &domain).unwrap();
    for replacement in [
        "",
        "<emulator>/example/qemu-system-x86_64</emulator>",
        "<emulator>qemu-system-x86_64</emulator>",
        "<emulator unexpected='yes'>/usr/bin/qemu-system-x86_64</emulator>",
        "<emulator>/usr/bin/qemu-system-x86_64<unexpected/></emulator>",
        &format!("{EMULATOR}{EMULATOR}"),
    ] {
        let xml = live.replace(EMULATOR, replacement);
        assert!(verify_domain(&xml, &domain).is_err(), "{replacement:?}");
    }
}

#[test]
fn rejects_unexpected_serial_and_console_shapes() {
    let domain = spec();
    let (live, _) = live_definition(&domain);
    for (old, new) in [
        ("<serial type='pty'>", "<serial type='file'>"),
        ("<console type='pty'", "<console type='tcp'"),
        (
            "<serial type='pty'>",
            "<serial type='pty'><log file='/example/log'/>",
        ),
        ("</console>", "<log file='/example/log'/></console>"),
        (
            "<source path='/dev/pts/2'/>",
            "<source path='/dev/pts/2' mode='connect'/>",
        ),
        (
            "<source path='/dev/pts/2'/>",
            "<source path='/dev/pts/2'><unexpected/></source>",
        ),
        ("<source path='/dev/pts/2'/>", "<source path='/example/2'/>"),
        ("<source path='/dev/pts/2'/>", "<source path='/dev/pts/'/>"),
        ("tty='/dev/pts/2'", "tty='/dev/pts/3'"),
        (
            "<target type='serial' port='0'/>",
            "<target type='virtio' port='0'/>",
        ),
        (
            "<target type='isa-serial' port='0'>",
            "<target type='isa-serial' port='1'>",
        ),
    ] {
        let xml = live.replace(old, new);
        assert!(verify_domain(&xml, &domain).is_err(), "{new}");
    }
    for device in [LIVE_SERIAL, LIVE_CONSOLE] {
        let duplicate = live.replace(device, &format!("{device}{device}"));
        assert!(verify_domain(&duplicate, &domain).is_err());
    }
    let mismatched_console = live.replace(LIVE_CONSOLE, &LIVE_CONSOLE.replace("/pts/2", "/pts/3"));
    assert!(verify_domain(&mismatched_console, &domain).is_err());
}

#[test]
fn rejects_extra_broker_channel_fields() {
    let domain = DomainSpec {
        broker: true,
        ..spec()
    };
    let (live, _) = live_definition(&domain);
    for (old, new) in [
        ("</channel>", "<log file='/example/log'/></channel>"),
        ("</channel>", "<source mode='connect'/></channel>"),
        ("</channel>", "<protocol type='raw'/></channel>"),
        ("mode='bind'", "mode='bind' host='example.invalid'"),
    ] {
        assert!(
            broker_socket(&live.replace(old, new), &domain).is_err(),
            "{new}"
        );
    }
}

#[test]
fn rejects_unexpected_default_device_and_disk_fields() {
    let domain = spec();
    let clean = domain.xml().unwrap();
    assert!(
        verify_domain(
            &clean.replace("</devices>", "</devices><devices/>"),
            &domain
        )
        .is_err()
    );
    for device in [
        "<input type='evdev' bus='ps2'/>",
        "<input type='keyboard' bus='ps2'><source evdev='/example/input'/></input>",
        "<audio type='none'><input/></audio>",
        "<controller type='pci' model='pci-bridge'/>",
        "<controller type='sata'><driver iothread='1'/></controller>",
        "<controller type='usb' model='none' ports='2'/>",
        "<watchdog model='itco' action='poweroff'/>",
    ] {
        let xml = clean.replace("</devices>", &format!("{device}</devices>"));
        assert!(verify_domain(&xml, &domain).is_err(), "{device}");
    }
    for (old, new) in [
        (
            "<memballoon model='none'/>",
            "<memballoon model='none'><stats period='5'/></memballoon>",
        ),
        ("<backingStore/>", "<backingStore type='file'/>"),
        ("<readonly/>", "<readonly/><backingStore type='file'/>"),
        ("<readonly/>", "<readonly/><source file='/example/input'/>"),
    ] {
        assert!(
            verify_domain(&clean.replace(old, new), &domain).is_err(),
            "{new}"
        );
    }
}
