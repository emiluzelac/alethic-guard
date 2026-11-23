use alethic_guardd::vm::{DomainSpec, verify_domain};
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
    let domain = spec();
    assert!(verify_domain(&domain.xml().unwrap(), &domain).is_ok());
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
