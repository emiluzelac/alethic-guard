use alethic_guardd::lifecycle::{Enrolled, Lifecycle, Mode, Observation, Registry};
use alethic_guardd::{
    GuardResult,
    vm::{DomainSpec, Hypervisor, VmState},
};
use std::{
    cell::{Cell, RefCell},
    path::PathBuf,
};
use tempfile::tempdir;
use uuid::Uuid;

#[derive(Default)]
struct FakeVm {
    state: Cell<Option<VmState>>,
    xml: RefCell<String>,
    drift: Cell<bool>,
    offline: Cell<bool>,
    persistent: Cell<bool>,
    resume_calls: Cell<u32>,
}

impl Hypervisor for FakeVm {
    fn create_paused(&self, spec: &DomainSpec) -> GuardResult<()> {
        let mut xml = spec.xml()?;
        if self.drift.get() {
            xml = xml.replace("</devices>", "<interface type='user'/></devices>");
        }
        self.xml.replace(xml);
        self.state.set(Some(VmState::Paused));
        Ok(())
    }

    fn active_xml(&self, _: Uuid) -> GuardResult<String> {
        Ok(self.xml.borrow().clone())
    }
    fn is_transient(&self, _: Uuid) -> GuardResult<bool> {
        Ok(!self.persistent.get())
    }
    fn state(&self, _: Uuid) -> GuardResult<VmState> {
        if self.offline.get() {
            Err("observer unavailable".into())
        } else {
            Ok(self.state.get().unwrap_or(VmState::Absent))
        }
    }
    fn suspend(&self, _: Uuid) -> GuardResult<()> {
        self.state.set(Some(VmState::Paused));
        Ok(())
    }
    fn resume(&self, _: Uuid) -> GuardResult<()> {
        self.resume_calls.set(self.resume_calls.get() + 1);
        self.state.set(Some(VmState::Running));
        Ok(())
    }
    fn destroy(&self, _: Uuid) -> GuardResult<()> {
        self.state.set(Some(VmState::Absent));
        Ok(())
    }
}

fn enrolled() -> Enrolled {
    Enrolled {
        id: Uuid::new_v4(),
        profile: "offline-research".into(),
        policy_digest: "example policy".into(),
        image: PathBuf::from("/approved/image.qcow2"),
        image_digest: "example image".into(),
        input: None,
        input_digest: None,
        broker: false,
    }
}

fn overlay() -> PathBuf {
    "/test/private.qcow2".into()
}

#[test]
fn test_unknown_domain_is_unmanaged() {
    let mut registry = Registry::memory().unwrap();
    let vm = FakeVm::default();
    let lifecycle = Lifecycle::new(&mut registry, &vm);
    assert!(lifecycle.status(Uuid::new_v4()).unwrap().is_none());
}

#[test]
fn test_active_drift_or_persistent_domain_never_unpauses() {
    for (drift, persistent) in [(true, false), (false, true)] {
        let mut registry = Registry::memory().unwrap();
        let vm = FakeVm::default();
        vm.drift.set(drift);
        vm.persistent.set(persistent);
        let item = enrolled();
        registry.enroll(&item).unwrap();
        let mut life = Lifecycle::new(&mut registry, &vm);
        assert!(life.start(item.id, |_| Ok(overlay())).is_err());
        assert_eq!(vm.resume_calls.get(), 0);
        assert_eq!(vm.state(item.id).unwrap(), VmState::Absent);
        assert_eq!(life.status(item.id).unwrap().unwrap().mode, Mode::Contained);
    }
}

#[test]
fn test_contain_rejects_start_until_release() {
    let mut registry = Registry::memory().unwrap();
    let vm = FakeVm::default();
    let item = enrolled();
    registry.enroll(&item).unwrap();
    let mut life = Lifecycle::new(&mut registry, &vm);
    let initial = life.start(item.id, |_| Ok(overlay())).unwrap();
    let report = life.contain(item.id, false).unwrap();
    assert_eq!(report.guest_network, Observation::Verified);
    assert!(life.start(item.id, |_| Ok(overlay())).is_err());
    life.contain(item.id, true).unwrap();
    life.release(item.id).unwrap();
    let again = life.start(item.id, |_| Ok(overlay())).unwrap();
    assert!(again.generation > initial.generation);
    assert!(again.epoch > initial.epoch);
}

#[test]
fn test_failed_hypervisor_observation_is_unknown() {
    let mut registry = Registry::memory().unwrap();
    let vm = FakeVm::default();
    let item = enrolled();
    registry.enroll(&item).unwrap();
    let mut life = Lifecycle::new(&mut registry, &vm);
    life.start(item.id, |_| Ok(overlay())).unwrap();
    vm.offline.set(true);
    let report = life.contain(item.id, true).unwrap();
    assert_eq!(report.shutdown, Observation::Unknown);
    assert_eq!(
        life.status(item.id).unwrap().unwrap().mode,
        Mode::Containing
    );
}

#[test]
fn test_reboot_recovers_running_without_autostart() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("registry.sqlite3");
    let item = enrolled();
    {
        let mut registry = Registry::open(&path).unwrap();
        registry.enroll(&item).unwrap();
        Lifecycle::new(&mut registry, &FakeVm::default())
            .start(item.id, |_| Ok(overlay()))
            .unwrap();
    }
    let vm = FakeVm::default();
    let mut registry = Registry::open(&path).unwrap();
    let mut life = Lifecycle::new(&mut registry, &vm);
    life.reconcile().unwrap();
    assert_eq!(
        life.status(item.id).unwrap().unwrap().mode,
        Mode::Terminated
    );
    assert_eq!(vm.resume_calls.get(), 0);
    assert!(life.start(item.id, |_| Ok(overlay())).is_err());
}
