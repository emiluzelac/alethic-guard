use alethic_guardd::lifecycle::{Enrolled, LaunchDisks, Lifecycle, Mode, Observation, Registry};
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
    orphan: Cell<bool>,
    disappear_after_observation: Cell<bool>,
    persistent: Cell<bool>,
    transient_unavailable: Cell<bool>,
    xml_unavailable: Cell<bool>,
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
        if self.xml_unavailable.get() {
            return Err("domain XML observation unavailable".into());
        }
        Ok(self.xml.borrow().clone())
    }
    fn is_transient(&self, _: Uuid) -> GuardResult<bool> {
        if self.transient_unavailable.get() {
            return Err("domain persistence observation unavailable".into());
        }
        Ok(!self.persistent.get())
    }
    fn state(&self, _: Uuid) -> GuardResult<VmState> {
        if self.offline.get() {
            Err("observer unavailable".into())
        } else {
            let state = self.state.get().unwrap_or(VmState::Absent);
            if self.disappear_after_observation.replace(false) {
                self.state.set(Some(VmState::Absent));
            }
            Ok(state)
        }
    }
    fn verify_absent(&self, id: Uuid) -> GuardResult<bool> {
        Ok(self.state(id)? == VmState::Absent && !self.orphan.get())
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

fn launch(row: &alethic_guardd::lifecycle::Workload) -> GuardResult<LaunchDisks> {
    Ok(LaunchDisks {
        overlay: "/test/private.qcow2".into(),
        base: row.enrollment.image.clone(),
        input: None,
    })
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
        assert!(life.start(item.id, launch).is_err());
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
    let initial = life.start(item.id, launch).unwrap();
    let report = life.contain(item.id, false).unwrap();
    assert_eq!(report.guest_network, Observation::Verified);
    assert!(life.start(item.id, launch).is_err());
    life.contain(item.id, true).unwrap();
    life.release(item.id).unwrap();
    let again = life.start(item.id, launch).unwrap();
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
    life.start(item.id, launch).unwrap();
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
            .start(item.id, launch)
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
    assert!(life.start(item.id, launch).is_err());
}

#[test]
fn test_libvirt_absence_alone_does_not_verify_containment() {
    let mut registry = Registry::memory().unwrap();
    let vm = FakeVm::default();
    let item = enrolled();
    registry.enroll(&item).unwrap();
    let mut lifecycle = Lifecycle::new(&mut registry, &vm);
    lifecycle.start(item.id, launch).unwrap();
    vm.state.set(Some(VmState::Absent));
    vm.orphan.set(true);

    let report = lifecycle.contain(item.id, false).unwrap();
    assert_eq!(report.guest_network, Observation::Failed);
    assert_eq!(report.shutdown, Observation::Failed);
    assert_eq!(report.mode, Mode::Containing);
    assert!(lifecycle.release(item.id).is_err());
}

#[test]
fn test_observer_failure_fences_a_running_workload() {
    let mut registry = Registry::memory().unwrap();
    let vm = FakeVm::default();
    let item = enrolled();
    registry.enroll(&item).unwrap();
    let mut lifecycle = Lifecycle::new(&mut registry, &vm);
    lifecycle.start(item.id, launch).unwrap();
    vm.offline.set(true);

    assert_eq!(lifecycle.verify(item.id).unwrap(), Observation::Unknown);
    let row = lifecycle.status(item.id).unwrap().unwrap();
    assert_eq!(row.mode, Mode::Containing);
    assert_eq!(row.epoch, 1);
}

#[test]
fn test_active_configuration_distinguishes_unavailable_observation_from_drift() {
    for (transient_unavailable, xml_unavailable, expected) in [
        (true, false, Observation::Unknown),
        (false, true, Observation::Unknown),
        (false, false, Observation::Failed),
    ] {
        let mut registry = Registry::memory().unwrap();
        let vm = FakeVm::default();
        let item = enrolled();
        registry.enroll(&item).unwrap();
        let mut lifecycle = Lifecycle::new(&mut registry, &vm);
        lifecycle.start(item.id, launch).unwrap();
        vm.transient_unavailable.set(transient_unavailable);
        vm.xml_unavailable.set(xml_unavailable);
        vm.persistent.set(expected == Observation::Failed);

        assert_eq!(lifecycle.verify(item.id).unwrap(), expected);
        assert_eq!(
            lifecycle.status(item.id).unwrap().unwrap().mode,
            Mode::Terminated
        );
    }
}

#[test]
fn test_disappearance_during_cutoff_requires_independent_process_confirmation() {
    let mut registry = Registry::memory().unwrap();
    let vm = FakeVm::default();
    let item = enrolled();
    registry.enroll(&item).unwrap();
    let mut lifecycle = Lifecycle::new(&mut registry, &vm);
    lifecycle.start(item.id, launch).unwrap();
    vm.disappear_after_observation.set(true);
    vm.orphan.set(true);

    let report = lifecycle.contain(item.id, false).unwrap();
    assert_eq!(report.guest_network, Observation::Failed);
    assert_eq!(report.shutdown, Observation::Failed);
    assert_eq!(report.mode, Mode::Containing);
}
