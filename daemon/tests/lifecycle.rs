use alethic_guardd::lifecycle::{Enrolled, LaunchDisks, Lifecycle, Mode, Observation, Registry};
use alethic_guardd::{
    GuardResult,
    emergency::Fences,
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
    unavailable_workload: Cell<Option<Uuid>>,
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
    fn state(&self, id: Uuid) -> GuardResult<VmState> {
        if self.offline.get() || self.unavailable_workload.get() == Some(id) {
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
fn startup_attempts_later_workloads_after_one_observer_fails() {
    let mut registry = Registry::memory().unwrap();
    registry.enroll(&enrolled()).unwrap();
    registry.enroll(&enrolled()).unwrap();
    let rows = registry.all().unwrap();
    let vm = FakeVm::default();
    vm.unavailable_workload.set(Some(rows[0].enrollment.id));
    vm.state.set(Some(VmState::Running));

    assert!(Lifecycle::new(&mut registry, &vm).reconcile().is_err());
    assert_eq!(vm.state(rows[1].enrollment.id).unwrap(), VmState::Absent);
}

#[test]
fn failed_resume_record_stops_the_vm() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("guard.sqlite3");
    let mut registry = Registry::open(&database).unwrap();
    let enrollment = enrolled();
    let id = enrollment.id;
    registry.enroll(&enrollment).unwrap();
    let vm = FakeVm::default();
    let mut lifecycle = Lifecycle::new(&mut registry, &vm);
    lifecycle.start(id, launch).unwrap();
    lifecycle.pause(id).unwrap();
    let connection = rusqlite::Connection::open(database).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER reject_running_mode BEFORE UPDATE ON workloads
             WHEN json_extract(NEW.record, '$.mode') = 'RUNNING'
             BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END;",
        )
        .unwrap();

    assert!(lifecycle.resume(id).is_err());
    assert!(vm.verify_absent(id).unwrap());
    assert_eq!(registry.get(id).unwrap().unwrap().mode, Mode::Terminated);
}

#[test]
fn resume_contains_a_vm_that_disagrees_with_its_recorded_pause() {
    let mut registry = Registry::memory().unwrap();
    let enrollment = enrolled();
    let id = enrollment.id;
    registry.enroll(&enrollment).unwrap();
    let vm = FakeVm::default();
    let mut lifecycle = Lifecycle::new(&mut registry, &vm);
    lifecycle.start(id, launch).unwrap();
    lifecycle.pause(id).unwrap();
    vm.state.set(Some(VmState::Running));
    assert!(lifecycle.resume(id).is_err());
    assert!(vm.verify_absent(id).unwrap());
    assert_eq!(registry.get(id).unwrap().unwrap().mode, Mode::Terminated);
}

#[test]
fn failed_resume_artifact_validation_contains_the_paused_vm() {
    let mut registry = Registry::memory().unwrap();
    let enrollment = enrolled();
    let id = enrollment.id;
    registry.enroll(&enrollment).unwrap();
    let vm = FakeVm::default();
    let mut lifecycle = Lifecycle::new(&mut registry, &vm);
    lifecycle.start(id, launch).unwrap();
    lifecycle.pause(id).unwrap();
    assert!(
        lifecycle
            .resume_guarded(id, |_| Err("approved image changed".into()))
            .is_err()
    );
    assert!(vm.verify_absent(id).unwrap());
    assert_eq!(registry.get(id).unwrap().unwrap().mode, Mode::Terminated);
}

#[test]
fn host_recovery_fences_only_the_enrolled_workload_and_requires_release() {
    let mut registry = Registry::memory().unwrap();
    let enrollment = enrolled();
    let id = enrollment.id;
    registry.enroll(&enrollment).unwrap();
    let dir = tempdir().unwrap();
    let fences = Fences::new(dir.path().into());
    let unregistered = Uuid::new_v4();

    assert!(
        registry
            .recover_host(
                unregistered,
                |id| fences.cutoff(id, |_| Ok(())),
                |_| panic!("unexpected shutdown")
            )
            .is_err()
    );
    assert!(!dir.path().join(unregistered.to_string()).exists());
    let report = registry
        .recover_host(
            id,
            |id| fences.cutoff(id, |_| Ok(())),
            |target| {
                assert_eq!(target, id);
                Ok(true)
            },
        )
        .unwrap();
    assert_eq!(report.admissions, Observation::Verified);
    assert_eq!(report.broker_cutoff, Observation::Verified);
    assert_eq!(report.shutdown, Observation::Verified);
    assert_eq!(report.record, Observation::Verified);
    assert!(dir.path().join(id.to_string()).is_file());

    let row = registry.get(id).unwrap().unwrap();
    assert_eq!(row.mode, Mode::Terminated);
    assert_eq!(row.epoch, 1);
    let vm = FakeVm::default();
    let mut lifecycle = Lifecycle::new(&mut registry, &vm);
    assert!(lifecycle.start(id, launch).is_err());
    lifecycle.release(id).unwrap();
}

#[test]
fn host_recovery_attempts_shutdown_when_fence_storage_is_unavailable() {
    let mut registry = Registry::memory().unwrap();
    let enrollment = enrolled();
    let id = enrollment.id;
    registry.enroll(&enrollment).unwrap();
    let dir = tempdir().unwrap();
    let fences = Fences::new(dir.path().join("missing"));
    let report = registry
        .recover_host(id, |id| fences.cutoff(id, |_| Ok(())), |_| Ok(true))
        .unwrap();
    assert_eq!(report.admissions, Observation::Unknown);
    assert_eq!(report.broker_cutoff, Observation::Verified);
    assert_eq!(report.shutdown, Observation::Verified);
    assert_eq!(report.record, Observation::Verified);
    assert_eq!(registry.get(id).unwrap().unwrap().mode, Mode::Containing);
}

#[test]
fn host_recovery_preserves_containment_when_shutdown_cannot_be_observed() {
    let mut registry = Registry::memory().unwrap();
    let enrollment = enrolled();
    let id = enrollment.id;
    registry.enroll(&enrollment).unwrap();
    let dir = tempdir().unwrap();
    let fences = Fences::new(dir.path().into());

    let report = registry
        .recover_host(
            id,
            |id| fences.cutoff(id, |_| Ok(())),
            |_| Err("observer unavailable".into()),
        )
        .unwrap();
    assert_eq!(report.admissions, Observation::Verified);
    assert_eq!(report.shutdown, Observation::Unknown);
    assert_eq!(registry.get(id).unwrap().unwrap().mode, Mode::Containing);
    let report = registry
        .recover_host(id, |id| fences.cutoff(id, |_| Ok(())), |_| Ok(true))
        .unwrap();
    assert_eq!(report.shutdown, Observation::Verified);
    let row = registry.get(id).unwrap().unwrap();
    assert_eq!(row.mode, Mode::Terminated);
    assert_eq!(row.epoch, 1);
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

#[test]
fn an_admission_fence_closed_while_paused_prevents_vm_resume() {
    let mut registry = Registry::memory().unwrap();
    let vm = FakeVm::default();
    let item = enrolled();
    registry.enroll(&item).unwrap();
    let mut lifecycle = Lifecycle::new(&mut registry, &vm);
    let result = lifecycle.start_guarded(item.id, launch, || {
        if vm.state(item.id)? == VmState::Paused {
            return Err("emergency fence closed after paused start".into());
        }
        Ok(())
    });
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("emergency fence closed")
    );
    assert_eq!(vm.resume_calls.get(), 0);
    assert_eq!(vm.state(item.id).unwrap(), VmState::Absent);
}

#[test]
fn an_admission_fence_closed_during_resume_requires_verified_cleanup() {
    let mut registry = Registry::memory().unwrap();
    let vm = FakeVm::default();
    let item = enrolled();
    registry.enroll(&item).unwrap();
    let mut lifecycle = Lifecycle::new(&mut registry, &vm);
    let result = lifecycle.start_guarded(item.id, launch, || {
        if vm.state(item.id)? == VmState::Running {
            return Err("emergency fence closed during resume".into());
        }
        Ok(())
    });
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("cleanup: Verified")
    );
    assert_eq!(vm.resume_calls.get(), 1);
    assert_eq!(vm.state(item.id).unwrap(), VmState::Absent);
    assert_eq!(
        lifecycle.status(item.id).unwrap().unwrap().mode,
        Mode::Contained
    );
}
