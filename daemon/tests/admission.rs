use alethic_guardd::{
    GuardResult,
    effect::{Action, Governance, Outcome},
    lifecycle::{Enrolled, Lifecycle, Registry},
    vm::{DomainSpec, Hypervisor, VmState},
};
use std::{cell::Cell, path::PathBuf};
use uuid::Uuid;

#[derive(Default)]
struct LabVm(Cell<Option<VmState>>, std::cell::RefCell<String>);

impl Hypervisor for LabVm {
    fn create_paused(&self, domain: &DomainSpec) -> GuardResult<()> {
        self.0.set(Some(VmState::Paused));
        self.1.replace(domain.xml()?);
        Ok(())
    }
    fn active_xml(&self, _: Uuid) -> GuardResult<String> {
        Ok(self.1.borrow().clone())
    }
    fn is_transient(&self, _: Uuid) -> GuardResult<bool> {
        Ok(true)
    }
    fn state(&self, _: Uuid) -> GuardResult<VmState> {
        Ok(self.0.get().unwrap_or(VmState::Absent))
    }
    fn suspend(&self, _: Uuid) -> GuardResult<()> {
        Ok(())
    }
    fn resume(&self, _: Uuid) -> GuardResult<()> {
        self.0.set(Some(VmState::Running));
        Ok(())
    }
    fn destroy(&self, _: Uuid) -> GuardResult<()> {
        self.0.set(None);
        Ok(())
    }
}

fn setup() -> (Registry, LabVm, Action, Governance) {
    setup_with(Registry::memory().unwrap())
}

fn setup_with(mut registry: Registry) -> (Registry, LabVm, Action, Governance) {
    let vm = LabVm::default();
    let workload_id = Uuid::new_v4();
    let enrolled = Enrolled {
        id: workload_id,
        profile: "broker-lab".into(),
        policy_digest: format!("sha256:{}", "a".repeat(64)),
        image: PathBuf::from("/fake/base.qcow2"),
        image_digest: "pinned".into(),
        input: None,
        input_digest: None,
        broker: false,
    };
    registry.enroll(&enrolled).unwrap();
    let running = Lifecycle::new(&mut registry, &vm)
        .start(workload_id, |_| Ok("/test/overlay.qcow2".into()))
        .unwrap();
    let action = Action {
        workload_id,
        generation: running.generation,
        epoch: running.epoch,
        policy_digest: enrolled.policy_digest,
        operation: "collector.publish".into(),
        target: "https://collector.example/test".into(),
        payload_sha256: "a".repeat(64),
        data_labels: vec!["public".into()],
        request_id: Uuid::new_v4(),
        idempotency_key: Uuid::new_v4(),
    };
    let decision = Governance {
        session: Uuid::new_v4(),
        ok: true,
        trace_id: Uuid::new_v4().to_string(),
        code: "COMMITTED".into(),
        proposal_id: "proposal".into(),
        action_id: Some("action".into()),
        evidence_id: Some("evidence".into()),
    };
    (registry, vm, action, decision)
}

#[test]
fn test_grant_is_single_use_and_bound_to_caller_and_action() {
    let (mut registry, _, action, decision) = setup();
    let permit = registry.issue_grant(&action, &decision, 300001, 0).unwrap();
    assert!(
        registry
            .authenticate_controller_session(permit, decision.session)
            .is_ok()
    );
    assert!(
        registry
            .authenticate_controller_session(permit, Uuid::new_v4())
            .is_err()
    );
    let mut changed = action.clone();
    changed.payload_sha256 = "b".repeat(64);
    assert!(registry.redeem_grant(permit, &changed, 300001, 1).is_err());
    assert!(registry.redeem_grant(permit, &action, 300002, 1).is_err());
    registry.redeem_grant(permit, &action, 300001, 1).unwrap();
    assert!(registry.redeem_grant(permit, &action, 300001, 1).is_err());
    assert_eq!(
        registry
            .outcome(action.workload_id, action.request_id)
            .unwrap(),
        Some(Outcome::Started)
    );
}

#[test]
fn test_commit_has_no_effect_without_current_permit() {
    let (mut registry, vm, action, decision) = setup();
    assert_eq!(
        registry
            .outcome(action.workload_id, action.request_id)
            .unwrap(),
        None
    );
    let permit = registry.issue_grant(&action, &decision, 300001, 0).unwrap();
    Lifecycle::new(&mut registry, &vm)
        .contain(action.workload_id, false)
        .unwrap();
    assert!(registry.redeem_grant(permit, &action, 300001, 1).is_err());
    assert_eq!(
        registry
            .outcome(action.workload_id, action.request_id)
            .unwrap(),
        None
    );
}

#[test]
fn test_crash_after_send_requires_reconciliation() {
    let (mut registry, _, action, decision) = setup();
    let permit = registry.issue_grant(&action, &decision, 300001, 0).unwrap();
    registry.redeem_grant(permit, &action, 300001, 1).unwrap();
    registry.recover_effects().unwrap();
    assert_eq!(
        registry
            .outcome(action.workload_id, action.request_id)
            .unwrap(),
        Some(Outcome::OutcomeUnknown)
    );
    assert!(registry.issue_grant(&action, &decision, 300001, 1).is_err());
}

#[test]
fn test_reconciliation_requires_exact_collector_receipt() {
    let (mut registry, _, action, decision) = setup();
    let permit = registry.issue_grant(&action, &decision, 300001, 0).unwrap();
    registry.redeem_grant(permit, &action, 300001, 1).unwrap();
    registry.recover_effects().unwrap();
    assert!(
        registry
            .reconcile_receipt(
                action.workload_id,
                action.request_id,
                Uuid::new_v4(),
                &action.payload_sha256
            )
            .is_err()
    );
    assert!(
        registry
            .reconcile_receipt(
                action.workload_id,
                action.request_id,
                action.idempotency_key,
                "wrong"
            )
            .is_err()
    );
    registry
        .reconcile_receipt(
            action.workload_id,
            action.request_id,
            action.idempotency_key,
            &action.payload_sha256,
        )
        .unwrap();
    assert_eq!(
        registry
            .outcome(action.workload_id, action.request_id)
            .unwrap(),
        Some(Outcome::Succeeded)
    );
}

#[test]
fn test_old_dispatch_is_fenced_when_containment_is_observed() {
    let (mut registry, vm, action, decision) = setup();
    let nonce = registry.issue_grant(&action, &decision, 300001, 0).unwrap();
    registry.redeem_grant(nonce, &action, 300001, 1).unwrap();
    assert!(registry.check_dispatch(nonce, 300001, 2).is_ok());
    Lifecycle::new(&mut registry, &vm)
        .contain(action.workload_id, true)
        .unwrap();
    assert!(registry.check_dispatch(nonce, 300001, 3).is_err());
    assert_eq!(
        registry
            .outcome(action.workload_id, action.request_id)
            .unwrap(),
        Some(Outcome::OutcomeUnknown)
    );
}

#[test]
fn test_expired_grant_never_admits_effect() {
    let (mut registry, _, action, decision) = setup();
    let nonce = registry.issue_grant(&action, &decision, 300001, 9).unwrap();
    assert!(
        registry
            .redeem_grant(nonce, &action, 300001, 10_000_000_009)
            .is_err()
    );
    assert!(
        registry
            .outcome(action.workload_id, action.request_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn test_admission_journal_failure_rolls_back_nonce_and_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.db");
    let (mut registry, _, action, decision) = setup_with(Registry::open(&path).unwrap());
    let nonce = registry.issue_grant(&action, &decision, 300001, 0).unwrap();
    let db = rusqlite::Connection::open(path).unwrap();
    db.execute_batch(
        "CREATE TRIGGER lab_journal_fault BEFORE INSERT ON events
         BEGIN SELECT RAISE(ABORT, 'synthetic journal fault'); END;",
    )
    .unwrap();
    assert!(registry.redeem_grant(nonce, &action, 300001, 1).is_err());
    assert_eq!(
        registry
            .outcome(action.workload_id, action.request_id)
            .unwrap(),
        None
    );
    assert!(registry.check_dispatch(nonce, 300001, 1).is_err());
    db.execute_batch("DROP TRIGGER lab_journal_fault;").unwrap();
    registry.redeem_grant(nonce, &action, 300001, 1).unwrap();
}

#[test]
fn test_only_one_concurrent_redemption_succeeds() {
    use std::sync::{Arc, Barrier};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("race.db");
    let (mut registry, _, action, decision) = setup_with(Registry::open(&path).unwrap());
    let nonce = registry.issue_grant(&action, &decision, 300001, 0).unwrap();
    let fence = Arc::new(Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let mut local = Registry::open(&path).unwrap();
            let action = action.clone();
            let fence = fence.clone();
            std::thread::spawn(move || {
                fence.wait();
                local.redeem_grant(nonce, &action, 300001, 1).is_ok()
            })
        })
        .collect();
    assert_eq!(
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|ok| *ok)
            .count(),
        1
    );
}

#[test]
fn test_evidence_separates_governance_effect_and_observer() {
    let (mut registry, _, action, decision) = setup();
    let nonce = registry.issue_grant(&action, &decision, 300001, 0).unwrap();
    registry.redeem_grant(nonce, &action, 300001, 1).unwrap();
    registry.finish(nonce, 300001, Outcome::Succeeded).unwrap();
    let events = registry.observation_page(action.workload_id, 0).unwrap();
    let types: Vec<_> = events.iter().map(|row| row.event_type.as_str()).collect();
    assert_eq!(
        types,
        [
            "GOVERNANCE_DECISION",
            "PERMIT_ISSUED",
            "EFFECT_STARTED",
            "EFFECT_SUCCEEDED"
        ]
    );
    assert_eq!(events[0].assurance, "HOST_REPORTED");
    assert_eq!(events[3].assurance, "EXTERNAL_ACK");
    assert_eq!(events[3].decision_id, Some(decision.trace_id));
}
