use alethic_guardd::emergency::Fences;
use std::sync::{Arc, mpsc};
use std::time::Duration;
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn cutoff_latches_across_reopen_and_requires_successful_release() {
    let directory = tempdir().unwrap();
    let id = Uuid::new_v4();
    let fences = Fences::new(directory.path().to_path_buf());
    assert!(fences.with_open(id, || Ok(42)).is_ok());
    fences.cutoff(id, |_| Ok(())).unwrap();

    let reopened = Fences::new(directory.path().to_path_buf());
    assert!(reopened.with_open(id, || Ok(())).is_err());
    assert!(
        reopened
            .release(id, || Err::<(), _>("release denied".into()))
            .is_err()
    );
    assert!(reopened.with_open(id, || Ok(())).is_err());
    reopened.release(id, || Ok(())).unwrap();
    assert!(reopened.with_open(id, || Ok(())).is_ok());
}

#[test]
fn verifying_cutoff_serializes_enable_for_the_same_workload() {
    let directory = tempdir().unwrap();
    let fences = Arc::new(Fences::new(directory.path().to_path_buf()));
    let id = Uuid::new_v4();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (finish_tx, finish_rx) = mpsc::channel();
    let worker = Arc::clone(&fences);
    let cut = std::thread::spawn(move || {
        worker
            .cutoff(id, |_| {
                entered_tx.send(()).unwrap();
                finish_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                Ok(())
            })
            .unwrap()
    });
    entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();

    assert!(fences.with_open(id, || Ok(())).is_err());
    let (outcome_tx, outcome_rx) = mpsc::channel();
    let other_worker = Arc::clone(&fences);
    let admission = std::thread::spawn(move || {
        outcome_tx
            .send(other_worker.enable(id, || Ok(())).is_err())
            .unwrap();
    });
    assert!(fences.with_open(Uuid::new_v4(), || Ok(())).is_ok());
    assert!(outcome_rx.recv_timeout(Duration::from_millis(20)).is_err());
    finish_tx.send(()).unwrap();
    cut.join().unwrap();
    assert!(outcome_rx.recv_timeout(Duration::from_secs(3)).unwrap());
    admission.join().unwrap();
}

#[test]
fn slow_ordinary_work_and_a_stale_release_cannot_hold_off_cutoff() {
    let directory = tempdir().unwrap();
    let fences = Fences::new(directory.path().to_path_buf());
    let id = Uuid::new_v4();
    let normal = fences.with_open(id, || {
        fences.cutoff(id, |_| Ok(()))?;
        Ok("grant committed")
    });
    assert!(normal.is_err());

    let stale_release = fences.release(id, || fences.cutoff(id, |_| Ok(())));
    assert!(stale_release.is_err());
    assert!(fences.with_open(id, || Ok(())).is_err());
    fences.release(id, || Ok(())).unwrap();
    assert!(fences.with_open(id, || Ok(())).is_ok());
}

#[test]
fn host_cutoff_is_attempted_even_when_marker_persistence_fails() {
    let directory = tempdir().unwrap();
    let fences = Fences::new(directory.path().join("missing"));
    let id = Uuid::new_v4();
    let mut attempted = false;
    assert!(
        fences
            .cutoff(id, |_| {
                attempted = true;
                Ok(())
            })
            .is_err()
    );
    assert!(attempted);
    assert!(fences.with_open(id, || Ok(())).is_err());
}

#[test]
fn emergency_shutdown_fences_admissions_before_observing_the_vm() {
    let directory = tempdir().unwrap();
    let fences = Arc::new(Fences::new(directory.path().to_path_buf()));
    let id = Uuid::new_v4();
    fences.register(id).unwrap();
    let observed = Arc::clone(&fences);

    let outcome = fences
        .emergency_terminate(
            id,
            |_| Ok(()),
            move || {
                assert!(observed.with_open(id, || Ok(())).is_err());
                Ok(true)
            },
        )
        .unwrap();
    assert_eq!(outcome["broker_cutoff"], "VERIFIED");
    assert_eq!(outcome["shutdown"], "VERIFIED");
    assert!(directory.path().join(id.to_string()).is_file());
    assert!(fences.guest_operation(id, || Ok(())).is_err());
}

#[test]
fn emergency_shutdown_proceeds_while_broker_cutoff_is_stalled() {
    let directory = tempdir().unwrap();
    let fences = Arc::new(Fences::new(directory.path().to_path_buf()));
    let id = Uuid::new_v4();
    fences.register(id).unwrap();
    let (finish_cut, release_cut) = mpsc::channel();
    let (stopped, observed) = mpsc::channel();

    let worker = std::thread::spawn(move || {
        fences
            .emergency_terminate(
                id,
                move |_| {
                    release_cut.recv_timeout(Duration::from_secs(6)).unwrap();
                    Ok(())
                },
                move || {
                    stopped.send(()).unwrap();
                    Ok(true)
                },
            )
            .unwrap()
    });
    let shutdown_was_independent = observed.recv_timeout(Duration::from_secs(1)).is_ok();
    let outcome = if shutdown_was_independent {
        let outcome = worker.join().unwrap();
        finish_cut.send(()).unwrap();
        outcome
    } else {
        finish_cut.send(()).unwrap();
        worker.join().unwrap()
    };
    assert!(
        shutdown_was_independent,
        "VM shutdown waited for broker cutoff"
    );
    assert_eq!(outcome["shutdown"], "VERIFIED");
    assert_eq!(outcome["broker_cutoff"], "UNKNOWN");
}

#[test]
fn unavailable_shutdown_observation_preserves_the_admission_fence() {
    let directory = tempdir().unwrap();
    let fences = Fences::new(directory.path().to_path_buf());
    let id = Uuid::new_v4();
    fences.register(id).unwrap();

    let outcome = fences
        .emergency_terminate(id, |_| Ok(()), || Err("hypervisor unavailable".into()))
        .unwrap();
    assert_eq!(outcome["admissions"], "VERIFIED");
    assert_eq!(outcome["shutdown"], "UNKNOWN");
    assert!(fences.with_open(id, || Ok(())).is_err());
}

#[test]
fn emergency_shutdown_cannot_report_absence_during_a_guest_transition() {
    let directory = tempdir().unwrap();
    let fences = Fences::new(directory.path().to_path_buf());
    let id = Uuid::new_v4();
    fences.register(id).unwrap();
    let (pending, stopped) = mpsc::channel();

    let result = fences
        .guest_operation(id, || {
            let report = fences.emergency_terminate(
                id,
                |_| Ok(()),
                move || {
                    pending.send(()).unwrap();
                    Ok(true)
                },
            )?;
            assert!(stopped.try_recv().is_err());
            Ok(report)
        })
        .unwrap();
    assert_eq!(result["broker_cutoff"], "VERIFIED");
    assert_eq!(result["shutdown"], "UNKNOWN");
    stopped.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(fences.guest_operation(id, || Ok(())).is_err());
    assert!(fences.guest_operation(Uuid::new_v4(), || Ok(())).is_ok());
}
