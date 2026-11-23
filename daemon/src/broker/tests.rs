use super::*;
use std::cell::RefCell;

fn record_binding(registry: &Registry, id: Uuid, slot: i64, retired: bool) {
    registry
        .conn
        .execute(
            "INSERT INTO gateway_bindings (workload, generation, slot, active, retired)
         VALUES (?1, 1, ?2, 1, ?3)",
            params![id.to_string(), slot, retired],
        )
        .unwrap();
}

#[test]
fn a_retired_slot_can_only_be_reused_by_its_enrollment() {
    let mut registry = Registry::memory().unwrap();
    let mut enrollment = crate::lifecycle::Enrolled {
        id: Uuid::new_v4(),
        profile: "mediated".into(),
        policy_digest: "test-policy".into(),
        image: "/approved/image.qcow2".into(),
        image_digest: "test-image".into(),
        input: None,
        input_digest: None,
        broker: true,
    };
    let mut workload = registry.enroll(&enrollment).unwrap();
    let first = registry
        .reserve_gateway_with(&workload, |_, reused| {
            assert!(!reused);
            Ok(())
        })
        .unwrap();
    assert!(
        registry
            .reserve_gateway_with(&workload, |_, _| panic!("active slot"))
            .is_err()
    );
    registry.set_gateway(first, false, true).unwrap();
    registry
        .conn
        .execute(
            "INSERT INTO gateway_processes VALUES (?1, 200, 1)",
            [first.slot],
        )
        .unwrap();

    enrollment.id = Uuid::new_v4();
    let other = registry.enroll(&enrollment).unwrap();
    let other_binding = registry
        .reserve_gateway_with(&other, |_, _| Ok(()))
        .unwrap();
    assert_ne!(other_binding.slot, first.slot);

    workload.generation += 1;
    let failed =
        registry.reserve_gateway_with(&workload, |_, _| Err("namespace still present".into()));
    assert!(failed.is_err());
    let next = registry
        .reserve_gateway_with(&workload, |_, reused| {
            assert!(reused);
            Ok(())
        })
        .unwrap();
    assert_eq!(next.slot, first.slot);
    assert_eq!(next.generation, workload.generation);
    let old_process: u32 = registry
        .conn
        .query_row(
            "SELECT COUNT(*) FROM gateway_processes WHERE slot=?1",
            [next.slot],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(old_process, 0);
}

#[test]
fn stop_sweeps_later_matching_bindings_after_a_host_operation_fails() {
    let id = Uuid::from_u128(1);
    let other = Uuid::from_u128(2);
    for (filter, failing_step) in [(None, "seal"), (Some(id), "stop")] {
        let mut registry = Registry::memory().unwrap();
        record_binding(&registry, id, 1, false);
        record_binding(&registry, id, 2, false);
        record_binding(&registry, other, 3, false);
        record_binding(&registry, id, 4, true);

        let attempts = RefCell::new(Vec::new());
        let result = stop_with(
            &mut registry,
            filter,
            |sandbox| {
                let ns = sandbox.namespace();
                let fail = ns == "aleg1" && failing_step == "seal";
                attempts.borrow_mut().push(("seal", ns));
                if fail {
                    return Err("cutoff observation failed".into());
                }
                Ok(())
            },
            |sandbox| {
                let ns = sandbox.namespace();
                let fail = ns == "aleg1" && failing_step == "stop";
                attempts.borrow_mut().push(("stop", ns));
                if fail {
                    return Err("helper shutdown unconfirmed".into());
                }
                Ok(())
            },
        );

        let expected_error = if failing_step == "seal" {
            "cutoff observation failed"
        } else {
            "helper shutdown unconfirmed"
        };
        assert!(result.unwrap_err().to_string().contains(expected_error));
        let mut expected = vec![
            ("seal", "aleg1"),
            ("stop", "aleg1"),
            ("seal", "aleg2"),
            ("stop", "aleg2"),
        ];
        if filter.is_none() {
            expected.extend([("seal", "aleg3"), ("stop", "aleg3")]);
        }
        let mut actual = attempts.into_inner();
        actual.sort_by(|a, b| a.1.cmp(&b.1));
        let actual: Vec<_> = actual
            .iter()
            .map(|(step, ns)| (*step, ns.as_str()))
            .collect();
        assert_eq!(actual, expected);
        let remaining = registry.bindings(None).unwrap();
        assert_eq!(remaining.len(), if filter.is_none() { 1 } else { 2 });
        let failed = remaining.iter().find(|binding| binding.slot == 1).unwrap();
        assert!(!failed.active);
        if filter.is_some() {
            assert!(
                remaining
                    .iter()
                    .any(|binding| binding.slot == 3 && binding.active)
            );
        }
    }
}

#[test]
fn stop_uses_each_identifiable_slot_even_with_invalid_binding_metadata() {
    let mut registry = Registry::memory().unwrap();
    let id = Uuid::from_u128(1);
    record_binding(&registry, id, -1, false);
    record_binding(&registry, id, 1, false);
    record_binding(&registry, id, 2, false);
    registry
        .conn
        .execute("UPDATE gateway_bindings SET generation=-1 WHERE slot=1", [])
        .unwrap();

    let mut cutoff = Vec::new();
    let result = stop_with(
        &mut registry,
        None,
        |sandbox| {
            cutoff.push(sandbox.namespace());
            Ok(())
        },
        |_| Ok(()),
    );

    assert!(result.is_err());
    cutoff.sort();
    assert_eq!(cutoff, ["aleg1", "aleg2"]);
    let retired: u32 = registry
        .conn
        .query_row(
            "SELECT COUNT(*) FROM gateway_bindings WHERE slot IN (1, 2) AND retired=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retired, 2);
}
