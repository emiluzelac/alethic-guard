use super::*;
use serde_json::json;

fn comparison(op: &str, left: Value, right: Value) -> Value {
    json!({"match": {"op": op, "left": left, "right": right}})
}

fn interface(direction: &str) -> Value {
    comparison("==", json!({"meta": {"key": direction}}), json!("agw7"))
}

fn payload(protocol: &str, field: &str, value: Value) -> Value {
    comparison(
        "==",
        json!({"payload": {"protocol": protocol, "field": field}}),
        value,
    )
}

fn rule(chain: &str, expressions: Vec<Value>) -> Value {
    json!({"rule": {
        "family": "inet", "table": "alethic_guard_7", "chain": chain, "expr": expressions
    }})
}

fn deny_observation() -> Value {
    let drop = |chain, direction| {
        rule(
            chain,
            vec![
                interface(direction),
                json!({"counter": {"packets": 4, "bytes": 248}}),
                json!({"drop": null}),
            ],
        )
    };
    json!({"nftables": [
        {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak", "json_schema_version": 1}},
        {"table": {"family": "inet", "name": "alethic_guard_7", "handle": 4}},
        {"chain": {"family": "inet", "table": "alethic_guard_7", "name": "input",
                   "type": "filter", "hook": "input", "prio": -250, "policy": "accept", "handle": 1}},
        drop("input", "iifname"),
        {"chain": {"family": "inet", "table": "alethic_guard_7", "name": "forward",
                   "type": "filter", "hook": "forward", "prio": -10, "policy": "accept", "handle": 2}},
        drop("forward", "iifname"),
        drop("forward", "oifname"),
        {"chain": {"family": "inet", "table": "alethic_guard_7", "name": "postrouting",
                   "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept", "handle": 3}}
    ]})
}

fn enabled_observation() -> Value {
    let mut observed = deny_observation();
    let entries = observed["nftables"].as_array_mut().unwrap();
    let icmpv6_type = json!({"payload": {"protocol": "icmpv6", "field": "type"}});
    entries.insert(
        3,
        rule(
            "input",
            vec![
                interface("iifname"),
                payload("ip6", "hoplimit", json!(255)),
                comparison(
                    "==",
                    icmpv6_type,
                    json!({"set": ["nd-neighbor-solicit", "nd-neighbor-advert"]}),
                ),
                json!({"accept": null}),
            ],
        ),
    );
    let ct = json!({"ct": {"key": "state"}});
    for (index, family, address) in [(0, "ip", "8.8.8.8"), (1, "ip6", "2606:4700::1111")] {
        entries.insert(
            6 + 2 * index,
            rule(
                "forward",
                vec![
                    interface("iifname"),
                    payload(family, "daddr", json!(address)),
                    payload("tcp", "dport", json!(8443)),
                    comparison("==", ct.clone(), json!({"set": ["established", "new"]})),
                    json!({"accept": null}),
                ],
            ),
        );
        entries.insert(
            7 + 2 * index,
            rule(
                "forward",
                vec![
                    interface("oifname"),
                    payload(family, "saddr", json!(address)),
                    payload("tcp", "sport", json!(8443)),
                    comparison("in", ct.clone(), json!("established")),
                    json!({"accept": null}),
                ],
            ),
        );
        entries.push(rule(
            "postrouting",
            vec![
                interface("iifname"),
                payload(family, "daddr", json!(address)),
                payload("tcp", "dport", json!(8443)),
                json!({"masquerade": null}),
            ],
        ));
    }
    observed
}

#[test]
fn cutoff_requires_active_table_and_all_exact_base_chains() {
    let sandbox = Sandbox::new(7).unwrap();
    let observed = deny_observation();
    sandbox.verify_readback(&observed, &[], 0).unwrap();

    for (index, field, invalid) in [
        (2, "type", Value::Null),
        (2, "hook", Value::Null),
        (2, "prio", json!(-249)),
        (4, "hook", json!("output")),
        (4, "policy", json!("drop")),
        (7, "prio", json!(101)),
        (7, "table", json!("alethic_guard_8")),
    ] {
        let mut modified = observed.clone();
        modified["nftables"][index]["chain"][field] = invalid;
        assert!(
            sandbox.verify_readback(&modified, &[], 0).is_err(),
            "{index} {field}"
        );
    }
    let mut dormant = observed.clone();
    dormant["nftables"][1]["table"]["flags"] = json!(["dormant"]);
    assert!(sandbox.verify_readback(&dormant, &[], 0).is_err());
    let mut duplicate = observed;
    let entries = duplicate["nftables"].as_array_mut().unwrap();
    entries.push(entries[2].clone());
    assert!(sandbox.verify_readback(&duplicate, &[], 0).is_err());
}

#[test]
fn cutoff_requires_exact_unconditional_per_interface_drops() {
    let sandbox = Sandbox::new(7).unwrap();
    let observed = deny_observation();
    let mut modified = observed.clone();
    modified["nftables"][3]["rule"]["expr"][0]["match"]["op"] = json!("!=");
    assert!(sandbox.verify_readback(&modified, &[], 0).is_err());

    let mut modified = observed.clone();
    modified["nftables"][5]["rule"]["expr"]
        .as_array_mut()
        .unwrap()
        .insert(1, payload("tcp", "dport", json!(8443)));
    assert!(sandbox.verify_readback(&modified, &[], 0).is_err());

    let mut modified = observed.clone();
    modified["nftables"].as_array_mut().unwrap().swap(5, 6);
    assert!(sandbox.verify_readback(&modified, &[], 0).is_err());

    let mut modified = observed;
    modified["nftables"].as_array_mut().unwrap().push(rule(
        "postrouting",
        vec![interface("iifname"), json!({"drop": null})],
    ));
    assert!(sandbox.verify_readback(&modified, &[], 0).is_err());
    assert!(
        sandbox
            .verify_readback(&enabled_observation(), &[], 0)
            .is_err()
    );
}

#[test]
fn enabled_readback_requires_exact_ordered_endpoint_rules_and_ipv6_neighbor_discovery() {
    let sandbox = Sandbox::new(7).unwrap();
    let addresses = [
        "8.8.8.8".parse().unwrap(),
        "2606:4700::1111".parse().unwrap(),
    ];
    let observed = enabled_observation();
    sandbox
        .verify_readback(&observed, &addresses, 8443)
        .unwrap();

    let mut variant = observed.clone();
    variant["nftables"][6]["rule"]["expr"][3]["match"]["op"] = json!("in");
    variant["nftables"][6]["rule"]["expr"][3]["match"]["right"] = json!(["new", "established"]);
    sandbox.verify_readback(&variant, &addresses, 8443).unwrap();

    for (rule, statement, value) in [
        (3, 2, payload("icmpv6", "type", json!("nd-neighbor-advert"))),
        (6, 1, payload("ip", "daddr", json!("8.8.4.4"))),
        (7, 2, payload("tcp", "dport", json!(8443))),
        (8, 2, payload("tcp", "dport", json!(443))),
        (
            9,
            3,
            comparison(
                "in",
                json!({"ct": {"key": "state"}}),
                json!(["new", "established"]),
            ),
        ),
        (13, 3, json!({"masquerade": {"flags": "random"}})),
    ] {
        let mut modified = observed.clone();
        modified["nftables"][rule]["rule"]["expr"][statement] = value;
        assert!(
            sandbox
                .verify_readback(&modified, &addresses, 8443)
                .is_err(),
            "{rule} {statement}"
        );
    }
    let mut reordered = observed.clone();
    reordered["nftables"].as_array_mut().unwrap().swap(6, 8);
    assert!(
        sandbox
            .verify_readback(&reordered, &addresses, 8443)
            .is_err()
    );

    let mut missing = observed;
    missing["nftables"].as_array_mut().unwrap().remove(7);
    assert!(sandbox.verify_readback(&missing, &addresses, 8443).is_err());
    assert!(
        sandbox
            .verify_readback(&deny_observation(), &addresses, 8443)
            .is_err()
    );
}

#[test]
fn link_readback_requires_valid_names_to_confirm_absence() {
    let sandbox = Sandbox::new(7).unwrap();
    assert!(
        !sandbox
            .observed_link_present(&json!([{"ifname": "lo"}]))
            .unwrap()
    );
    assert!(
        sandbox
            .observed_link_present(&json!([{"ifname": "lo"}, {"ifindex": 4}]))
            .is_err()
    );
    assert!(
        sandbox
            .observed_link_present(&json!([{"ifindex": 4}, {"ifname": "agw7"}]))
            .unwrap()
    );
}

#[test]
fn unnamed_namespace_requires_observed_absence_of_managed_host_link() {
    let sandbox = Sandbox::new(7).unwrap();
    assert!(sandbox.stop_helpers_with(false, |_| Ok(false)).is_ok());
    assert!(sandbox.stop_helpers_with(false, |_| Ok(true)).is_err());
    assert!(
        sandbox
            .stop_helpers_with(false, |_| Err("link observation failed".into()))
            .is_err()
    );
}
