import json
from pathlib import Path

import pytest

from alethic_guard.policy import BackendCapabilities, PolicyError, compile_policy


EXAMPLE = Path(__file__).resolve().parents[2] / "policy/examples/offline-research.yaml"


def test_policy_rejects_unknown_fields_and_unsupported_features():
    doc = EXAMPLE.read_bytes()
    with pytest.raises(PolicyError, match="unknown|Additional"):
        compile_policy(doc + b"  unsafe: true\n", BackendCapabilities())
    with pytest.raises(PolicyError, match="backend|unsupported"):
        compile_policy(doc, BackendCapabilities(vm_isolated=False))
    with pytest.raises(PolicyError, match="profile|unsupported"):
        compile_policy(doc.replace(b"offline-strict", b"monitor-only"), BackendCapabilities())


def test_policy_rejects_duplicate_keys_and_ambiguous_paths():
    doc = EXAMPLE.read_bytes()
    with pytest.raises(PolicyError, match="duplicate"):
        compile_policy(doc + b"  enforce: false\n", BackendCapabilities())
    with pytest.raises(PolicyError, match="path"):
        compile_policy(doc.replace(b"/data/approved", b"/data/../approved"), BackendCapabilities())


def test_policy_digest_is_stable_and_semantic():
    doc = EXAMPLE.read_bytes()
    compiled = compile_policy(doc, BackendCapabilities())
    assert compiled.name == "offline-research"
    assert compiled.profile == "offline-strict"
    assert compiled.digest.startswith("sha256:")
    assert compile_policy(json.dumps(json.loads(compiled.canonical)).encode(), BackendCapabilities()) == compiled
    assert compile_policy(doc.replace(b"/data/results", b"/data/output"), BackendCapabilities()).digest != compiled.digest


def test_mediated_profile_requires_capability_and_exact_https_endpoint():
    path = EXAMPLE.with_name("allowlisted-api.yaml")
    doc = path.read_bytes()
    with pytest.raises(PolicyError, match="backend|unsupported"):
        compile_policy(doc, BackendCapabilities())
    caps = BackendCapabilities(mediated_api=True)
    assert compile_policy(doc, caps).profile == "allowlisted-api"
    for target in (b"http://collector.example/v1/fixture", b"https://user@collector.example/v1/fixture",
                   b"https://collector.example/v1/fixture?source=guest",
                   b"https://collector.example/a/../v1/fixture"):
        with pytest.raises(PolicyError, match="destination"):
            compile_policy(doc.replace(b"https://collector.example/v1/fixture", target), caps)
