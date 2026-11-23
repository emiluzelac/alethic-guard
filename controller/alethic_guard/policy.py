"""Compile a fail-closed WorkloadPolicy into a stable representation."""

from dataclasses import dataclass
import hashlib
from importlib.resources import files
import json
from pathlib import PurePosixPath
import re

from jsonschema import Draft202012Validator
import yaml


class PolicyError(ValueError):
    """A policy is invalid or exceeds the declared backend capabilities."""


class _PolicyLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise PolicyError("policy keys must be strings")
            if key in result:
                raise PolicyError(f"duplicate policy key: {key}")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


@dataclass(frozen=True)
class BackendCapabilities:
    vm_isolated: bool = True


@dataclass(frozen=True)
class CompiledPolicy:
    name: str
    profile: str
    digest: str
    canonical: bytes


_SCHEMA = Draft202012Validator(
    json.loads(files("alethic_guard_policy_data").joinpath("schema-v1.json").read_bytes())
)
_GUEST_PATH = re.compile(r"/data(?:/[A-Za-z0-9_.-]+)+", re.ASCII)
_MAX_POLICY_BYTES = 65_536


def compile_policy(document: bytes, capabilities: BackendCapabilities) -> CompiledPolicy:
    if len(document) > _MAX_POLICY_BYTES:
        raise PolicyError("policy exceeds 65536 bytes")
    try:
        for token in yaml.scan(document, Loader=_PolicyLoader):
            if isinstance(token, (yaml.AliasToken, yaml.AnchorToken, yaml.TagToken)):
                raise PolicyError("policy aliases, anchors, and explicit tags are unsupported")
        policy = yaml.load(document, Loader=_PolicyLoader)
    except (yaml.YAMLError, RecursionError) as error:
        raise PolicyError("invalid YAML policy") from error
    error = next(_SCHEMA.iter_errors(policy), None)
    if error is not None:
        raise PolicyError(f"{error.json_path}: {error.message}")

    spec = policy["spec"]
    if not capabilities.vm_isolated:
        raise PolicyError("backend does not support vm-isolated")
    if spec["profile"] != "offline-strict":
        raise PolicyError(f"unsupported profile: {spec['profile']}")
    if spec["network"]["approved_broker_destinations"] or "collector.publish" in spec["tools"]["allowed"]:
        raise PolicyError("offline-strict denies broker destinations and operations")
    paths = []
    for volume in spec["filesystem"]["inputs"] + spec["filesystem"]["outputs"]:
        value = volume["path"]
        if not _GUEST_PATH.fullmatch(value) or {".", ".."}.intersection(value.split("/")):
            raise PolicyError(f"ambiguous guest volume path: {value}")
        paths.append(PurePosixPath(value))
    if len(paths) == 2 and (paths[0].is_relative_to(paths[1]) or paths[1].is_relative_to(paths[0])):
        raise PolicyError("input and output volume paths overlap")
    spec["tools"]["allowed"].sort()
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return CompiledPolicy(
        name=policy["metadata"]["name"],
        profile=spec["profile"],
        digest="sha256:" + hashlib.sha256(canonical).hexdigest(),
        canonical=canonical,
    )
