"""Compile a fail-closed WorkloadPolicy into a stable representation."""

from dataclasses import dataclass
import hashlib
from importlib.resources import files
import json
from pathlib import PurePosixPath
from urllib.parse import urlsplit
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
    mediated_api: bool = False


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
_HOSTNAME = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+", re.ASCII)
_TARGET_PATH = re.compile(r"/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+", re.ASCII)


def _validate_destination(target: str) -> None:
    if not target.isascii() or any(c.isspace() or ord(c) < 32 for c in target):
        raise PolicyError("invalid collector destination")
    parsed = urlsplit(target)
    port = parsed.port
    hostname = parsed.hostname or ""
    if (
        parsed.scheme != "https" or not _HOSTNAME.fullmatch(hostname)
        or not hostname.rsplit(".", 1)[1].isalpha()
        or parsed.netloc != hostname + (f":{port}" if port else "")
        or port == 443 or not _TARGET_PATH.fullmatch(parsed.path)
        or {".", ".."}.intersection(parsed.path.split("/"))
        or target != f"https://{parsed.netloc}{parsed.path}"
    ):
        raise PolicyError("collector destination must be an exact canonical HTTPS URL")



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
    destinations = spec["network"]["approved_broker_destinations"]
    collector = "collector.publish" in spec["tools"]["allowed"]
    if spec["profile"] == "offline-strict":
        if destinations or collector:
            raise PolicyError("offline-strict denies broker destinations and operations")
    elif spec["profile"] == "allowlisted-api" and capabilities.mediated_api:
        if len(destinations) != 1 or not collector:
            raise PolicyError("allowlisted-api requires one destination and collector.publish")
        try:
            _validate_destination(destinations[0])
        except ValueError as error:
            raise PolicyError("invalid collector destination") from error
    else:
        raise PolicyError(f"unsupported profile for this backend: {spec['profile']}")
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
