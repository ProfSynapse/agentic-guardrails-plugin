"""Trusted, data-only contracts for opaque write-capable scripts.

Repository manifests are inert until a user explicitly trusts one.  Trusting
copies a normalized, script-hash-bound record into AGW_HOME and authenticates
it with a machine-local key.  Execution resolves only a small placeholder
language; manifests never execute code.
"""
from __future__ import annotations

import base64
import binascii
import copy
import difflib
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import stat
import sys
import tempfile
import time
import zlib
from datetime import datetime, timezone
from typing import Optional

from . import store


MANIFEST_SCHEMA_V1 = "agw.workflow/v1"
MANIFEST_SCHEMA = "agw.workflow/v2"
PARAMETERIZED_SCHEMA = "agw.workflow/v3"
MANIFEST_SCHEMAS = {MANIFEST_SCHEMA_V1, MANIFEST_SCHEMA, PARAMETERIZED_SCHEMA}
RECORD_SCHEMA_V1 = "agw.trusted-workflow/v1"
RECORD_SCHEMA = "agw.trusted-workflow/v2"
RECORD_SCHEMAS = {RECORD_SCHEMA_V1, RECORD_SCHEMA}
REFRESH_PLAN_SCHEMA = "agw.workflow-refresh-plan/v1"
DIAGNOSTIC_SCHEMA = "agw.workflow-diagnostics/v1"
DIAGNOSTIC_REASON_CODES = frozenset({
    "command_normalization_failed",
    "unverified_record",
    "invalid_record",
    "runtime_mismatch",
    "script_path_mismatch",
    "script_hash_mismatch",
    "arguments_mismatch",
    "parameters_mismatch",
})
_DIAGNOSTIC_CLASS_ORDER = {
    "exact": 0,
    "parameterizable": 1,
    "near": 2,
    "incompatible": 3,
}
MAX_MANIFEST_BYTES = 256 * 1024
MAX_RECORD_BYTES = 512 * 1024
MAX_WORKFLOWS = 256
MAX_OUTPUTS = 128
MAX_ROOTS = 16
MAX_PATTERNS = 64
MAX_ARGS = 128
MAX_ARG_BYTES = 16 * 1024
MAX_PARAMETERS = 32
MAX_ENUM_VALUES = 512
MAX_PARAMETER_BYTES = 4096
MAX_SCRIPT_SNAPSHOT_BYTES = 128 * 1024
MAX_SCRIPT_SNAPSHOT_COMPRESSED_BYTES = 128 * 1024
MAX_REFRESH_PLAN_BYTES = 512 * 1024
MAX_REFRESH_DIFF_BYTES = 128 * 1024
MAX_REFRESH_DIFF_LINES = 2000
REFRESH_PLAN_TTL_NS = 30 * 60 * 1_000_000_000

_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
_PARAMETER_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_PLACEHOLDER_RE = re.compile(
    r"\{(cwd|script_dir|script_name|script_stem|temp|"
    r"arg:(?:0|[1-9][0-9]{0,2})(?::(?:basename|sha256))?|"
    r"param:[a-z][a-z0-9_-]{0,63}(?::(?:basename|sha256))?)\}"
)
_PYTHON_RE = re.compile(r"^(?:py|python|python3(?:\.\d+)?)$")
_PY_SELECTOR_RE = re.compile(r"^-\d(?:\.\d+)?(?:-\d+)?$")


class WorkflowError(RuntimeError):
    error_code = "workflow_error"

    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.details = details or {}


class WorkflowConflict(WorkflowError):
    error_code = "workflow_conflict"


class WorkflowTrustError(WorkflowError):
    error_code = "workflow_trust_error"


class WorkflowProvenanceError(WorkflowTrustError):
    error_code = "workflow_provenance_error"


class WorkflowRefreshError(WorkflowTrustError):
    error_code = "workflow_refresh_error"


def _json_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise WorkflowError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json_file(path: str) -> tuple[dict, str]:
    source = os.path.abspath(os.path.expanduser(str(path or "")))
    try:
        st = os.stat(source, follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise WorkflowError("workflow manifest must be an ordinary local file")
        if st.st_size > MAX_MANIFEST_BYTES:
            raise WorkflowError("workflow manifest exceeds 256 KiB")
        with open(source, "rb") as handle:
            raw = handle.read(MAX_MANIFEST_BYTES + 1)
    except OSError as exc:
        raise WorkflowError(f"workflow manifest could not be read: {exc}") from exc
    digest = hashlib.sha256(raw).hexdigest()
    try:
        value = json.loads(
            raw.decode("utf-8-sig"), object_pairs_hook=_json_no_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                WorkflowError(f"non-finite JSON value: {token}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise WorkflowError(f"workflow manifest must be valid UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise WorkflowError("workflow manifest must be a JSON object")
    return value, digest


def _exact_keys(value: dict, allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise WorkflowError(f"{label} contains unknown field(s): {', '.join(unknown)}")


def _validate_template(value, label: str, *, allow_args: bool = True,
                       allow_parameters: bool = True) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise WorkflowError(f"{label} must be a non-empty string of at most 4096 characters")
    if "\x00" in value or any(ord(char) < 32 for char in value):
        raise WorkflowError(f"{label} contains control characters")
    cursor = 0
    for match in re.finditer(r"\{[^{}]*\}", value):
        token = match.group(0)
        if not _PLACEHOLDER_RE.fullmatch(token):
            raise WorkflowError(f"{label} contains an unresolved or unsupported placeholder: {token}")
        if not allow_args and token.startswith("{arg:"):
            raise WorkflowError(f"{label} may not depend on command arguments")
        if not allow_parameters and token.startswith("{param:"):
            raise WorkflowError(f"{label} may not depend on workflow parameters")
        cursor = match.end()
    if "{" in value[cursor:] or "}" in value[cursor:]:
        raise WorkflowError(f"{label} contains an unresolved or ambiguous placeholder")
    without = _PLACEHOLDER_RE.sub("", value)
    if "{" in without or "}" in without:
        raise WorkflowError(f"{label} contains an unresolved or ambiguous placeholder")
    return value


def _compile_machine_template(value: str) -> str:
    """Bind machine-local roots at validation/trust time, not from run-time env."""
    if "{temp}" not in value:
        return value
    trusted_temp = os.path.realpath(os.path.abspath(tempfile.gettempdir()))
    return value.replace("{temp}", trusted_temp)


def _ordinary_data_file(path: str, label: str) -> tuple[str, bytes, str]:
    absolute = os.path.abspath(os.path.expanduser(path))
    try:
        st = os.stat(absolute, follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise WorkflowError(f"{label} must be an ordinary local file, not a link")
        if st.st_size > MAX_MANIFEST_BYTES:
            raise WorkflowError(f"{label} exceeds 256 KiB")
        with open(absolute, "rb") as handle:
            raw = handle.read(MAX_MANIFEST_BYTES + 1)
    except OSError as exc:
        raise WorkflowError(f"{label} could not be read: {exc}") from exc
    return os.path.realpath(absolute), raw, hashlib.sha256(raw).hexdigest()


def _enum_values(values, label: str) -> list[str]:
    if not isinstance(values, list) or not values or len(values) > MAX_ENUM_VALUES:
        raise WorkflowError(f"{label} must contain 1-{MAX_ENUM_VALUES} strings")
    normalized = []
    for index, value in enumerate(values):
        if (not isinstance(value, str) or not value
                or len(value.encode("utf-8")) > MAX_PARAMETER_BYTES
                or any(ord(char) < 32 for char in value)):
            raise WorkflowError(f"{label}[{index}] must be a non-empty bounded string")
        normalized.append(value)
    if len(normalized) != len(set(normalized)):
        raise WorkflowError(f"{label} must contain unique values")
    return normalized


def _safe_regex(pattern, label: str) -> str:
    if (not isinstance(pattern, str) or not pattern or len(pattern) > 256
            or any(ord(char) < 32 for char in pattern)):
        raise WorkflowError(f"{label} must be a non-empty regex of at most 256 characters")
    # Runtime values are bounded, but reject constructs that can introduce
    # backtracking surprises or executable-style regex extensions. Character
    # classes, alternation, anchors, and ordinary quantifiers remain available.
    if any(char in pattern for char in "()") or re.search(r"\\[1-9gk]", pattern):
        raise WorkflowError(f"{label} uses unsupported grouping or backreferences")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise WorkflowError(f"{label} is invalid: {exc}") from exc
    return pattern


def _validate_parameters(value, manifest_path: str) -> dict:
    if not isinstance(value, dict) or not value or len(value) > MAX_PARAMETERS:
        raise WorkflowError(f"parameters must contain 1-{MAX_PARAMETERS} named definitions")
    normalized = {}
    manifest_dir = os.path.dirname(os.path.abspath(manifest_path))
    for name, spec in value.items():
        label = f"parameters.{name}"
        if not isinstance(name, str) or not _PARAMETER_RE.fullmatch(name):
            raise WorkflowError(
                "parameter names must start with a lowercase letter and contain "
                "only lowercase letters, digits, '_' or '-'"
            )
        if not isinstance(spec, dict):
            raise WorkflowError(f"{label} must be an object")
        kind = spec.get("type")
        if kind == "enum":
            _exact_keys(spec, {"type", "values"}, label)
            normalized[name] = {
                "type": "enum", "values": _enum_values(spec.get("values"), f"{label}.values")
            }
        elif kind == "enum-file":
            _exact_keys(spec, {"type", "source", "source_sha256", "format"}, label)
            source = spec.get("source")
            if (not isinstance(source, str) or not source
                    or any(char in source for char in "*?[]{}")):
                raise WorkflowError(f"{label}.source must be one literal file path")
            source_path = source if os.path.isabs(source) else os.path.join(manifest_dir, source)
            resolved, raw, actual = _ordinary_data_file(source_path, f"{label}.source")
            wanted = str(spec.get("source_sha256") or "").lower()
            if not _HASH_RE.fullmatch(wanted):
                raise WorkflowError(f"{label}.source_sha256 must be a SHA-256")
            if not hmac.compare_digest(wanted, actual):
                raise WorkflowConflict(
                    f"{label} source hash does not match the manifest",
                    {"source": resolved, "expected": wanted, "actual": actual},
                )
            file_format = spec.get("format", "lines")
            if file_format == "lines":
                try:
                    text = raw.decode("utf-8-sig")
                except UnicodeError as exc:
                    raise WorkflowError(f"{label}.source must be UTF-8") from exc
                values = [line.strip() for line in text.splitlines()
                          if line.strip() and not line.lstrip().startswith("#")]
            elif file_format == "json-array":
                try:
                    values = json.loads(raw.decode("utf-8-sig"))
                except (UnicodeError, json.JSONDecodeError) as exc:
                    raise WorkflowError(f"{label}.source must be a UTF-8 JSON array") from exc
            else:
                raise WorkflowError(f"{label}.format must be lines or json-array")
            normalized[name] = {
                "type": "enum", "values": _enum_values(values, f"{label}.source"),
                "source": resolved, "source_sha256": actual, "format": file_format,
            }
        elif kind == "regex":
            _exact_keys(spec, {"type", "pattern"}, label)
            normalized[name] = {
                "type": "regex", "pattern": _safe_regex(spec.get("pattern"), f"{label}.pattern")
            }
        elif kind == "integer":
            _exact_keys(spec, {"type", "minimum", "maximum"}, label)
            minimum, maximum = spec.get("minimum"), spec.get("maximum")
            if (not isinstance(minimum, int) or isinstance(minimum, bool)
                    or not isinstance(maximum, int) or isinstance(maximum, bool)
                    or minimum > maximum):
                raise WorkflowError(f"{label} requires integer minimum <= maximum")
            normalized[name] = {
                "type": "integer", "minimum": minimum, "maximum": maximum,
            }
        elif kind == "path":
            _exact_keys(spec, {"type", "root", "must_exist", "kind"}, label)
            root = _validate_template(
                spec.get("root"), f"{label}.root", allow_args=False,
                allow_parameters=False,
            )
            root = _compile_machine_template(root)
            must_exist = spec.get("must_exist", True)
            path_kind = spec.get("kind", "any")
            if not isinstance(must_exist, bool):
                raise WorkflowError(f"{label}.must_exist must be true or false")
            if path_kind not in {"any", "file", "directory"}:
                raise WorkflowError(f"{label}.kind must be any, file, or directory")
            normalized[name] = {
                "type": "path", "root": root, "must_exist": must_exist,
                "kind": path_kind,
            }
        else:
            raise WorkflowError(
                f"{label}.type must be enum, enum-file, regex, integer, or path"
            )
    return normalized


def _ordinary_script(path: str) -> str:
    absolute = os.path.abspath(os.path.expanduser(path))
    try:
        st = os.stat(absolute, follow_symlinks=False)
    except OSError as exc:
        raise WorkflowError(f"workflow script could not be read: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise WorkflowError("workflow script must be an ordinary local file, not a link")
    return os.path.realpath(absolute)


def validate_manifest(value: dict, manifest_path: str) -> dict:
    """Validate and normalize a source manifest without granting it trust."""
    schema = value.get("schema")
    if schema not in MANIFEST_SCHEMAS:
        raise WorkflowError(
            f"workflow schema must be one of {', '.join(sorted(MANIFEST_SCHEMAS))}"
        )
    manifest_keys = {
        "schema", "id", "description", "command", "allowed_roots", "outputs",
        "observed_roots",
    }
    if schema == PARAMETERIZED_SCHEMA:
        manifest_keys.add("parameters")
    _exact_keys(
        value, manifest_keys, "workflow manifest",
    )
    workflow_id = value.get("id")
    if not isinstance(workflow_id, str) or not _ID_RE.fullmatch(workflow_id):
        raise WorkflowError("workflow id must be 1-128 lowercase letters, digits, '.', '_' or '-'")
    description = value.get("description", "")
    if not isinstance(description, str) or len(description) > 500:
        raise WorkflowError("workflow description must be a string of at most 500 characters")

    command = value.get("command")
    if not isinstance(command, dict):
        raise WorkflowError("workflow command must be an object")
    command_keys = {"runtime", "script", "script_sha256"}
    if schema in {MANIFEST_SCHEMA, PARAMETERIZED_SCHEMA}:
        command_keys.add("args")
    _exact_keys(command, command_keys, "workflow command")
    runtime = command.get("runtime")
    if runtime not in {"python", "node", "powershell"}:
        raise WorkflowError("workflow runtime must be python, node, or powershell")
    script_value = command.get("script")
    if not isinstance(script_value, str) or not script_value or "\x00" in script_value:
        raise WorkflowError("workflow command.script must be a literal path")
    if any(char in script_value for char in "*?[]{}"):
        raise WorkflowError("workflow command.script must not contain wildcards or placeholders")
    script_path = script_value if os.path.isabs(script_value) else os.path.join(
        os.path.dirname(os.path.abspath(manifest_path)), script_value
    )
    script_path = _ordinary_script(script_path)
    wanted_script_hash = str(command.get("script_sha256") or "").lower()
    if not _HASH_RE.fullmatch(wanted_script_hash):
        raise WorkflowError("workflow command.script_sha256 must be a SHA-256")
    actual_script_hash = store.file_sha256(script_path)
    if not hmac.compare_digest(wanted_script_hash, actual_script_hash):
        raise WorkflowConflict(
            "workflow script hash does not match the manifest",
            {"script": script_path, "expected": wanted_script_hash,
             "actual": actual_script_hash},
        )
    parameters = _validate_parameters(value.get("parameters"), manifest_path) \
        if schema == PARAMETERIZED_SCHEMA else {}
    bound_args = command.get("args", [])
    if schema in {MANIFEST_SCHEMA, PARAMETERIZED_SCHEMA}:
        if not isinstance(bound_args, list) or len(bound_args) > MAX_ARGS:
            raise WorkflowError(f"workflow command.args must contain at most {MAX_ARGS} entries")
        normalized_args = []
        referenced_parameters = set()
        for index, arg in enumerate(bound_args):
            if isinstance(arg, str):
                if "\x00" in arg or any(ord(char) < 32 for char in arg):
                    raise WorkflowError(
                        f"workflow command.args[{index}] contains control characters"
                    )
                normalized_args.append(arg)
                continue
            if schema != PARAMETERIZED_SCHEMA or not isinstance(arg, dict):
                raise WorkflowError(
                    f"workflow command.args[{index}] must be a literal string"
                )
            _exact_keys(arg, {"parameter"}, f"workflow command.args[{index}]")
            name = arg.get("parameter")
            if name not in parameters:
                raise WorkflowError(
                    f"workflow command.args[{index}] references unknown parameter {name!r}"
                )
            normalized_args.append({"parameter": name})
            referenced_parameters.add(name)
        if schema == PARAMETERIZED_SCHEMA:
            unused = sorted(set(parameters) - referenced_parameters)
            if unused:
                raise WorkflowError(
                    "workflow parameters are not used by command.args: " + ", ".join(unused)
                )
        encoded_size = sum(
            len(arg.encode("utf-8")) if isinstance(arg, str)
            else len(arg["parameter"].encode("utf-8"))
            for arg in normalized_args
        )
        if encoded_size > MAX_ARG_BYTES:
            raise WorkflowError("workflow command.args exceeds the 16 KiB limit")
        bound_args = normalized_args

    roots = value.get("allowed_roots")
    if not isinstance(roots, list) or not roots or len(roots) > MAX_ROOTS:
        raise WorkflowError(f"allowed_roots must contain 1-{MAX_ROOTS} path templates")
    normalized_roots = [
        _compile_machine_template(
            _validate_template(
                item, f"allowed_roots[{index}]", allow_args=False,
                allow_parameters=False,
            )
        )
        for index, item in enumerate(roots)
    ]
    if len(normalized_roots) != len(set(normalized_roots)):
        raise WorkflowError("allowed_roots must be unique")

    outputs = value.get("outputs")
    if not isinstance(outputs, list) or not outputs or len(outputs) > MAX_OUTPUTS:
        raise WorkflowError(f"outputs must contain 1-{MAX_OUTPUTS} exact output objects")
    normalized_outputs = []
    for index, item in enumerate(outputs):
        if not isinstance(item, dict):
            raise WorkflowError(f"outputs[{index}] must be an object")
        output_keys = {"path", "expected"}
        if schema == PARAMETERIZED_SCHEMA:
            output_keys.add("optional")
        _exact_keys(item, output_keys, f"outputs[{index}]")
        path_template = _compile_machine_template(
            _validate_template(item.get("path"), f"outputs[{index}].path")
        )
        literal_path = _PLACEHOLDER_RE.sub("", path_template)
        wildcard_positions = [
            position for position, char in enumerate(literal_path)
            if char in "*?["
        ]
        if wildcard_positions:
            found = "".join(literal_path[position] for position in wildcard_positions)
            raise WorkflowError(
                f"outputs[{index}].path must resolve to one exact file; "
                f"wildcard {found!r} found at position(s) "
                + ", ".join(str(position) for position in wildcard_positions),
                {
                    "field": f"outputs[{index}].path",
                    "path": path_template,
                    "wildcard": found,
                    "positions": wildcard_positions,
                },
            )
        expected = _validate_template(
            item.get("expected", "any"), f"outputs[{index}].expected"
        )
        optional = item.get("optional", False)
        if not isinstance(optional, bool):
            raise WorkflowError(f"outputs[{index}].optional must be true or false")
        normalized_outputs.append({
            "path": path_template, "expected": expected,
            **({"optional": optional} if schema == PARAMETERIZED_SCHEMA else {}),
        })

    observed = value.get("observed_roots", [])
    if not isinstance(observed, list) or len(observed) > MAX_ROOTS:
        raise WorkflowError(f"observed_roots must contain at most {MAX_ROOTS} objects")
    normalized_observed = []
    pattern_count = 0
    for index, item in enumerate(observed):
        if not isinstance(item, dict):
            raise WorkflowError(f"observed_roots[{index}] must be an object")
        _exact_keys(item, {"path", "patterns"}, f"observed_roots[{index}]")
        root = _validate_template(
            item.get("path"), f"observed_roots[{index}].path", allow_args=False,
            allow_parameters=False,
        )
        root = _compile_machine_template(root)
        patterns = item.get("patterns", [])
        if not isinstance(patterns, list):
            raise WorkflowError(f"observed_roots[{index}].patterns must be an array")
        clean_patterns = []
        for pattern_index, pattern in enumerate(patterns):
            if not isinstance(pattern, str) or not pattern or len(pattern) > 512:
                raise WorkflowError(
                    f"observed_roots[{index}].patterns[{pattern_index}] is invalid"
                )
            normalized = pattern.replace("\\", "/")
            if (os.path.isabs(normalized) or "\x00" in normalized
                    or any(part == ".." for part in normalized.split("/"))):
                raise WorkflowError("observed output patterns must be relative and may not contain '..'")
            clean_patterns.append(normalized)
        pattern_count += len(clean_patterns)
        normalized_observed.append({"path": root, "patterns": clean_patterns})
    if pattern_count > MAX_PATTERNS:
        raise WorkflowError(f"workflow declares more than {MAX_PATTERNS} observed patterns")

    return {
        "schema": schema,
        "id": workflow_id,
        "description": description,
        "command": {
            "runtime": runtime,
            "script": script_path,
            "script_sha256": actual_script_hash,
            **({"args": list(bound_args)}
               if schema in {MANIFEST_SCHEMA, PARAMETERIZED_SCHEMA} else {}),
        },
        **({"parameters": parameters} if schema == PARAMETERIZED_SCHEMA else {}),
        "allowed_roots": normalized_roots,
        "outputs": normalized_outputs,
        "observed_roots": normalized_observed,
    }


def validate_manifest_file(path: str, expected_manifest_hash: str = "") -> dict:
    """Validate an inert manifest and its script identity without granting trust."""
    raw, actual = _load_json_file(path)
    wanted = str(expected_manifest_hash or "").strip().lower()
    if wanted:
        if not _HASH_RE.fullmatch(wanted):
            raise WorkflowError("--expected-manifest-hash must be a SHA-256")
        if not hmac.compare_digest(wanted, actual):
            raise WorkflowConflict(
                "workflow manifest hash does not match the expected version",
                {"expected": wanted, "actual": actual},
            )
    manifest = validate_manifest(raw, path)
    return {
        "ok": True,
        "valid": True,
        "workflow": manifest["id"],
        "schema": manifest["schema"],
        "manifest_sha256": actual,
        "script_sha256": manifest["command"]["script_sha256"],
        "arguments_bound": manifest["schema"] in {MANIFEST_SCHEMA, PARAMETERIZED_SCHEMA},
        "argument_count": len(manifest["command"].get("args", [])),
        "parameter_count": len(manifest.get("parameters", {})),
        "outputs": len(manifest["outputs"]),
        "observed_roots": len(manifest.get("observed_roots", [])),
        "manifest": manifest,
    }


def manifest_status(path: str) -> dict:
    """Report whether this machine trusts this exact manifest and script."""
    validated = validate_manifest_file(path)
    record_path = _record_path(validated["workflow"])
    if not os.path.lexists(record_path):
        return {
            **{key: validated[key] for key in (
                "workflow", "schema", "manifest_sha256", "script_sha256",
            )},
            "trusted": False,
            "status": "not_trusted_on_this_machine",
        }
    record = load_trusted(validated["workflow"])
    exact = (
        hmac.compare_digest(
            record.get("manifest_sha256", ""), validated["manifest_sha256"]
        )
        and record.get("manifest") == validated["manifest"]
    )
    return {
        **{key: validated[key] for key in (
            "workflow", "schema", "manifest_sha256", "script_sha256",
        )},
        "trusted": exact,
        "status": "trusted_exact" if exact else "trusted_record_differs",
    }


def initialize_manifest(
    script: str,
    manifest_path: str,
    *,
    workflow_id: str,
    runtime: str = "",
    args: Optional[list[str]] = None,
    outputs: Optional[list[str]] = None,
    expected: Optional[list[str]] = None,
    allowed_roots: Optional[list[str]] = None,
    description: str = "",
) -> dict:
    """Build and validate a v2 manifest; the caller owns guarded publication."""
    script_path = _ordinary_script(script)
    inferred = {".py": "python", ".js": "node", ".mjs": "node",
                ".cjs": "node", ".ps1": "powershell"}.get(
                    os.path.splitext(script_path)[1].lower(), ""
                )
    runtime = runtime or inferred
    if runtime not in {"python", "node", "powershell"}:
        raise WorkflowError("--runtime is required for an unrecognized script extension")
    outputs = list(outputs or [])
    roots = list(allowed_roots or [])
    if not outputs:
        raise WorkflowError("workflow init requires at least one --output")
    if not roots:
        raise WorkflowError("workflow init requires at least one --allowed-root")
    expected = list(expected or [])
    if expected and len(expected) != len(outputs):
        raise WorkflowError("repeat --expected once per --output, in the same order")
    if not expected:
        expected = ["any"] * len(outputs)
    manifest_dir = os.path.dirname(os.path.abspath(os.path.expanduser(manifest_path)))
    try:
        script_value = os.path.relpath(script_path, manifest_dir).replace("\\", "/")
    except ValueError:
        script_value = script_path
    manifest = _build_v2_manifest(
        workflow_id=workflow_id,
        description=description,
        runtime=runtime,
        script=script_value,
        script_sha256=store.file_sha256(script_path),
        args=list(args or []),
        outputs=outputs,
        expected_states=expected,
        allowed_roots=roots,
    )
    normalized = validate_manifest(manifest, manifest_path)
    return {"manifest": manifest, "normalized": normalized}


def _build_v2_manifest(
    *,
    workflow_id: str,
    description: str,
    runtime: str,
    script: str,
    script_sha256: str,
    args: list[str],
    outputs: list[str],
    expected_states: list[str],
    allowed_roots: list[str],
) -> dict:
    """Assemble a v2 manifest; validation remains the caller's responsibility."""
    return {
        "schema": MANIFEST_SCHEMA,
        "id": workflow_id,
        "description": description,
        "command": {
            "runtime": runtime,
            "script": script,
            "script_sha256": script_sha256,
            "args": list(args),
        },
        "allowed_roots": list(allowed_roots),
        "outputs": [
            {"path": path, "expected": expectation}
            for path, expectation in zip(outputs, expected_states)
        ],
        "observed_roots": [],
    }


def _explicit_string_list(value, label: str) -> list[str]:
    if not isinstance(value, (list, tuple)) or not value:
        raise WorkflowError(f"{label} must be an explicitly supplied non-empty array")
    return list(value)


def _validate_explicit_expected_states(states: list[str]) -> None:
    for index, state in enumerate(states):
        if not isinstance(state, str):
            raise WorkflowError(f"expected_states[{index}] must be a string")
        normalized = state.strip().lower()
        if normalized.startswith("sha256:"):
            normalized = normalized.split(":", 1)[1]
        if normalized not in {"any", "absent", "missing", "new", "present"} \
                and not _HASH_RE.fullmatch(normalized):
            raise WorkflowError(
                f"expected_states[{index}] must be any, absent, present, or a SHA-256"
            )


def build_workflow_proposal(
    command: list[str],
    cwd: str,
    *,
    workflow_id: str,
    outputs: list[str],
    allowed_roots: list[str],
    expected_states: list[str],
    description: str = "",
) -> dict:
    """Return an inert, validated v2 proposal for one exact command.

    This function performs read-only normalization and validation.  It never
    writes a manifest, creates a trusted record, or changes trust state.
    """
    working = os.path.realpath(os.path.abspath(os.path.expanduser(cwd or os.getcwd())))
    if not os.path.isdir(working):
        raise WorkflowError("workflow working directory does not exist")
    normalized = normalize_command(command, working)
    output_list = _explicit_string_list(outputs, "outputs")
    root_list = _explicit_string_list(allowed_roots, "allowed_roots")
    expected_list = _explicit_string_list(expected_states, "expected_states")
    if len(expected_list) != len(output_list):
        raise WorkflowError(
            "expected_states must contain exactly one entry per output, in the same order"
        )
    _validate_explicit_expected_states(expected_list)
    manifest = _build_v2_manifest(
        workflow_id=workflow_id,
        description=description,
        runtime=normalized["runtime"],
        script=normalized["script"],
        script_sha256=normalized["script_sha256"],
        args=normalized["args"],
        outputs=output_list,
        expected_states=expected_list,
        allowed_roots=root_list,
    )
    # An absolute script path keeps the proposal valid regardless of where a
    # caller later chooses to serialize it.  The synthetic path is never used
    # for I/O; validate_manifest only uses its directory for relative inputs.
    validate_manifest(manifest, os.path.join(working, ".agw-workflow-proposal.json"))
    return manifest


def _trust_dir() -> str:
    return os.path.join(store.agw_home(), "trusted-workflows")


def _ensure_trust_dir(*, create: bool) -> str:
    directory = _trust_dir()
    if os.path.lexists(directory):
        try:
            st = os.stat(directory, follow_symlinks=False)
        except OSError as exc:
            raise WorkflowTrustError(f"trusted workflow store could not be verified: {exc}") from exc
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise WorkflowTrustError("trusted workflow store must be an ordinary directory")
    elif create:
        os.makedirs(directory, mode=0o700, exist_ok=False)
    return directory


def _key_path() -> str:
    return os.path.join(store.agw_home(), "workflow-trust.key")


def _record_path(workflow_id: str) -> str:
    digest = hashlib.sha256(workflow_id.encode("utf-8")).hexdigest()
    return os.path.join(_trust_dir(), digest + ".json")


def _atomic_write(path: str, payload: bytes, mode: int = 0o600) -> None:
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, staged = tempfile.mkstemp(prefix=".agw-workflow-", dir=directory)
    try:
        try:
            os.fchmod(fd, mode)
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staged, path)
        try:
            os.chmod(path, mode)
        except OSError:
            pass
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(staged)
        except OSError:
            pass


def _write_trusted_record(path: str, record: dict) -> None:
    payload = _canonical_json(record) + b"\n"
    if len(payload) > MAX_RECORD_BYTES:
        raise WorkflowTrustError(
            "trusted workflow record exceeds its storage bound",
            {"bytes": len(payload), "maximum_bytes": MAX_RECORD_BYTES},
        )
    _atomic_write(path, payload)


def _trust_key(*, create: bool) -> bytes:
    path = _key_path()
    try:
        st = os.stat(path, follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise WorkflowTrustError("the workflow trust key is not an ordinary file")
        with open(path, "rb") as handle:
            key = handle.read(65)
    except FileNotFoundError:
        if not create:
            raise WorkflowTrustError("the workflow trust key is missing; trust the manifest again")
        key = secrets.token_bytes(32)
        _atomic_write(path, key)
    except OSError as exc:
        raise WorkflowTrustError(f"the workflow trust key could not be read: {exc}") from exc
    if len(key) != 32:
        raise WorkflowTrustError("the workflow trust key is invalid or was tampered with")
    return key


def _canonical_json(value: dict) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _contract_manifest(manifest: dict) -> dict:
    contract = copy.deepcopy(manifest)
    command = contract.get("command")
    if isinstance(command, dict):
        command.pop("script_sha256", None)
    return contract


def _contract_sha256(manifest: dict) -> str:
    return _sha256_bytes(_canonical_json(_contract_manifest(manifest)))


def _source_label(value: str, field: str) -> str:
    label = str(value or "unavailable").strip()
    if not label:
        label = "unavailable"
    if len(label.encode("utf-8")) > 256 or any(ord(char) < 32 for char in label):
        raise WorkflowError(f"{field} must be a short printable label")
    return label


def _seal(record: dict, key: bytes) -> str:
    unsigned = dict(record)
    unsigned.pop("seal", None)
    return hmac.new(key, _canonical_json(unsigned), hashlib.sha256).hexdigest()


def _decode_snapshot(payload: bytes, expected_sha256: str) -> bytes:
    if len(payload) > MAX_SCRIPT_SNAPSHOT_COMPRESSED_BYTES:
        raise WorkflowTrustError("workflow source snapshot exceeds its compressed bound")
    try:
        decoder = zlib.decompressobj()
        source = decoder.decompress(payload, MAX_SCRIPT_SNAPSHOT_BYTES + 1)
    except zlib.error as exc:
        raise WorkflowTrustError("workflow source snapshot is corrupt") from exc
    if (len(source) > MAX_SCRIPT_SNAPSHOT_BYTES or decoder.unconsumed_tail
            or not decoder.eof):
        raise WorkflowTrustError("workflow source snapshot exceeds its content bound")
    if not hmac.compare_digest(_sha256_bytes(source), expected_sha256):
        raise WorkflowTrustError("workflow source snapshot hash is invalid")
    try:
        source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WorkflowTrustError("workflow source snapshot is not UTF-8 text") from exc
    return source


def _read_snapshot_blob(metadata: dict) -> bytes:
    if not isinstance(metadata, dict) or metadata.get("available") is not True:
        raise WorkflowProvenanceError("the approved script snapshot is unavailable")
    content_hash = str(metadata.get("content_sha256") or "")
    blob_hash = str(metadata.get("blob_sha256") or "")
    if not _HASH_RE.fullmatch(content_hash) or not _HASH_RE.fullmatch(blob_hash):
        raise WorkflowTrustError("workflow source snapshot metadata is invalid")
    try:
        payload = base64.b64decode(
            str(metadata.get("payload_base64") or "").encode("ascii"), validate=True,
        )
    except (UnicodeError, ValueError, binascii.Error) as exc:
        raise WorkflowTrustError("workflow source snapshot encoding is invalid") from exc
    compressed_bytes = metadata.get("compressed_bytes")
    source_bytes = metadata.get("bytes")
    if (not isinstance(compressed_bytes, int) or isinstance(compressed_bytes, bool)
            or not isinstance(source_bytes, int) or isinstance(source_bytes, bool)
            or compressed_bytes < 0 or source_bytes < 0
            or compressed_bytes != len(payload)
            or source_bytes > MAX_SCRIPT_SNAPSHOT_BYTES):
        raise WorkflowTrustError("workflow source snapshot size metadata is invalid")
    if len(payload) > MAX_SCRIPT_SNAPSHOT_COMPRESSED_BYTES:
        raise WorkflowTrustError("workflow source snapshot exceeds its compressed bound")
    if not hmac.compare_digest(_sha256_bytes(payload), blob_hash):
        raise WorkflowTrustError("workflow source snapshot blob hash is invalid")
    source = _decode_snapshot(payload, content_hash)
    if len(source) != source_bytes:
        raise WorkflowTrustError("workflow source snapshot size binding is invalid")
    return source


def _capture_source_snapshot(script_path: str, expected_sha256: str) -> dict:
    try:
        st = os.stat(script_path, follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise WorkflowConflict("workflow script is no longer an ordinary file")
        if st.st_size > MAX_SCRIPT_SNAPSHOT_BYTES:
            return {
                "available": False, "reason": "script_too_large",
                "content_sha256": expected_sha256, "bytes": int(st.st_size),
            }
        with open(script_path, "rb") as handle:
            source = handle.read(MAX_SCRIPT_SNAPSHOT_BYTES + 1)
    except OSError as exc:
        raise WorkflowConflict(f"workflow script could not be snapshotted: {exc}") from exc
    if len(source) > MAX_SCRIPT_SNAPSHOT_BYTES:
        return {
            "available": False, "reason": "script_too_large",
            "content_sha256": expected_sha256, "bytes": len(source),
        }
    actual = _sha256_bytes(source)
    if not hmac.compare_digest(actual, expected_sha256):
        raise WorkflowConflict(
            "workflow script changed while its approved snapshot was captured",
            {"expected": expected_sha256, "actual": actual},
        )
    try:
        source.decode("utf-8")
    except UnicodeDecodeError:
        return {
            "available": False, "reason": "script_not_utf8",
            "content_sha256": expected_sha256, "bytes": len(source),
        }
    payload = zlib.compress(source, level=9)
    if len(payload) > MAX_SCRIPT_SNAPSHOT_COMPRESSED_BYTES:
        return {
            "available": False, "reason": "compressed_snapshot_too_large",
            "content_sha256": expected_sha256, "bytes": len(source),
        }
    blob_hash = _sha256_bytes(payload)
    metadata = {
        "available": True, "encoding": "utf-8", "compression": "zlib",
        "content_sha256": expected_sha256, "blob_sha256": blob_hash,
        "bytes": len(source), "compressed_bytes": len(payload),
        "payload_base64": base64.b64encode(payload).decode("ascii"),
    }
    if _read_snapshot_blob(metadata) != source:
        raise WorkflowTrustError("workflow source snapshot failed verification")
    return metadata


def _build_provenance(manifest_path: str, manifest_file_sha256: str,
                      manifest: dict, *, source_name: str = "",
                      source_version: str = "", approved_at: str = "",
                      snapshot: Optional[dict] = None) -> dict:
    approved_at = approved_at or datetime.now(timezone.utc).isoformat()
    script_path = manifest["command"]["script"]
    script_sha256 = manifest["command"]["script_sha256"]
    if snapshot is None:
        snapshot = _capture_source_snapshot(script_path, script_sha256)
    return {
        "source_manifest_path": os.path.realpath(os.path.abspath(
            os.path.expanduser(manifest_path)
        )),
        "source_manifest_sha256": manifest_file_sha256,
        "effective_manifest_sha256": manifest_file_sha256,
        "contract_sha256": _contract_sha256(manifest),
        "script_path": script_path,
        "script_sha256": script_sha256,
        "source": {
            "name": _source_label(source_name, "source name"),
            "version": _source_label(source_version, "source version"),
            "attested": False,
        },
        "approval": {
            "approved_at": approved_at,
            "identity": "local-user-confirmation",
            "identity_attested": False,
            "method": "explicit-cli-approval",
        },
        "script_snapshot": snapshot,
    }


def _validate_provenance(record: dict) -> None:
    provenance = record.get("provenance")
    if not isinstance(provenance, dict):
        raise WorkflowTrustError("trusted workflow provenance is missing")
    manifest = record["manifest"]
    path = provenance.get("source_manifest_path")
    if not isinstance(path, str) or not path or not os.path.isabs(path):
        raise WorkflowTrustError("trusted workflow manifest provenance path is invalid")
    for field in (
            "source_manifest_sha256", "effective_manifest_sha256",
            "contract_sha256", "script_sha256"):
        if not _HASH_RE.fullmatch(str(provenance.get(field) or "")):
            raise WorkflowTrustError(f"trusted workflow provenance {field} is invalid")
    if not hmac.compare_digest(
            provenance["contract_sha256"], _contract_sha256(manifest)):
        raise WorkflowTrustError("trusted workflow contract provenance is invalid")
    if provenance.get("script_path") != manifest["command"]["script"] or not hmac.compare_digest(
            provenance["script_sha256"], manifest["command"]["script_sha256"]):
        raise WorkflowTrustError("trusted workflow script provenance is invalid")
    approval = provenance.get("approval")
    if not isinstance(approval, dict) or not isinstance(approval.get("approved_at"), str):
        raise WorkflowTrustError("trusted workflow approval provenance is invalid")
    source = provenance.get("source")
    if (not isinstance(source, dict)
            or not isinstance(source.get("name"), str)
            or not isinstance(source.get("version"), str)
            or source.get("attested") is not False):
        raise WorkflowTrustError("trusted workflow source provenance is invalid")
    snapshot = provenance.get("script_snapshot")
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("available"), bool):
        raise WorkflowTrustError("trusted workflow source snapshot metadata is invalid")
    if not hmac.compare_digest(
            str(snapshot.get("content_sha256") or ""), provenance["script_sha256"]):
        raise WorkflowTrustError("trusted workflow source snapshot binding is invalid")


def trust_manifest(path: str, expected_manifest_hash: str, *, replace: bool = False,
                   source_name: str = "", source_version: str = "",
                   phase_callback=None) -> dict:
    """Explicitly trust one hash-checked manifest and its current script."""
    started = time.monotonic()
    phases = []

    def phase(name):
        item = {"phase": name, "elapsed_seconds": round(time.monotonic() - started, 3)}
        phases.append(item)
        if phase_callback:
            phase_callback(item)

    phase("acquiring_lock")
    with store.Lock("workflow-trust", timeout=10.0):
        result = _trust_manifest_locked(
            path, expected_manifest_hash, replace=replace,
            source_name=source_name, source_version=source_version,
            phase_callback=phase,
        )
    phase("complete")
    result["phases"] = phases
    return result


def _trust_manifest_locked(path: str, expected_manifest_hash: str,
                           *, replace: bool = False, source_name: str = "",
                           source_version: str = "", phase_callback=None) -> dict:
    wanted = str(expected_manifest_hash or "").strip().lower()
    if not _HASH_RE.fullmatch(wanted):
        raise WorkflowError("--expected-manifest-hash must be a SHA-256")
    if phase_callback:
        phase_callback("reading_manifest")
    raw, actual = _load_json_file(path)
    if not hmac.compare_digest(wanted, actual):
        raise WorkflowConflict(
            "workflow manifest hash does not match the expected version",
            {"expected": wanted, "actual": actual},
        )
    if phase_callback:
        phase_callback("hashing_script_and_validating_contract")
    manifest = validate_manifest(raw, path)
    trust_dir = _ensure_trust_dir(create=True)
    existing_records = [name for name in os.listdir(trust_dir) if name.endswith(".json")]
    record_path = _record_path(manifest["id"])
    key = _trust_key(create=True)
    existing = None
    migrate_legacy = False
    if os.path.exists(record_path):
        existing = load_trusted(manifest["id"])
        if (existing.get("manifest_sha256") == actual
                and existing.get("manifest") == manifest):
            if existing.get("schema") == RECORD_SCHEMA and not replace:
                return {
                    "ok": True, "changed": False, "workflow": manifest["id"],
                    "manifest_sha256": actual,
                    "script_sha256": manifest["command"]["script_sha256"],
                    "provenance": existing["provenance"],
                }
            migrate_legacy = existing.get("schema") == RECORD_SCHEMA_V1
        if not replace:
            if not migrate_legacy:
                raise WorkflowConflict(
                    "a different trusted record already exists; review it and repeat with --replace",
                    {"workflow": manifest["id"]},
                )
    elif len(existing_records) >= MAX_WORKFLOWS:
        raise WorkflowError(f"trusted workflow store is limited to {MAX_WORKFLOWS} records")
    trusted_at = (
        str(existing.get("trusted_at") or "")
        if migrate_legacy and existing else ""
    ) or datetime.now(timezone.utc).isoformat()
    provenance = _build_provenance(
        path, actual, manifest, source_name=source_name,
        source_version=source_version, approved_at=trusted_at,
    )
    record = {
        "schema": RECORD_SCHEMA,
        "manifest_sha256": actual,
        "trusted_at": trusted_at,
        "manifest": manifest,
        "provenance": provenance,
    }
    record["seal"] = _seal(record, key)
    if phase_callback:
        phase_callback("writing_record")
    _write_trusted_record(record_path, record)
    return {
        "ok": True, "changed": True, "migrated": migrate_legacy,
        "workflow": manifest["id"],
        "manifest_sha256": actual, "script": manifest["command"]["script"],
        "script_sha256": manifest["command"]["script_sha256"],
        "provenance": provenance,
    }


def load_trusted(workflow_id: str) -> dict:
    if not isinstance(workflow_id, str) or not _ID_RE.fullmatch(workflow_id):
        raise WorkflowError("workflow id is invalid")
    _ensure_trust_dir(create=False)
    path = _record_path(workflow_id)
    try:
        st = os.stat(path, follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise WorkflowTrustError("trusted workflow record is not an ordinary file")
        if st.st_size > MAX_RECORD_BYTES:
            raise WorkflowTrustError("trusted workflow record is too large")
        with open(path, "rb") as handle:
            raw = handle.read(MAX_RECORD_BYTES + 1)
        record = json.loads(raw.decode("utf-8"), object_pairs_hook=_json_no_duplicates)
    except FileNotFoundError as exc:
        raise WorkflowTrustError(
            f"workflow {workflow_id!r} is not trusted; use `agw workflow trust --help`"
        ) from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WorkflowTrustError(f"trusted workflow record could not be verified: {exc}") from exc
    if not isinstance(record, dict) or record.get("schema") not in RECORD_SCHEMAS:
        raise WorkflowTrustError("trusted workflow record has an invalid schema")
    manifest = record.get("manifest")
    if not isinstance(manifest, dict) or manifest.get("id") != workflow_id:
        raise WorkflowTrustError("trusted workflow record identity is invalid")
    seal = record.get("seal")
    if not isinstance(seal, str) or not _HASH_RE.fullmatch(seal):
        raise WorkflowTrustError("trusted workflow record has no valid authentication seal")
    expected = _seal(record, _trust_key(create=False))
    if not hmac.compare_digest(seal, expected):
        raise WorkflowTrustError("trusted workflow record was tampered with")
    if record.get("schema") == RECORD_SCHEMA:
        _validate_provenance(record)
    return record


def list_trusted() -> list[dict]:
    directory = _ensure_trust_dir(create=False)
    if not os.path.isdir(directory):
        return []
    names = sorted(name for name in os.listdir(directory) if name.endswith(".json"))
    if len(names) > MAX_WORKFLOWS:
        raise WorkflowTrustError("trusted workflow store exceeds its record limit")
    result = []
    for name in names:
        path = os.path.join(directory, name)
        try:
            st = os.stat(path, follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) \
                    or st.st_size > MAX_RECORD_BYTES:
                raise WorkflowTrustError("record verification failed")
            with open(path, "rb") as handle:
                candidate = json.loads(handle.read(MAX_RECORD_BYTES + 1).decode("utf-8"))
            workflow_id = candidate.get("manifest", {}).get("id", "")
            record = load_trusted(workflow_id)
            manifest = record["manifest"]
            result.append({
                "id": workflow_id, "description": manifest.get("description", ""),
                "runtime": manifest["command"]["runtime"],
                "script": manifest["command"]["script"], "verified": True,
                "provenance_available": record.get("schema") == RECORD_SCHEMA,
            })
        except (OSError, ValueError, TypeError, WorkflowError):
            result.append({"record": name, "verified": False, "error": "record verification failed"})
    return result


def export_trusted(workflow_id: str) -> dict:
    """Return a deterministic inert manifest for a trusted workflow."""
    record = load_trusted(workflow_id)
    manifest = record["manifest"]
    payload = _canonical_json(manifest)
    provenance = record.get("provenance") if record.get("schema") == RECORD_SCHEMA else None
    return {
        "ok": True,
        "workflow": workflow_id,
        "schema": manifest["schema"],
        "manifest": manifest,
        "content": payload.decode("utf-8"),
        "manifest_sha256": _sha256_bytes(payload),
        "provenance_available": provenance is not None,
        "source_manifest_path": (
            provenance.get("source_manifest_path", "") if provenance else ""
        ),
        "legacy_reconstruction": provenance is None,
    }


def _refresh_source(record: dict) -> dict:
    if record.get("schema") != RECORD_SCHEMA:
        raise WorkflowProvenanceError(
            "this legacy workflow has no canonical manifest provenance; export and trust it once before refresh",
            {"reason_code": "workflow_provenance_missing"},
        )
    provenance = record["provenance"]
    manifest_path = provenance["source_manifest_path"]
    raw, source_manifest_sha256 = _load_json_file(manifest_path)
    if raw.get("id") != record["manifest"].get("id"):
        raise WorkflowProvenanceError(
            "the canonical manifest no longer identifies this workflow",
            {"reason_code": "workflow_manifest_identity_changed"},
        )
    command = raw.get("command")
    if not isinstance(command, dict):
        raise WorkflowError("the canonical workflow manifest has no command object")
    script_value = command.get("script")
    if not isinstance(script_value, str) or not script_value:
        raise WorkflowError("the canonical workflow manifest has no literal script path")
    script_path = script_value if os.path.isabs(script_value) else os.path.join(
        os.path.dirname(os.path.abspath(manifest_path)), script_value
    )
    script_path = _ordinary_script(script_path)
    script_sha256 = store.file_sha256(script_path)
    candidate_raw = copy.deepcopy(raw)
    candidate_raw["command"]["script_sha256"] = script_sha256
    candidate = validate_manifest(candidate_raw, manifest_path)
    candidate_manifest_sha256 = _sha256_bytes(_canonical_json(candidate))
    before_contract = _contract_manifest(record["manifest"])
    after_contract = _contract_manifest(candidate)
    return {
        "manifest_path": manifest_path,
        "source_manifest_sha256": source_manifest_sha256,
        "source_declared_script_sha256": str(command.get("script_sha256") or "").lower(),
        "script_path": script_path,
        "script_sha256": script_sha256,
        "candidate_manifest_sha256": candidate_manifest_sha256,
        "candidate": candidate,
        "contract_sha256": _contract_sha256(candidate),
        "contract_changed": before_contract != after_contract,
        "contract_changed_fields": _changed_fields(before_contract, after_contract),
    }


def _changed_fields(before, after, prefix: str = "") -> list[str]:
    changed = []
    if type(before) is not type(after):
        return [prefix or "/"]
    if isinstance(before, dict):
        for key in sorted(set(before) | set(after)):
            child = (prefix + "/" + str(key).replace("~", "~0").replace("/", "~1"))
            if key not in before or key not in after:
                changed.append(child)
            else:
                changed.extend(_changed_fields(before[key], after[key], child))
            if len(changed) >= 128:
                return changed[:128]
        return changed
    if isinstance(before, list):
        if before != after:
            return [prefix or "/"]
        return []
    return [prefix or "/"] if before != after else []


def _current_script_text(path: str, expected_sha256: str) -> tuple[Optional[str], str]:
    try:
        st = os.stat(path, follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            return None, "script_not_ordinary"
        if st.st_size > MAX_SCRIPT_SNAPSHOT_BYTES:
            return None, "script_too_large"
        with open(path, "rb") as handle:
            source = handle.read(MAX_SCRIPT_SNAPSHOT_BYTES + 1)
    except OSError as exc:
        raise WorkflowRefreshError(f"current workflow script could not be read: {exc}") from exc
    if len(source) > MAX_SCRIPT_SNAPSHOT_BYTES:
        return None, "script_too_large"
    actual = _sha256_bytes(source)
    if not hmac.compare_digest(actual, expected_sha256):
        raise WorkflowConflict(
            "workflow script changed while the refresh review was prepared",
            {"expected": expected_sha256, "actual": actual},
        )
    try:
        return source.decode("utf-8"), ""
    except UnicodeDecodeError:
        return None, "script_not_utf8"


def _script_diff(record: dict, current_path: str, current_sha256: str) -> dict:
    snapshot = record["provenance"].get("script_snapshot", {})
    if snapshot.get("available") is not True:
        return {
            "available": False,
            "reason": str(snapshot.get("reason") or "approved_snapshot_unavailable"),
            "truncated": False,
        }
    approved = _read_snapshot_blob(snapshot).decode("utf-8")
    current, reason = _current_script_text(current_path, current_sha256)
    if current is None:
        return {"available": False, "reason": reason, "truncated": False}
    lines = list(difflib.unified_diff(
        approved.splitlines(), current.splitlines(),
        fromfile="approved-script", tofile="current-script", lineterm="",
    ))
    truncated = len(lines) > MAX_REFRESH_DIFF_LINES
    lines = lines[:MAX_REFRESH_DIFF_LINES]
    diff = "\n".join(lines)
    encoded = diff.encode("utf-8")
    if len(encoded) > MAX_REFRESH_DIFF_BYTES:
        encoded = encoded[:MAX_REFRESH_DIFF_BYTES]
        while encoded:
            try:
                diff = encoded.decode("utf-8")
                break
            except UnicodeDecodeError:
                encoded = encoded[:-1]
        truncated = True
    return {
        "available": True, "diff": diff, "changed": approved != current,
        "truncated": truncated,
        "approved_sha256": snapshot["content_sha256"],
        "current_sha256": current_sha256,
    }


def _refresh_plan_hash(plan: dict) -> str:
    unsigned = dict(plan)
    unsigned.pop("plan_sha256", None)
    return _sha256_bytes(_canonical_json(unsigned))


def build_refresh_plan(workflow_id: str, *, now_ns: Optional[int] = None) -> dict:
    """Build a read-only, expiring review plan for one trusted workflow."""
    record = load_trusted(workflow_id)
    source = _refresh_source(record)
    now_ns = int(time.time_ns() if now_ns is None else now_ns)
    plan = {
        "schema": REFRESH_PLAN_SCHEMA,
        "workflow": workflow_id,
        "created_at_ns": now_ns,
        "expires_at_ns": now_ns + REFRESH_PLAN_TTL_NS,
        "trusted_record": {
            "seal": record["seal"],
            "manifest_sha256": record["manifest_sha256"],
            "script_sha256": record["manifest"]["command"]["script_sha256"],
            "contract_sha256": _contract_sha256(record["manifest"]),
        },
        "candidate": {
            "source_manifest_path": source["manifest_path"],
            "source_manifest_sha256": source["source_manifest_sha256"],
            "source_declared_script_sha256": source["source_declared_script_sha256"],
            "manifest_sha256": source["candidate_manifest_sha256"],
            "script_path": source["script_path"],
            "script_sha256": source["script_sha256"],
            "contract_sha256": source["contract_sha256"],
        },
        "contract_changed": source["contract_changed"],
        "contract_changed_fields": source["contract_changed_fields"],
        "script_diff": _script_diff(record, source["script_path"], source["script_sha256"]),
        "apply_allowed": not source["contract_changed"],
    }
    plan["plan_sha256"] = _refresh_plan_hash(plan)
    if len(_canonical_json(plan)) > MAX_REFRESH_PLAN_BYTES:
        raise WorkflowRefreshError("workflow refresh plan exceeds its bounded size")
    return plan


def load_refresh_plan(path: str) -> dict:
    source = os.path.abspath(os.path.expanduser(str(path or "")))
    try:
        st = os.stat(source, follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise WorkflowRefreshError("workflow refresh plan must be an ordinary file")
        if st.st_size > MAX_REFRESH_PLAN_BYTES:
            raise WorkflowRefreshError("workflow refresh plan exceeds its bounded size")
        with open(source, "rb") as handle:
            raw = handle.read(MAX_REFRESH_PLAN_BYTES + 1)
        plan = json.loads(raw.decode("utf-8"), object_pairs_hook=_json_no_duplicates)
    except WorkflowError as exc:
        raise WorkflowRefreshError(str(exc), getattr(exc, "details", None)) from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WorkflowRefreshError(f"workflow refresh plan could not be read: {exc}") from exc
    expected_keys = {
        "schema", "workflow", "created_at_ns", "expires_at_ns", "trusted_record",
        "candidate", "contract_changed", "contract_changed_fields", "script_diff",
        "apply_allowed", "plan_sha256",
    }
    if not isinstance(plan, dict) or set(plan) != expected_keys:
        raise WorkflowRefreshError("workflow refresh plan has an invalid schema")
    if plan.get("schema") != REFRESH_PLAN_SCHEMA:
        raise WorkflowRefreshError("workflow refresh plan schema is unsupported")
    if not isinstance(plan.get("workflow"), str) or not _ID_RE.fullmatch(plan["workflow"]):
        raise WorkflowRefreshError("workflow refresh plan identity is invalid")
    if (not isinstance(plan.get("created_at_ns"), int)
            or isinstance(plan.get("created_at_ns"), bool)
            or not isinstance(plan.get("expires_at_ns"), int)
            or isinstance(plan.get("expires_at_ns"), bool)
            or plan["created_at_ns"] < 0
            or plan["expires_at_ns"] <= plan["created_at_ns"]):
        raise WorkflowRefreshError("workflow refresh plan timestamps are invalid")
    if not isinstance(plan.get("contract_changed"), bool) \
            or not isinstance(plan.get("apply_allowed"), bool):
        raise WorkflowRefreshError("workflow refresh plan decision fields are invalid")
    if not isinstance(plan.get("contract_changed_fields"), list) \
            or len(plan["contract_changed_fields"]) > 128 \
            or not all(isinstance(value, str) and len(value) <= 512
                       for value in plan["contract_changed_fields"]):
        raise WorkflowRefreshError("workflow refresh plan contract diff is invalid")
    trusted = plan.get("trusted_record")
    candidate = plan.get("candidate")
    if not isinstance(trusted, dict) or set(trusted) != {
            "seal", "manifest_sha256", "script_sha256", "contract_sha256"}:
        raise WorkflowRefreshError("workflow refresh plan trusted binding is invalid")
    if not isinstance(candidate, dict) or set(candidate) != {
            "source_manifest_path", "source_manifest_sha256",
            "source_declared_script_sha256", "manifest_sha256", "script_path",
            "script_sha256", "contract_sha256"}:
        raise WorkflowRefreshError("workflow refresh plan candidate binding is invalid")
    for value in trusted.values():
        if not _HASH_RE.fullmatch(str(value or "")):
            raise WorkflowRefreshError("workflow refresh plan trusted hash is invalid")
    for field in (
            "source_manifest_sha256", "manifest_sha256", "script_sha256",
            "contract_sha256"):
        if not _HASH_RE.fullmatch(str(candidate.get(field) or "")):
            raise WorkflowRefreshError("workflow refresh plan candidate hash is invalid")
    for field in ("source_manifest_path", "script_path"):
        value = candidate.get(field)
        if not isinstance(value, str) or not value or not os.path.isabs(value):
            raise WorkflowRefreshError("workflow refresh plan candidate path is invalid")
    if not isinstance(candidate.get("source_declared_script_sha256"), str) \
            or len(candidate["source_declared_script_sha256"]) > 128:
        raise WorkflowRefreshError("workflow refresh plan declared script hash is invalid")
    if not isinstance(plan.get("script_diff"), dict):
        raise WorkflowRefreshError("workflow refresh plan script diff is invalid")
    plan_hash = str(plan.get("plan_sha256") or "")
    if not _HASH_RE.fullmatch(plan_hash) or not hmac.compare_digest(
            plan_hash, _refresh_plan_hash(plan)):
        raise WorkflowRefreshError("workflow refresh plan hash is invalid")
    return plan


def apply_refresh_plan(path: str, expected_plan_hash: str,
                       *, now_ns: Optional[int] = None) -> dict:
    """Atomically replace one trusted record after exact refresh review."""
    plan = load_refresh_plan(path)
    wanted = str(expected_plan_hash or "").strip().lower()
    if not _HASH_RE.fullmatch(wanted):
        raise WorkflowRefreshError("--expected-plan-hash must be a SHA-256")
    if not hmac.compare_digest(wanted, plan["plan_sha256"]):
        raise WorkflowConflict(
            "workflow refresh plan hash does not match the reviewed version",
            {"expected": wanted, "actual": plan["plan_sha256"]},
        )
    now_ns = int(time.time_ns() if now_ns is None else now_ns)
    if now_ns > int(plan["expires_at_ns"]):
        raise WorkflowRefreshError(
            "workflow refresh plan expired; create and review a new plan",
            {"reason_code": "workflow_refresh_plan_expired"},
        )
    if plan.get("contract_changed") or not plan.get("apply_allowed"):
        raise WorkflowRefreshError(
            "workflow contract changed; use full workflow trust replacement after review",
            {"reason_code": "workflow_contract_changed",
             "changed_fields": plan.get("contract_changed_fields", [])},
        )
    with store.Lock("workflow-trust", timeout=10.0):
        record = load_trusted(plan["workflow"])
        trusted = plan["trusted_record"]
        if not hmac.compare_digest(record["seal"], str(trusted.get("seal") or "")):
            raise WorkflowConflict(
                "trusted workflow changed after the refresh plan was created",
                {"reason_code": "workflow_trusted_record_changed"},
            )
        source = _refresh_source(record)
        candidate = plan["candidate"]
        comparisons = {
            "source_manifest_path": source["manifest_path"],
            "source_manifest_sha256": source["source_manifest_sha256"],
            "source_declared_script_sha256": source["source_declared_script_sha256"],
            "manifest_sha256": source["candidate_manifest_sha256"],
            "script_path": source["script_path"],
            "script_sha256": source["script_sha256"],
            "contract_sha256": source["contract_sha256"],
        }
        if candidate != comparisons:
            raise WorkflowConflict(
                "workflow source changed after the refresh plan was created",
                {"reason_code": "workflow_refresh_source_changed"},
            )
        if source["contract_changed"]:
            raise WorkflowRefreshError(
                "workflow contract changed; use full workflow trust replacement after review",
                {"reason_code": "workflow_contract_changed",
                 "changed_fields": source["contract_changed_fields"]},
            )
        snapshot = _capture_source_snapshot(source["script_path"], source["script_sha256"])
        prior = record["provenance"]
        source_meta = prior.get("source", {})
        provenance = _build_provenance(
            source["manifest_path"], source["source_manifest_sha256"], source["candidate"],
            source_name=source_meta.get("name", "unavailable"),
            source_version=source_meta.get("version", "unavailable"),
            approved_at=prior["approval"]["approved_at"], snapshot=snapshot,
        )
        provenance["effective_manifest_sha256"] = source["candidate_manifest_sha256"]
        refreshed_at = datetime.now(timezone.utc).isoformat()
        provenance["refresh"] = {
            "refreshed_at": refreshed_at,
            "identity": "local-user-confirmation",
            "identity_attested": False,
            "method": "hash-bound-refresh-plan",
            "plan_sha256": plan["plan_sha256"],
        }
        updated = {
            "schema": RECORD_SCHEMA,
            "manifest_sha256": source["candidate_manifest_sha256"],
            "trusted_at": record["trusted_at"],
            "refreshed_at": refreshed_at,
            "manifest": source["candidate"],
            "provenance": provenance,
        }
        updated["seal"] = _seal(updated, _trust_key(create=False))
        _write_trusted_record(_record_path(plan["workflow"]), updated)
        verified = load_trusted(plan["workflow"])
        if not hmac.compare_digest(verified["seal"], updated["seal"]):
            raise WorkflowTrustError("refreshed workflow record failed verification")
    return {
        "ok": True, "changed": True, "workflow": plan["workflow"],
        "plan_sha256": plan["plan_sha256"],
        "manifest_sha256": updated["manifest_sha256"],
        "script_sha256": updated["manifest"]["command"]["script_sha256"],
        "contract_sha256": provenance["contract_sha256"],
        "refreshed_at": refreshed_at,
    }


def _executable_name(value: str) -> str:
    name = str(value or "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def normalize_command(command: list[str], cwd: str) -> dict:
    """Normalize supported interpreter launch forms without invoking a shell."""
    if not command or any(not isinstance(item, str) or "\x00" in item for item in command):
        raise WorkflowError("workflow command must be a non-empty literal argument array")
    name = _executable_name(command[0])
    runtime = ""
    script_index = -1
    if _PYTHON_RE.fullmatch(name):
        runtime = "python"
        index = 1
        if name == "py" and index < len(command) and _PY_SELECTOR_RE.fullmatch(command[index]):
            index += 1
        while index < len(command):
            token = command[index]
            if token in {"-c", "-m"}:
                raise WorkflowError("trusted Python workflows require a script file, not -c or -m")
            if token in {"-X", "-W"}:
                index += 2
                continue
            if token in {"-B", "-E", "-I", "-O", "-OO", "-P", "-s", "-S", "-u", "-v", "-x"}:
                index += 1
                continue
            if token.startswith("-"):
                raise WorkflowError(f"unsupported Python launcher option: {token}")
            script_index = index
            break
    elif name in {"node", "nodejs"}:
        runtime = "node"
        for index, token in enumerate(command[1:], 1):
            if token in {"-e", "--eval", "-p", "--print"}:
                raise WorkflowError("trusted Node workflows require a script file, not eval")
            if token.startswith("-"):
                raise WorkflowError(f"unsupported Node launcher option: {token}")
            script_index = index
            break
    elif name in {"powershell", "pwsh"}:
        runtime = "powershell"
        index = 1
        while index < len(command):
            token = command[index]
            lowered = token.lower()
            if lowered in {"-command", "-c", "-encodedcommand", "-enc"}:
                raise WorkflowError("trusted PowerShell workflows require -File, not command text")
            if lowered in {"-noprofile", "-noninteractive"}:
                index += 1
                continue
            if lowered in {"-executionpolicy", "-ep"}:
                if index + 1 >= len(command):
                    raise WorkflowError("PowerShell -ExecutionPolicy is missing its value")
                index += 2
                continue
            if lowered in {"-file", "-f"}:
                if index + 1 >= len(command):
                    raise WorkflowError("PowerShell -File is missing its script")
                script_index = index + 1
                break
            if not token.startswith("-") and token.lower().endswith(".ps1"):
                script_index = index
                break
            raise WorkflowError(f"unsupported PowerShell launcher option: {token}")
    else:
        raise WorkflowError("trusted workflows support only Python, Node, and PowerShell scripts")
    if script_index < 0 or script_index >= len(command):
        raise WorkflowError("workflow command did not identify one script file")
    script_token = command[script_index]
    if any(char in script_token for char in "*?[]{}$`"):
        raise WorkflowError("workflow script path must be literal")
    script = script_token if os.path.isabs(script_token) else os.path.join(cwd, script_token)
    script = _ordinary_script(script)
    return {
        "runtime": runtime, "script": script,
        "script_sha256": store.file_sha256(script),
        "args": command[script_index + 1:],
    }


def command_for_manifest(manifest: dict, resolved_args: Optional[list[str]] = None) -> list[str]:
    """Build a shell-free launcher from one already-validated command contract."""
    command = manifest["command"]
    if manifest.get("schema") == MANIFEST_SCHEMA_V1:
        raise WorkflowError("manifest v1 requires an explicit command after --")
    runtime = command["runtime"]
    script = command["script"]
    if manifest.get("schema") == PARAMETERIZED_SCHEMA:
        if resolved_args is None:
            raise WorkflowError("parameterized workflow requires resolved parameters")
        args = list(resolved_args)
    else:
        args = list(command.get("args", []))
    if runtime == "python":
        return [sys.executable, script, *args]
    if runtime == "node":
        executable = shutil.which("node") or shutil.which("nodejs")
        if not executable:
            raise WorkflowError("the trusted Node runtime is not available")
        return [executable, script, *args]
    executable = shutil.which("pwsh") or shutil.which("powershell")
    if not executable:
        raise WorkflowError("the trusted PowerShell runtime is not available")
    return [executable, "-NoProfile", "-File", script, *args]


def _expand(template: str, context: dict, label: str) -> str:
    def replace(match):
        token = match.group(1)
        if token in {"cwd", "script_dir", "script_name", "script_stem", "temp"}:
            return context[token]
        parts = token.split(":")
        if parts[0] == "arg":
            index = int(parts[1])
            args = context["args"]
            if index >= len(args):
                raise WorkflowError(f"{label} references missing command argument {index}")
            value = args[index]
        else:
            name = parts[1]
            if name not in context.get("parameters", {}):
                raise WorkflowError(f"{label} references missing workflow parameter {name!r}")
            value = context["parameters"][name]
        if len(parts) == 3 and parts[2] == "basename":
            value = os.path.basename(value.rstrip("/\\"))
        elif len(parts) == 3 and parts[2] == "sha256":
            value = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return value
    expanded = _PLACEHOLDER_RE.sub(replace, template)
    if "{" in expanded or "}" in expanded:
        raise WorkflowError(f"{label} contains an unresolved placeholder")
    return expanded


def _path_within(path: str, root: str) -> bool:
    try:
        return os.path.normcase(os.path.commonpath([path, root])) == os.path.normcase(root)
    except ValueError:
        return False


def _resolved_path(template: str, context: dict, label: str) -> str:
    raw = _expand(template, context, label)
    if (not raw or any(ord(char) < 32 for char in raw)
            or any(char in raw for char in "*?[")):
        raise WorkflowError(f"{label} did not resolve to one literal path")
    value = raw if os.path.isabs(raw) else os.path.join(context["cwd"], raw)
    return os.path.realpath(os.path.abspath(os.path.expanduser(value)))


def _validate_runtime_parameter(name: str, value, spec: dict, context: dict) -> str:
    label = f"parameter {name!r}"
    if (not isinstance(value, str) or not value
            or len(value.encode("utf-8")) > MAX_PARAMETER_BYTES
            or any(ord(char) < 32 for char in value)):
        raise WorkflowError(f"{label} must be a non-empty bounded string")
    kind = spec["type"]
    if kind == "enum":
        if value not in spec["values"]:
            raise WorkflowTrustError(
                f"{label} is not an approved enum value",
                {"parameter": name, "allowed_count": len(spec["values"])},
            )
    elif kind == "regex":
        if re.fullmatch(spec["pattern"], value) is None:
            raise WorkflowTrustError(
                f"{label} does not match its reviewed pattern",
                {"parameter": name, "pattern": spec["pattern"]},
            )
    elif kind == "integer":
        if re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value) is None:
            raise WorkflowTrustError(f"{label} must be a canonical integer")
        number = int(value)
        if number < spec["minimum"] or number > spec["maximum"]:
            raise WorkflowTrustError(
                f"{label} is outside its reviewed range",
                {"parameter": name, "minimum": spec["minimum"],
                 "maximum": spec["maximum"]},
            )
    elif kind == "path":
        if any(char in value for char in "*?["):
            raise WorkflowTrustError(f"{label} must be one literal path")
        root = _resolved_path(spec["root"], context, f"parameters.{name}.root")
        candidate = value if os.path.isabs(value) else os.path.join(context["cwd"], value)
        candidate = os.path.realpath(os.path.abspath(os.path.expanduser(candidate)))
        if not _path_within(candidate, root):
            raise WorkflowTrustError(
                f"{label} resolves outside its reviewed root",
                {"parameter": name, "path": candidate, "root": root},
            )
        if spec["must_exist"] and not os.path.lexists(candidate):
            raise WorkflowTrustError(
                f"{label} does not exist", {"parameter": name, "path": candidate},
            )
        if os.path.lexists(candidate):
            if os.path.islink(candidate):
                raise WorkflowTrustError(f"{label} must not resolve to a link")
            if spec["kind"] == "file" and not os.path.isfile(candidate):
                raise WorkflowTrustError(f"{label} must resolve to a file")
            if spec["kind"] == "directory" and not os.path.isdir(candidate):
                raise WorkflowTrustError(f"{label} must resolve to a directory")
    else:  # authenticated records should never reach this branch
        raise WorkflowTrustError(f"{label} has an unsupported trusted type")
    return value


def _resolve_parameter_args(manifest: dict, supplied: dict, context: dict,
                            actual_args: Optional[list[str]] = None) -> tuple[list[str], dict]:
    definitions = manifest.get("parameters", {})
    if not isinstance(supplied, dict):
        raise WorkflowError("workflow parameters must be a name-to-string object")
    unknown = sorted(set(supplied) - set(definitions))
    if unknown:
        raise WorkflowTrustError("unknown workflow parameter(s): " + ", ".join(unknown))
    contract = manifest["command"].get("args", [])
    if actual_args is not None and len(actual_args) != len(contract):
        raise WorkflowTrustError(
            "command argument count does not match the parameterized workflow",
            {"expected_count": len(contract), "actual_count": len(actual_args)},
        )
    captured = dict(supplied)
    rendered = []
    for index, item in enumerate(contract):
        actual = actual_args[index] if actual_args is not None else None
        if isinstance(item, str):
            if actual_args is not None and actual != item:
                raise WorkflowTrustError(
                    f"command argument {index} does not match its reviewed literal"
                )
            rendered.append(item)
            continue
        name = item["parameter"]
        if actual_args is not None:
            if name in captured and captured[name] != actual:
                raise WorkflowTrustError(
                    f"command argument {index} conflicts with parameter {name!r}"
                )
            captured[name] = actual
        if name not in captured:
            raise WorkflowTrustError(f"missing required workflow parameter {name!r}")
        value = _validate_runtime_parameter(name, captured[name], definitions[name], context)
        captured[name] = value
        rendered.append(value)
    missing = sorted(set(definitions) - set(captured))
    if missing:
        raise WorkflowTrustError("missing workflow parameter(s): " + ", ".join(missing))
    return rendered, captured


def _expected_value(template: str, context: dict, path: str, label: str) -> str:
    value = _expand(template, context, label).strip().lower()
    if value in {"", "any"}:
        return ""
    if value in {"absent", "missing", "new"}:
        return "absent"
    if value == "present":
        if not os.path.isfile(path) or os.path.islink(path):
            raise WorkflowConflict("workflow expected an existing ordinary output", {"path": path})
        return store.file_sha256(path)
    if value.startswith("sha256:"):
        value = value.split(":", 1)[1]
    if not _HASH_RE.fullmatch(value):
        raise WorkflowError(f"{label} must resolve to any, absent, present, or a SHA-256")
    return value


def resolve_run(workflow_id: str, command: list[str], cwd: str,
                parameters: Optional[dict[str, str]] = None) -> dict:
    """Authenticate a trusted record and resolve exact run declarations."""
    working = os.path.realpath(os.path.abspath(os.path.expanduser(cwd or os.getcwd())))
    if not os.path.isdir(working):
        raise WorkflowError("workflow working directory does not exist")
    record = load_trusted(workflow_id)
    manifest = record["manifest"]
    bound = manifest["command"]
    supplied_parameters = dict(parameters or {})
    provided_command = bool(command)
    parameter_values = {}
    parameter_context = {
        "cwd": working,
        "script_dir": os.path.dirname(bound["script"]),
        "script_name": os.path.basename(bound["script"]),
        "script_stem": os.path.splitext(os.path.basename(bound["script"]))[0],
        "temp": os.path.realpath(os.path.abspath(tempfile.gettempdir())),
        "args": [], "parameters": {},
    }
    if manifest.get("schema") == PARAMETERIZED_SCHEMA and not command:
        rendered, parameter_values = _resolve_parameter_args(
            manifest, supplied_parameters, parameter_context,
        )
        command = command_for_manifest(manifest, rendered)
    elif supplied_parameters and manifest.get("schema") != PARAMETERIZED_SCHEMA:
        raise WorkflowTrustError("this trusted workflow does not accept parameters")
    if not command:
        command = command_for_manifest(manifest)
    normalized = normalize_command(command, working)
    if normalized["runtime"] != bound["runtime"]:
        raise WorkflowTrustError("command runtime does not match the trusted workflow")
    if os.path.normcase(normalized["script"]) != os.path.normcase(bound["script"]):
        raise WorkflowTrustError("command script path does not match the trusted workflow")
    if not hmac.compare_digest(normalized["script_sha256"], bound["script_sha256"]):
        raise WorkflowTrustError(
            "trusted script changed; review and trust a new manifest before running it",
            {"script": normalized["script"], "expected": bound["script_sha256"],
             "actual": normalized["script_sha256"]},
        )
    if manifest.get("schema") == PARAMETERIZED_SCHEMA and provided_command:
        parameter_context["args"] = normalized["args"]
        rendered, parameter_values = _resolve_parameter_args(
            manifest, supplied_parameters, parameter_context,
            actual_args=normalized["args"],
        )
        if rendered != normalized["args"]:  # defensive; binding already compares every slot
            raise WorkflowTrustError("command arguments do not match the parameterized workflow")
    elif manifest.get("schema") == MANIFEST_SCHEMA \
            and normalized["args"] != bound.get("args", []):
        raise WorkflowTrustError(
            "command arguments do not match the trusted workflow",
            {"expected_count": len(bound.get("args", [])),
             "actual_count": len(normalized["args"])},
        )
    context = {
        "cwd": working,
        "script_dir": os.path.dirname(normalized["script"]),
        "script_name": os.path.basename(normalized["script"]),
        "script_stem": os.path.splitext(os.path.basename(normalized["script"]))[0],
        "temp": os.path.realpath(os.path.abspath(tempfile.gettempdir())),
        "args": normalized["args"],
        "parameters": parameter_values,
    }
    roots = [
        _resolved_path(template, context, f"allowed_roots[{index}]")
        for index, template in enumerate(manifest["allowed_roots"])
    ]
    folded_roots = [os.path.normcase(path) for path in roots]
    if len(folded_roots) != len(set(folded_roots)):
        raise WorkflowError("allowed roots resolve ambiguously or to duplicates")
    for root in roots:
        if os.path.lexists(root) and not os.path.isdir(root):
            raise WorkflowTrustError("permitted output root is not a directory", {"path": root})
    outputs, expected, optional_outputs = [], [], []
    for index, item in enumerate(manifest["outputs"]):
        path = _resolved_path(item["path"], context, f"outputs[{index}].path")
        if os.path.isdir(path):
            raise WorkflowError(f"outputs[{index}] resolves to a directory")
        if not any(
                _path_within(path, root)
                and os.path.normcase(path) != os.path.normcase(root)
                for root in roots):
            raise WorkflowTrustError(
                "workflow output resolves outside its permitted roots", {"path": path}
            )
        outputs.append(path)
        optional_outputs.append(bool(item.get("optional", False)))
        expected.append(_expected_value(
            item["expected"], context, path, f"outputs[{index}].expected"
        ))
    folded_outputs = [os.path.normcase(path) for path in outputs]
    if len(folded_outputs) != len(set(folded_outputs)):
        raise WorkflowError("workflow outputs resolve ambiguously or to duplicates")

    observed_roots, patterns = [], []
    observed_specs = manifest.get("observed_roots", [])
    if len(observed_specs) > 1 and any(item.get("patterns") for item in observed_specs):
        raise WorkflowError(
            "observed patterns are ambiguous across multiple roots; use one root "
            "or declare exact sidecars"
        )
    for index, item in enumerate(observed_specs):
        root = _resolved_path(item["path"], context, f"observed_roots[{index}].path")
        if not any(_path_within(root, allowed) for allowed in roots):
            raise WorkflowTrustError("observed root resolves outside permitted roots", {"path": root})
        if root not in observed_roots:
            observed_roots.append(root)
        patterns.extend(item.get("patterns", []))
    return {
        "workflow": workflow_id, "command": command, "cwd": working,
        "outputs": outputs, "expected_hashes": expected,
        "optional_outputs": optional_outputs,
        "output_roots": observed_roots, "output_patterns": patterns,
        "manifest_sha256": record["manifest_sha256"],
        "script_sha256": normalized["script_sha256"],
        "parameters": parameter_values,
    }


def _diagnostic_reason(code: str, message: str, **details) -> dict:
    if code not in DIAGNOSTIC_REASON_CODES:
        raise ValueError(f"unsupported workflow diagnostic reason code: {code}")
    return {"code": code, "message": message, **details}


def _arguments_sha256(arguments: list) -> str:
    return hashlib.sha256(_canonical_json({"arguments": arguments})).hexdigest()


def _normalized_command_diagnostic(normalized: dict) -> dict:
    return {
        "runtime": normalized["runtime"],
        "script": normalized["script"],
        "script_sha256": normalized["script_sha256"],
        "argument_count": len(normalized["args"]),
        "arguments_sha256": _arguments_sha256(normalized["args"]),
        "argument_hashes": [
            {
                "index": index,
                "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
            }
            for index, value in enumerate(normalized["args"])
        ],
    }


def _candidate_metadata(manifest: dict) -> dict:
    command = manifest["command"]
    return {
        "id": manifest["id"],
        "schema": manifest["schema"],
        "verified": True,
        "runtime": command["runtime"],
        "script": command["script"],
        "script_sha256": command["script_sha256"],
        "argument_count": len(command.get("args", [])),
        "parameter_count": len(manifest.get("parameters", {})),
    }


def _parameter_constraint_metadata(spec: dict) -> dict:
    """Return useful parameter constraints without copying approved values."""
    kind = spec["type"]
    if kind == "enum":
        result = {"type": kind, "allowed_count": len(spec["values"])}
        if spec.get("source_sha256"):
            result["source_sha256"] = spec["source_sha256"]
        return result
    if kind == "regex":
        return {"type": kind, "pattern": spec["pattern"]}
    if kind == "integer":
        return {
            "type": kind, "minimum": spec["minimum"], "maximum": spec["maximum"],
        }
    return {
        "type": kind, "root": spec["root"],
        "must_exist": spec["must_exist"], "kind": spec["kind"],
    }


def _inferred_parameter_metadata(manifest: dict, values: dict) -> list[dict]:
    """Describe inferred values without placing their plaintext in a candidate."""
    contract = manifest["command"].get("args", [])
    result = []
    for name in sorted(values):
        source_indexes = [
            index for index, item in enumerate(contract)
            if isinstance(item, dict) and item.get("parameter") == name
        ]
        result.append({
            "name": name,
            "source_indexes": source_indexes,
            "constraints": _parameter_constraint_metadata(manifest["parameters"][name]),
            "value_sha256": hashlib.sha256(values[name].encode("utf-8")).hexdigest(),
        })
    return result


def _candidate_class(manifest: dict, normalized: Optional[dict],
                     reasons: list[dict]) -> str:
    if normalized is None:
        return "incompatible"
    if not reasons:
        return "parameterizable" \
            if manifest.get("schema") == PARAMETERIZED_SCHEMA else "exact"
    identity_codes = {
        "runtime_mismatch", "script_path_mismatch", "script_hash_mismatch",
    }
    if not any(reason["code"] in identity_codes for reason in reasons):
        return "near"
    return "incompatible"


def _resolved_identity(resolved: dict, cwd: str) -> dict:
    """Select the complete run identity that recommendation revalidation binds."""
    command = normalize_command(resolved["command"], cwd)
    return {
        "command": {
            "runtime": command["runtime"],
            "script": os.path.normcase(command["script"]),
            "script_sha256": command["script_sha256"],
            "args": command["args"],
        },
        "script_sha256": resolved["script_sha256"],
        "parameters": resolved["parameters"],
        "outputs": resolved["outputs"],
        "roots": resolved["output_roots"],
        "patterns": resolved["output_patterns"],
        "states": resolved["expected_hashes"],
        "optional_outputs": resolved["optional_outputs"],
    }


def _revalidated_recommendation(workflow_id: str, manifest: dict,
                                command: list[str], cwd: str) -> tuple[list[str], dict, str]:
    """Resolve twice around canonical reconstruction; never execute either argv."""
    try:
        first = resolve_run(workflow_id, command, cwd)
    except WorkflowError:
        return [], {}, "resolution_failed"
    if manifest.get("schema") == MANIFEST_SCHEMA_V1:
        return [], {}, "reconstruction_unavailable"
    try:
        second = resolve_run(
            workflow_id, [], cwd,
            parameters=first["parameters"] if manifest.get("schema") == PARAMETERIZED_SCHEMA
            else None,
        )
        if _resolved_identity(first, cwd) != _resolved_identity(second, cwd):
            return [], {}, "identity_changed"
    except WorkflowError:
        return [], {}, "revalidation_failed"
    return ["agw", "run", "--workflow", workflow_id, "--", *second["command"]], \
        first["parameters"], ""


def _candidate_mismatch_reasons(manifest: dict, normalized: dict, cwd: str) -> list[dict]:
    """Compare identities without echoing trusted argument or parameter values."""
    bound = manifest["command"]
    reasons = []
    if bound["runtime"] != normalized["runtime"]:
        reasons.append(_diagnostic_reason(
            "runtime_mismatch", "runtime does not match the trusted workflow",
            expected=bound["runtime"], actual=normalized["runtime"],
        ))
    if os.path.normcase(bound["script"]) != os.path.normcase(normalized["script"]):
        reasons.append(_diagnostic_reason(
            "script_path_mismatch", "script path does not match the trusted workflow",
            expected=bound["script"], actual=normalized["script"],
        ))
    if not hmac.compare_digest(bound["script_sha256"], normalized["script_sha256"]):
        reasons.append(_diagnostic_reason(
            "script_hash_mismatch", "script content does not match the trusted workflow",
            expected=bound["script_sha256"], actual=normalized["script_sha256"],
        ))
    if manifest.get("schema") == MANIFEST_SCHEMA \
            and bound.get("args", []) != normalized["args"]:
        reasons.append(_diagnostic_reason(
            "arguments_mismatch", "arguments do not match the trusted workflow",
            expected_count=len(bound.get("args", [])),
            actual_count=len(normalized["args"]),
            expected_sha256=_arguments_sha256(bound.get("args", [])),
            actual_sha256=_arguments_sha256(normalized["args"]),
        ))
    if manifest.get("schema") == PARAMETERIZED_SCHEMA:
        context = {
            "cwd": os.path.realpath(os.path.abspath(cwd or os.getcwd())),
            "script_dir": os.path.dirname(normalized["script"]),
            "script_name": os.path.basename(normalized["script"]),
            "script_stem": os.path.splitext(os.path.basename(normalized["script"]))[0],
            "temp": os.path.realpath(os.path.abspath(tempfile.gettempdir())),
            "args": normalized["args"], "parameters": {},
        }
        try:
            _resolve_parameter_args(
                manifest, {}, context, actual_args=normalized["args"],
            )
        except WorkflowError as exc:
            reasons.append(_diagnostic_reason(
                "parameters_mismatch",
                "arguments do not satisfy the trusted parameter contract",
                expected_count=len(bound.get("args", [])),
                actual_count=len(normalized["args"]),
                cause_code=exc.error_code,
            ))
    return reasons


def diagnose_matching_workflows(command: list[str], cwd: str) -> dict:
    """Explain how every trusted-store candidate compares with one command.

    Serialized normalized arguments are represented only by counts and hashes.  Candidate
    mismatch records use counts and hashes so diagnostics do not duplicate
    potentially confidential argument or parameter values.
    """
    normalized = None
    normalization_error = None
    try:
        normalized = normalize_command(command, cwd)
    except WorkflowError as exc:
        normalization_error = _diagnostic_reason(
            "command_normalization_failed", str(exc), cause_code=exc.error_code,
        )

    candidates = []
    matches = []
    for item in list_trusted():
        if not item.get("verified"):
            candidates.append({
                "record": item.get("record", ""),
                "verified": False,
                "matched": False,
                "candidate_class": "incompatible",
                "confidence": "none",
                "remaining_differences": ["unverified_record"],
                "remaining_difference_count": 1,
                "inferred_parameters": [],
                "mismatch_reasons": [_diagnostic_reason(
                    "unverified_record", "trusted workflow record could not be verified",
                )],
            })
            continue
        try:
            record = load_trusted(item["id"])
        except WorkflowError as exc:
            candidates.append({
                "id": item["id"],
                "verified": False,
                "matched": False,
                "candidate_class": "incompatible",
                "confidence": "none",
                "remaining_differences": ["invalid_record"],
                "remaining_difference_count": 1,
                "inferred_parameters": [],
                "mismatch_reasons": [_diagnostic_reason(
                    "invalid_record", "trusted workflow record failed verification",
                    cause_code=exc.error_code,
                )],
            })
            continue
        manifest = record["manifest"]
        candidate = _candidate_metadata(manifest)
        if normalized is None:
            reasons = [_diagnostic_reason(
                "command_normalization_failed",
                "candidate was not evaluated because the command could not be normalized",
            )]
        else:
            reasons = _candidate_mismatch_reasons(manifest, normalized, cwd)
        candidate["matched"] = not reasons
        candidate["mismatch_reasons"] = reasons
        candidate["candidate_class"] = _candidate_class(manifest, normalized, reasons)
        candidate["confidence"] = "medium" \
            if candidate["candidate_class"] == "near" else "none"
        candidate["remaining_differences"] = [reason["code"] for reason in reasons]
        candidate["remaining_difference_count"] = len(reasons)
        candidate["inferred_parameters"] = []
        candidate["_manifest"] = manifest
        candidates.append(candidate)
        if candidate["matched"]:
            matches.append(candidate["id"])

    revalidated = []
    if normalized is not None:
        for candidate in candidates:
            if candidate.get("candidate_class") not in {"exact", "parameterizable"}:
                continue
            argv, parameters, difference = _revalidated_recommendation(
                candidate["id"], candidate["_manifest"], command, cwd,
            )
            if difference:
                candidate["remaining_differences"].append(difference)
                candidate["remaining_difference_count"] += 1
                continue
            candidate["confidence"] = "high"
            if candidate["candidate_class"] == "parameterizable":
                candidate["inferred_parameters"] = _inferred_parameter_metadata(
                    candidate["_manifest"], parameters,
                )
            revalidated.append((candidate["id"], argv))

    candidates.sort(key=lambda candidate: (
        _DIAGNOSTIC_CLASS_ORDER[candidate["candidate_class"]],
        candidate["remaining_difference_count"],
        candidate.get("id", candidate.get("record", "")),
    ))
    for rank, candidate in enumerate(candidates, 1):
        candidate["rank"] = rank
        candidate["rank_key"] = [
            _DIAGNOSTIC_CLASS_ORDER[candidate["candidate_class"]],
            candidate["remaining_difference_count"],
            candidate.get("id", candidate.get("record", "")),
        ]
        candidate.pop("_manifest", None)
    recommended_argv = revalidated[0][1] if len(revalidated) == 1 else []
    return {
        "schema": DIAGNOSTIC_SCHEMA,
        "ok": normalization_error is None,
        "normalized": _normalized_command_diagnostic(normalized) if normalized else None,
        "normalization_error": normalization_error,
        "candidate_count": len(candidates),
        "candidates": candidates,
        "matches": matches,
        "recommended_argv": recommended_argv,
        "suggested_argv": {
            "deprecated": True,
            "replacement": "recommended_argv",
            "value_included": False,
        },
    }


def matching_workflows(command: list[str], cwd: str) -> list[str]:
    """Return every authenticated workflow matching one exact command."""
    return diagnose_matching_workflows(command, cwd)["matches"]


def matching_workflow(command: list[str], cwd: str) -> str:
    """Return one unambiguous authenticated workflow, or an empty string."""
    matches = matching_workflows(command, cwd)
    return matches[0] if len(matches) == 1 else ""
