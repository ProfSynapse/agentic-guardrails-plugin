"""Trusted, data-only contracts for opaque write-capable scripts.

Repository manifests are inert until a user explicitly trusts one.  Trusting
copies a normalized, script-hash-bound record into AGW_HOME and authenticates
it with a machine-local key.  Execution resolves only a small placeholder
language; manifests never execute code.
"""
from __future__ import annotations

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
from datetime import datetime, timezone
from typing import Optional

from . import store


MANIFEST_SCHEMA_V1 = "agw.workflow/v1"
MANIFEST_SCHEMA = "agw.workflow/v2"
PARAMETERIZED_SCHEMA = "agw.workflow/v3"
MANIFEST_SCHEMAS = {MANIFEST_SCHEMA_V1, MANIFEST_SCHEMA, PARAMETERIZED_SCHEMA}
RECORD_SCHEMA = "agw.trusted-workflow/v1"
MAX_MANIFEST_BYTES = 256 * 1024
MAX_WORKFLOWS = 256
MAX_OUTPUTS = 128
MAX_ROOTS = 16
MAX_PATTERNS = 64
MAX_ARGS = 128
MAX_ARG_BYTES = 16 * 1024
MAX_PARAMETERS = 32
MAX_ENUM_VALUES = 512
MAX_PARAMETER_BYTES = 4096

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
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "id": workflow_id,
        "description": description,
        "command": {
            "runtime": runtime,
            "script": script_value,
            "script_sha256": store.file_sha256(script_path),
            "args": list(args or []),
        },
        "allowed_roots": roots,
        "outputs": [
            {"path": path, "expected": expectation}
            for path, expectation in zip(outputs, expected)
        ],
        "observed_roots": [],
    }
    normalized = validate_manifest(manifest, manifest_path)
    return {"manifest": manifest, "normalized": normalized}


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


def _seal(record: dict, key: bytes) -> str:
    unsigned = dict(record)
    unsigned.pop("seal", None)
    return hmac.new(key, _canonical_json(unsigned), hashlib.sha256).hexdigest()


def trust_manifest(path: str, expected_manifest_hash: str, *, replace: bool = False,
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
            path, expected_manifest_hash, replace=replace, phase_callback=phase,
        )
    phase("complete")
    result["phases"] = phases
    return result


def _trust_manifest_locked(path: str, expected_manifest_hash: str,
                           *, replace: bool = False, phase_callback=None) -> dict:
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
    if os.path.exists(record_path):
        existing = load_trusted(manifest["id"])
        if (existing.get("manifest_sha256") == actual
                and existing.get("manifest") == manifest):
            return {
                "ok": True, "changed": False, "workflow": manifest["id"],
                "manifest_sha256": actual, "script_sha256": manifest["command"]["script_sha256"],
            }
        if not replace:
            raise WorkflowConflict(
                "a different trusted record already exists; review it and repeat with --replace",
                {"workflow": manifest["id"]},
            )
    elif len(existing_records) >= MAX_WORKFLOWS:
        raise WorkflowError(f"trusted workflow store is limited to {MAX_WORKFLOWS} records")
    record = {
        "schema": RECORD_SCHEMA,
        "manifest_sha256": actual,
        "trusted_at": datetime.now(timezone.utc).isoformat(),
        "manifest": manifest,
    }
    record["seal"] = _seal(record, key)
    if phase_callback:
        phase_callback("writing_record")
    _atomic_write(record_path, _canonical_json(record) + b"\n")
    return {
        "ok": True, "changed": True, "workflow": manifest["id"],
        "manifest_sha256": actual, "script": manifest["command"]["script"],
        "script_sha256": manifest["command"]["script_sha256"],
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
        if st.st_size > MAX_MANIFEST_BYTES:
            raise WorkflowTrustError("trusted workflow record is too large")
        with open(path, "rb") as handle:
            raw = handle.read(MAX_MANIFEST_BYTES + 1)
        record = json.loads(raw.decode("utf-8"), object_pairs_hook=_json_no_duplicates)
    except FileNotFoundError as exc:
        raise WorkflowTrustError(
            f"workflow {workflow_id!r} is not trusted; use `agw workflow trust --help`"
        ) from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WorkflowTrustError(f"trusted workflow record could not be verified: {exc}") from exc
    if not isinstance(record, dict) or record.get("schema") != RECORD_SCHEMA:
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
                    or st.st_size > MAX_MANIFEST_BYTES:
                raise WorkflowTrustError("record verification failed")
            with open(path, "rb") as handle:
                candidate = json.loads(handle.read(MAX_MANIFEST_BYTES + 1).decode("utf-8"))
            workflow_id = candidate.get("manifest", {}).get("id", "")
            record = load_trusted(workflow_id)
            manifest = record["manifest"]
            result.append({
                "id": workflow_id, "description": manifest.get("description", ""),
                "runtime": manifest["command"]["runtime"],
                "script": manifest["command"]["script"], "verified": True,
            })
        except (OSError, ValueError, TypeError, WorkflowError):
            result.append({"record": name, "verified": False, "error": "record verification failed"})
    return result


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


def matching_workflows(command: list[str], cwd: str) -> list[str]:
    """Return every authenticated workflow matching one exact command."""
    try:
        normalized = normalize_command(command, cwd)
    except WorkflowError:
        return []
    matches = []
    for item in list_trusted():
        if not item.get("verified"):
            continue
        try:
            record = load_trusted(item["id"])
        except WorkflowError:
            continue
        manifest = record["manifest"]
        bound = manifest["command"]
        if not (bound["runtime"] == normalized["runtime"]
                and os.path.normcase(bound["script"]) == os.path.normcase(normalized["script"])
                and hmac.compare_digest(bound["script_sha256"], normalized["script_sha256"])):
            continue
        if manifest.get("schema") == MANIFEST_SCHEMA \
                and bound.get("args", []) != normalized["args"]:
            continue
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
            except WorkflowError:
                continue
        matches.append(item["id"])
    return matches


def matching_workflow(command: list[str], cwd: str) -> str:
    """Return one unambiguous authenticated workflow, or an empty string."""
    matches = matching_workflows(command, cwd)
    return matches[0] if len(matches) == 1 else ""
