"""Strict Codex 0.160.0 embedded PreToolUse wire schema regression oracle.

Extracted from pinned Linux x86_64 binary SHA256
12eb3e81114588aca3b7998f4f19e8997b056aca08e57a7ca7c8a3ec8c652aad.
This validates the actual embedded schema subset, not a permissive imitation of
Claude's contract. An omitted output is handled by the adapter harness as {}.
"""
SCHEMA = {
    '$schema': 'http://json-schema.org/draft-07/schema#',
    'additionalProperties': False,
    'definitions': {
        'PreToolUseDecisionWire': {'enum': ['approve', 'block'], 'type': 'string'},
        'PreToolUsePermissionDecisionWire': {'enum': ['allow', 'deny', 'ask'], 'type': 'string'},
        'PreToolUseHookSpecificOutputWire': {
            'additionalProperties': False, 'type': 'object',
            'required': ['hookEventName'],
            'properties': {
                'additionalContext': {'default': None, 'type': 'string'},
                'hookEventName': {'const': 'PreToolUse', 'type': 'string'},
                'permissionDecision': {'default': None, 'allOf': [{'$ref': '#/definitions/PreToolUsePermissionDecisionWire'}]},
                'permissionDecisionReason': {'default': None, 'type': 'string'},
                'updatedInput': {'default': None},
            },
        },
    },
    'properties': {
        'continue': {'default': True, 'type': 'boolean'},
        'decision': {'default': None, 'allOf': [{'$ref': '#/definitions/PreToolUseDecisionWire'}]},
        'hookSpecificOutput': {'default': None, 'allOf': [{'$ref': '#/definitions/PreToolUseHookSpecificOutputWire'}]},
        'reason': {'default': None, 'type': 'string'},
        'stopReason': {'default': None, 'type': 'string'},
        'suppressOutput': {'default': False, 'type': 'boolean'},
        'systemMessage': {'default': None, 'type': 'string'},
    },
    'title': 'pre-tool-use.command.output', 'type': 'object',
}


def validate_wire(value, schema=None):
    """Validate all keywords present in the captured draft-07 schema.

    Defaults do not permit explicit null. Unknown schema keywords fail loudly
    so an updated fixture cannot silently weaken the regression oracle.
    """
    node = SCHEMA if schema is None else schema
    assert set(node) <= {'$schema', 'title', 'definitions', '$ref', 'allOf',
                         'default', 'type', 'enum', 'const', 'required',
                         'properties', 'additionalProperties'}
    if '$ref' in node:
        assert node['$ref'].startswith('#/definitions/')
        validate_wire(value, SCHEMA['definitions'][node['$ref'].split('/')[-1]])
    for child in node.get('allOf', []):
        validate_wire(value, child)
    if 'type' in node:
        expected = {'object': dict, 'string': str, 'boolean': bool}[node['type']]
        assert type(value) is expected, (node['type'], value)
    if 'enum' in node:
        assert value in node['enum'], value
    if 'const' in node:
        assert value == node['const'], value
    if isinstance(value, dict):
        assert set(node.get('required', [])) <= set(value)
        properties = node.get('properties', {})
        if node.get('additionalProperties') is False:
            assert set(value) <= set(properties), set(value) - set(properties)
        for key in value.keys() & properties.keys():
            validate_wire(value[key], properties[key])
