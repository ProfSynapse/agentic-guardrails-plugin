"""Dependency-free OOXML reads and localized Word/PowerPoint text edits."""
from __future__ import annotations

import hashlib
import os
import tempfile
import zipfile
from xml.etree import ElementTree

import office_opc


W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"
P_NS = "http://schemas.openxmlformats.org/presentationml/2006/main"
DOC_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
XML_NS = "http://www.w3.org/XML/1998/namespace"

for prefix, namespace in (
    ("w", W_NS), ("a", A_NS), ("p", P_NS), ("r", DOC_REL_NS),
):
    ElementTree.register_namespace(prefix, namespace)


class OoxmlError(RuntimeError):
    pass


def _part(package: zipfile.ZipFile, name: str) -> bytes:
    try:
        return package.read(name)
    except KeyError as exc:
        raise OoxmlError(f"OOXML package is missing {name}") from exc


def _xml(package: zipfile.ZipFile, name: str):
    try:
        return ElementTree.fromstring(_part(package, name))
    except ElementTree.ParseError as exc:
        raise OoxmlError(f"OOXML part is malformed: {name}") from exc


def _serialized(root) -> bytes:
    return ElementTree.tostring(root, encoding="utf-8", xml_declaration=True)


def rewrite_parts(path: str, replacements: dict[str, bytes]) -> None:
    """Rewrite named OOXML parts while byte-preserving every other part."""
    fd, staged = tempfile.mkstemp(
        prefix=".agw-ooxml-", suffix=os.path.splitext(path)[1],
        dir=os.path.dirname(path),
    )
    os.close(fd)
    try:
        with zipfile.ZipFile(path) as source, zipfile.ZipFile(staged, "w") as target:
            target.comment = source.comment
            names = set(source.namelist())
            missing = sorted(set(replacements) - names)
            if missing:
                raise OoxmlError(f"OOXML package is missing {missing[0]}")
            for item in source.infolist():
                target.writestr(
                    item,
                    replacements.get(item.filename, source.read(item)),
                )
        os.replace(staged, path)
    finally:
        if os.path.exists(staged):
            try:
                os.unlink(staged)
            except OSError:
                pass


def _relationship_map(package: zipfile.ZipFile, base_part: str) -> dict[str, str]:
    rels_part = office_opc.relationship_part_for(base_part)
    root = _xml(package, rels_part)
    result = {}
    for relationship in root.findall(f"{{{PKG_REL_NS}}}Relationship"):
        rel_id = relationship.attrib.get("Id", "")
        if rel_id:
            resolution = office_opc.resolve_relationship(
                package.namelist(), rels_part, rel_id,
                relationship.attrib.get("Target", ""),
                relationship.attrib.get("TargetMode", ""),
                owner_part=base_part,
            )
            if resolution.reason == "external_target_not_opened":
                continue
            if not resolution.usable:
                if resolution.reason == "package_root_escape":
                    raise OoxmlError("OOXML relationship escapes the package")
                raise OoxmlError("OOXML relationship target is invalid")
            result[rel_id] = resolution.actual_part
    return result


def _combined_text(nodes) -> str:
    return "".join(node.text or "" for node in nodes)


def _set_text_nodes(nodes, text: str) -> None:
    if not nodes:
        raise OoxmlError("text-bearing OOXML block has no text nodes")
    remaining = text
    for index, node in enumerate(nodes):
        width = len(node.text or "")
        value = remaining if index == len(nodes) - 1 else remaining[:width]
        remaining = remaining[len(value):]
        node.text = value
        if value != value.strip():
            node.attrib[f"{{{XML_NS}}}space"] = "preserve"
        else:
            node.attrib.pop(f"{{{XML_NS}}}space", None)


def _replace_selected(text: str, find: str, replacement: str,
                      occurrence: int, targets: set[int] | None):
    pieces = text.split(find)
    output = pieces[0]
    replaced = 0
    for piece in pieces[1:]:
        occurrence += 1
        if targets is None or occurrence in targets:
            output += replacement
            replaced += 1
        else:
            output += find
        output += piece
    return output, occurrence, replaced


# Word -----------------------------------------------------------------------

def _canonical_word_style(name: str) -> str:
    value = str(name or "")
    lower = value.casefold()
    if lower.startswith("heading "):
        return "Heading " + value.split(" ", 1)[1]
    if lower.startswith("list "):
        return "List " + value.split(" ", 1)[1]
    return value


def _word_styles(package: zipfile.ZipFile):
    try:
        root = _xml(package, "word/styles.xml")
    except OoxmlError:
        return {}, {}
    by_id = {}
    by_name = {}
    for style in root.findall(f"{{{W_NS}}}style"):
        style_id = style.attrib.get(f"{{{W_NS}}}styleId", "")
        name_node = style.find(f"{{{W_NS}}}name")
        name = name_node.attrib.get(f"{{{W_NS}}}val", "") if name_node is not None else ""
        canonical = _canonical_word_style(name)
        if style_id:
            by_id[style_id] = canonical or style_id
            if name:
                by_name[name] = style_id
                by_name[canonical] = style_id
    return by_id, by_name


def _word_style_id(paragraph) -> str:
    node = paragraph.find(f"{{{W_NS}}}pPr/{{{W_NS}}}pStyle")
    return node.attrib.get(f"{{{W_NS}}}val", "") if node is not None else ""


def _word_kind(style: str) -> str:
    if style.startswith("Heading"):
        suffix = style[len("Heading"):].strip()
        return "h" + (suffix or "?")
    if style.startswith("List"):
        return "li"
    return "p"


def _word_record(index: int, paragraph, styles: dict[str, str], location: str):
    style_id = _word_style_id(paragraph)
    style = styles.get(style_id, style_id)
    nodes = list(paragraph.iter(f"{{{W_NS}}}t"))
    text = _combined_text(nodes)
    kind = _word_kind(style)
    digest = hashlib.sha256(
        "\x1f".join((kind, style, text)).encode("utf-8", "replace")
    ).hexdigest()[:8]
    return {
        "id": f"p{index}-{digest}", "index": index, "kind": kind,
        "style": style, "style_id": style_id, "text": text,
        "nodes": nodes, "element": paragraph, "location": location,
    }


def _word_document(path: str):
    with zipfile.ZipFile(path) as package:
        root = _xml(package, "word/document.xml")
        styles, by_name = _word_styles(package)
    body = root.find(f"{{{W_NS}}}body")
    if body is None:
        raise OoxmlError("Word document has no body")
    paragraphs = list(body.findall(f"{{{W_NS}}}p"))
    blocks = [
        _word_record(index, paragraph, styles, f"paragraph {index}")
        for index, paragraph in enumerate(paragraphs, 1)
    ]
    return root, body, blocks, styles, by_name


def word_info(path: str) -> dict:
    root, body, blocks, _styles, _by_name = _word_document(path)
    tables = body.findall(f"{{{W_NS}}}tbl")
    return {
        "type": "docx", "paragraphs": len(blocks), "tables": len(tables),
        "headings": [item["text"] for item in blocks
                     if item["kind"].startswith("h") and item["text"].strip()],
    }


def word_get_text(path: str) -> str:
    _root, body, blocks, _styles, _by_name = _word_document(path)
    parts = [item["text"] for item in blocks]
    for table in body.findall(f"{{{W_NS}}}tbl"):
        for row in table.findall(f"{{{W_NS}}}tr"):
            cells = []
            for cell in row.findall(f"{{{W_NS}}}tc"):
                cells.append("\n".join(
                    _combined_text(paragraph.iter(f"{{{W_NS}}}t"))
                    for paragraph in cell.findall(f"{{{W_NS}}}p")
                ))
            parts.append("\t".join(cells))
    return "\n".join(parts)


def word_blocks(path: str):
    return _word_document(path)[2]


def _word_all_records(path: str):
    with zipfile.ZipFile(path) as package:
        root = _xml(package, "word/document.xml")
        styles, _by_name = _word_styles(package)
    body = root.find(f"{{{W_NS}}}body")
    if body is None:
        raise OoxmlError("Word document has no body")
    records = []
    for index, paragraph in enumerate(body.findall(f"{{{W_NS}}}p"), 1):
        records.append(_word_record(index, paragraph, styles, f"paragraph {index}"))
    record_index = len(records)
    for table_index, table in enumerate(body.findall(f"{{{W_NS}}}tbl"), 1):
        for paragraph in table.findall(f".//{{{W_NS}}}tc/{{{W_NS}}}p"):
            record_index += 1
            records.append(_word_record(
                record_index, paragraph, styles, f"table {table_index}"
            ))
    return root, records


def word_find_matches(path: str, find: str) -> list:
    _root, records = _word_all_records(path)
    return _find_matches(records, find)


def _find_matches(records, find: str) -> list:
    matches = []
    for record in records:
        start = 0
        while True:
            index = record["text"].find(find, start)
            if index < 0:
                break
            context = record["text"][max(0, index - 40):index + len(find) + 40]
            matches.append({
                "n": len(matches) + 1,
                "where": record["location"],
                "context": context,
            })
            start = index + len(find)
    return matches


def word_replace(path: str, find: str, replacement: str,
                 targets: set[int] | None) -> int:
    root, records = _word_all_records(path)
    occurrence = 0
    replaced = 0
    for record in records:
        if find not in record["text"]:
            continue
        updated, occurrence, count = _replace_selected(
            record["text"], find, replacement, occurrence, targets
        )
        if count:
            _set_text_nodes(record["nodes"], updated)
            replaced += count
    rewrite_parts(path, {"word/document.xml": _serialized(root)})
    return replaced


def word_paragraph_is_complex(paragraph) -> bool:
    names = {
        f"{{{W_NS}}}fldChar", f"{{{W_NS}}}drawing", f"{{{W_NS}}}object",
        f"{{{W_NS}}}bookmarkStart", f"{{{W_NS}}}commentRangeStart",
        f"{{{W_NS}}}hyperlink",
    }
    return any(node.tag in names for node in paragraph.iter())


def _word_style_value(style: str, by_name: dict[str, str]) -> str:
    if not style:
        return ""
    if style not in by_name:
        raise OoxmlError(f"unknown Word style: {style}")
    return by_name[style]


def validate_word_patch(path: str, operations: list) -> int:
    _root, _body, blocks, _styles, by_name = _word_document(path)
    mapping = {item["id"]: item for item in blocks}
    allowed = {
        "replace_text": {"op", "id", "find", "replace"},
        "replace_block": {"op", "id", "text", "style"},
        "insert_before": {"op", "id", "blocks"},
        "insert_after": {"op", "id", "blocks"},
        "append": {"op", "blocks"},
        "delete_block": {"op", "id"},
    }
    seen = set()
    for number, operation in enumerate(operations, 1):
        if not isinstance(operation, dict):
            raise OoxmlError(f"Word patch operation {number} must be an object")
        op = operation.get("op")
        if op not in allowed:
            raise OoxmlError(f"unsupported Word patch operation: {op!r}")
        unknown = set(operation) - allowed[op]
        if unknown:
            raise OoxmlError(f"unknown fields for {op}: {', '.join(sorted(unknown))}")
        block_id = operation.get("id")
        if block_id:
            if block_id not in mapping:
                raise OoxmlError(f"stale or unknown Word block ID: {block_id}")
            if block_id in seen:
                raise OoxmlError("a Word block may be targeted only once per patch")
            seen.add(block_id)
            if op in {"replace_text", "replace_block", "delete_block"} \
                    and word_paragraph_is_complex(mapping[block_id]["element"]):
                raise OoxmlError("target paragraph contains unsupported complex content")
        if op == "replace_text":
            find = operation.get("find")
            if not isinstance(find, str) or not find:
                raise OoxmlError("replace_text needs non-empty find text")
            if mapping[block_id]["text"].count(find) != 1:
                raise OoxmlError("replace_text must match exactly once in its block")
        if op == "replace_block":
            if not isinstance(operation.get("text"), str):
                raise OoxmlError("replace_block needs text")
            _word_style_value(operation.get("style", ""), by_name)
        if op in {"insert_before", "insert_after", "append"}:
            inserted = operation.get("blocks")
            if not isinstance(inserted, list) or not inserted:
                raise OoxmlError(f"{op} needs a non-empty blocks array")
            for block in inserted:
                if not (isinstance(block, list) and len(block) == 2
                        and all(isinstance(value, str) for value in block)):
                    raise OoxmlError("inserted blocks must be [style, text] pairs")
                _word_style_value(block[0], by_name)
    return len(operations)


def _new_word_paragraph(style_id: str, text: str):
    paragraph = ElementTree.Element(f"{{{W_NS}}}p")
    if style_id:
        properties = ElementTree.SubElement(paragraph, f"{{{W_NS}}}pPr")
        style = ElementTree.SubElement(properties, f"{{{W_NS}}}pStyle")
        style.attrib[f"{{{W_NS}}}val"] = style_id
    run = ElementTree.SubElement(paragraph, f"{{{W_NS}}}r")
    node = ElementTree.SubElement(run, f"{{{W_NS}}}t")
    node.text = text
    if text != text.strip():
        node.attrib[f"{{{XML_NS}}}space"] = "preserve"
    return paragraph


def _replace_word_block(paragraph, style_id: str, text: str):
    properties = paragraph.find(f"{{{W_NS}}}pPr")
    for child in list(paragraph):
        if child is not properties:
            paragraph.remove(child)
    if style_id:
        if properties is None:
            properties = ElementTree.Element(f"{{{W_NS}}}pPr")
            paragraph.insert(0, properties)
        style = properties.find(f"{{{W_NS}}}pStyle")
        if style is None:
            style = ElementTree.SubElement(properties, f"{{{W_NS}}}pStyle")
        style.attrib[f"{{{W_NS}}}val"] = style_id
    elif properties is not None:
        style = properties.find(f"{{{W_NS}}}pStyle")
        if style is not None:
            properties.remove(style)
    run = ElementTree.SubElement(paragraph, f"{{{W_NS}}}r")
    node = ElementTree.SubElement(run, f"{{{W_NS}}}t")
    node.text = text
    if text != text.strip():
        node.attrib[f"{{{XML_NS}}}space"] = "preserve"


def apply_word_patch(path: str, operations: list) -> int:
    root, body, blocks, _styles, by_name = _word_document(path)
    mapping = {item["id"]: item for item in blocks}
    for operation in operations:
        op = operation["op"]
        record = mapping.get(operation.get("id"))
        paragraph = record["element"] if record else None
        if op == "replace_text":
            updated = record["text"].replace(
                operation["find"], operation.get("replace", ""), 1
            )
            _set_text_nodes(record["nodes"], updated)
        elif op == "replace_block":
            style = operation.get("style") or record["style"]
            _replace_word_block(paragraph, _word_style_value(style, by_name),
                                operation["text"])
        elif op in {"insert_before", "insert_after"}:
            index = list(body).index(paragraph)
            if op == "insert_after":
                index += 1
            for style, text in operation["blocks"]:
                body.insert(index, _new_word_paragraph(
                    _word_style_value(style, by_name), text
                ))
                index += 1
        elif op == "append":
            children = list(body)
            section = body.find(f"{{{W_NS}}}sectPr")
            index = children.index(section) if section is not None else len(children)
            for style, text in operation["blocks"]:
                body.insert(index, _new_word_paragraph(
                    _word_style_value(style, by_name), text
                ))
                index += 1
        elif op == "delete_block":
            body.remove(paragraph)
    rewrite_parts(path, {"word/document.xml": _serialized(root)})
    return len(operations)


# PowerPoint -----------------------------------------------------------------

def _presentation_slides(path: str):
    with zipfile.ZipFile(path) as package:
        presentation = _xml(package, "ppt/presentation.xml")
        relationships = _relationship_map(package, "ppt/presentation.xml")
        parts = []
        for slide in presentation.findall(f".//{{{P_NS}}}sldId"):
            rel_id = slide.attrib.get(f"{{{DOC_REL_NS}}}id", "")
            part = relationships.get(rel_id)
            if not part or part not in package.namelist():
                raise OoxmlError("PowerPoint slide relationship is invalid")
            parts.append((part, _xml(package, part)))
    return parts


def _slide_records(slide_number: int, root):
    records = []
    for paragraph in root.findall(f".//{{{A_NS}}}p"):
        nodes = list(paragraph.iter(f"{{{A_NS}}}t"))
        if nodes:
            records.append({
                "text": _combined_text(nodes), "nodes": nodes,
                "location": f"slide {slide_number}", "element": paragraph,
            })
    return records


def presentation_get_text(path: str) -> str:
    parts = []
    for number, (_part_name, root) in enumerate(_presentation_slides(path), 1):
        parts.append(f"--- slide {number} ---")
        for shape in root.findall(f".//{{{P_NS}}}sp"):
            paragraphs = shape.findall(f".//{{{A_NS}}}p")
            text = "\n".join(_combined_text(item.iter(f"{{{A_NS}}}t"))
                             for item in paragraphs)
            if text:
                parts.append(text)
    return "\n".join(parts)


def presentation_info(path: str) -> dict:
    slides = _presentation_slides(path)
    titles = []
    for _part_name, root in slides:
        title = ""
        for shape in root.findall(f".//{{{P_NS}}}sp"):
            placeholder = shape.find(f"{{{P_NS}}}nvSpPr/{{{P_NS}}}nvPr/{{{P_NS}}}ph")
            if placeholder is not None and placeholder.attrib.get("type", "") in {
                    "title", "ctrTitle"}:
                title = _combined_text(shape.iter(f"{{{A_NS}}}t"))
                break
        titles.append(title)
    return {"type": "pptx", "slides": len(slides), "titles": titles}


def presentation_find_matches(path: str, find: str) -> list:
    records = []
    for number, (_part_name, root) in enumerate(_presentation_slides(path), 1):
        records.extend(_slide_records(number, root))
    return _find_matches(records, find)


def presentation_replace(path: str, find: str, replacement: str,
                         targets: set[int] | None) -> int:
    slides = _presentation_slides(path)
    occurrence = 0
    replaced = 0
    replacements = {}
    for number, (part_name, root) in enumerate(slides, 1):
        changed = False
        for record in _slide_records(number, root):
            if find not in record["text"]:
                continue
            updated, occurrence, count = _replace_selected(
                record["text"], find, replacement, occurrence, targets
            )
            if count:
                _set_text_nodes(record["nodes"], updated)
                replaced += count
                changed = True
        if changed:
            replacements[part_name] = _serialized(root)
    if replacements:
        rewrite_parts(path, replacements)
    return replaced
