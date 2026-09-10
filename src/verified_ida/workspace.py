"""Protected model-authored Markdown notebook for Verified IDA."""

from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Iterator, Mapping


CURRENT_STATE_SECTIONS = {
    "objective_and_scope": "Objective and Scope",
    "component_map": "Component Map",
    "active_workstreams": "Active Workstreams",
    "established_understanding": "Established Understanding",
    "hypotheses_and_uncertainty": "Hypotheses and Uncertainty",
    "changed_conclusions_and_impact": "Changed Conclusions and Impact",
    "deferred_or_nonmaterial_work": "Deferred or Nonmaterial Work",
    "next_actions": "Next Actions",
    "closure_review": "Closure Review",
}
DEFAULT_JOURNAL_LIMIT = 3
MAX_JOURNAL_LIMIT = 10
MAX_SECTION_BYTES = 32_000
MAX_JOURNAL_ENTRY_BYTES = 16_000
MAX_JOURNAL_TITLE_BYTES = 240
NOTEBOOK_CURSOR_SCHEMA = "verified_ida.reversing_log_cursor.v1"
_MARKER_PREFIX = "<!-- verified-ida:"
_JOURNAL_START = "<!-- verified-ida:journal:start -->"
_JOURNAL_END = "<!-- verified-ida:journal:end -->"
_ENTRY_START = re.compile(
    r"### Entry: ([^\n]+)\n"
    r"<!-- verified-ida:entry:([a-f0-9]{24}):start -->\n"
)
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_RESERVED_ATX = re.compile(r"^ {0,3}#{1,3}(?:\s|$)")
_SETEXT = re.compile(r"^ {0,3}(?:=+|-+)\s*$")


class ReversingLogError(ValueError):
    """Raised when a notebook request could damage or overwrite structure."""


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _section_start(section: str) -> str:
    return "<!-- verified-ida:section:%s:start -->" % section


def _section_end(section: str) -> str:
    return "<!-- verified-ida:section:%s:end -->" % section


def _entry_start(entry_id: str) -> str:
    return "<!-- verified-ida:entry:%s:start -->" % entry_id


def _entry_end(entry_id: str) -> str:
    return "<!-- verified-ida:entry:%s:end -->" % entry_id


def _render_entry(entry: Mapping[str, str]) -> str:
    entry_id = str(entry["entry_id"])
    return "\n".join([
        "### Entry: %s" % entry["title"],
        _entry_start(entry_id),
        str(entry["content"]),
        _entry_end(entry_id),
    ])


def _journal_body(entries: list[Mapping[str, str]]) -> str:
    return "\n\n".join(_render_entry(entry) for entry in entries)


def _render_notebook(
    sections: Mapping[str, str],
    entries: list[Mapping[str, str]],
) -> str:
    blocks = ["# Reverse Engineering Log", "", "## Current Project State", ""]
    for section, heading in CURRENT_STATE_SECTIONS.items():
        blocks.extend([
            "### %s" % heading,
            _section_start(section),
            str(sections.get(section, "")),
            _section_end(section),
            "",
        ])
    blocks.extend([
        "## Investigation Journal",
        _JOURNAL_START,
        _journal_body(entries),
        _JOURNAL_END,
        "",
    ])
    return "\n".join(blocks)


REVERSING_LOG_TEMPLATE = _render_notebook(
    {section: "" for section in CURRENT_STATE_SECTIONS},
    [],
)


def _consume(text: str, position: int, expected: str) -> int:
    if not text.startswith(expected, position):
        raise ReversingLogError(
            "reversing_log.md has noncanonical protected structure. "
            "Do not edit its H1/H2/H3 headings or verified-ida markers; use the "
            "notebook tools in a newly initialized project."
        )
    return position + len(expected)


def _parse_notebook(text: str) -> dict[str, Any]:
    position = _consume(
        text,
        0,
        "# Reverse Engineering Log\n\n## Current Project State\n\n",
    )
    sections: dict[str, str] = {}
    for index, (section, heading) in enumerate(CURRENT_STATE_SECTIONS.items()):
        prefix = "### %s\n%s\n" % (heading, _section_start(section))
        position = _consume(text, position, prefix)
        suffix = "\n%s\n\n" % _section_end(section)
        end = text.find(suffix, position)
        if end < 0:
            raise ReversingLogError(
                "reversing_log.md section %s has a missing protected end marker. "
                "Use update_reversing_log_section instead of editing the file."
                % section
            )
        sections[section] = text[position:end]
        position = end + len(suffix)
    position = _consume(
        text,
        position,
        "## Investigation Journal\n%s\n" % _JOURNAL_START,
    )
    journal_suffix = "\n%s\n" % _JOURNAL_END
    journal_end = text.find(journal_suffix, position)
    if journal_end < 0 or journal_end + len(journal_suffix) != len(text):
        raise ReversingLogError(
            "reversing_log.md has a malformed protected journal region. "
            "Append entries only with append_reversing_log_journal."
        )
    journal_body = text[position:journal_end]
    entries: list[dict[str, str]] = []
    cursor = 0
    while cursor < len(journal_body):
        match = _ENTRY_START.match(journal_body, cursor)
        if not match:
            raise ReversingLogError(
                "reversing_log.md contains a malformed journal entry. "
                "Append entries only with append_reversing_log_journal."
            )
        title, entry_id = match.groups()
        content_start = match.end()
        end_marker = "\n%s" % _entry_end(entry_id)
        content_end = journal_body.find(end_marker, content_start)
        if content_end < 0:
            raise ReversingLogError(
                "Journal entry %s is missing its protected end marker." % entry_id
            )
        entries.append({
            "entry_id": entry_id,
            "title": title,
            "content": journal_body[content_start:content_end],
        })
        cursor = content_end + len(end_marker)
        if cursor < len(journal_body):
            cursor = _consume(journal_body, cursor, "\n\n")
    parsed = {"sections": sections, "entries": entries}
    if _render_notebook(sections, entries) != text:
        raise ReversingLogError(
            "reversing_log.md protected structure is not canonical. "
            "Use the notebook tools rather than whole-file edits."
        )
    return parsed


def _validate_content(content: str, *, maximum_bytes: int, field: str) -> None:
    if not isinstance(content, str):
        raise ReversingLogError("%s must be a Markdown string." % field)
    size = len(content.encode("utf-8"))
    if size > maximum_bytes:
        raise ReversingLogError(
            "%s is %d UTF-8 bytes; the maximum is %d. Split the material into "
            "a shorter current-state summary and journal entries."
            % (field, size, maximum_bytes)
        )
    if _MARKER_PREFIX in content:
        raise ReversingLogError(
            "%s contains a reserved verified-ida marker. Remove the HTML marker "
            "and retry with ordinary Markdown." % field
        )
    fence_character = None
    fence_length = 0
    previous_nonblank = False
    for line_number, line in enumerate(content.splitlines(), start=1):
        fence = _FENCE.match(line)
        if fence:
            token = fence.group(1)
            if fence_character is None:
                fence_character = token[0]
                fence_length = len(token)
            elif token[0] == fence_character and len(token) >= fence_length:
                fence_character = None
                fence_length = 0
            previous_nonblank = bool(line.strip())
            continue
        if fence_character is not None:
            continue
        if _RESERVED_ATX.match(line):
            raise ReversingLogError(
                "%s line %d introduces a reserved H1/H2/H3 heading. Use an H4 "
                "subheading such as `#### Evidence` and retry."
                % (field, line_number)
            )
        if previous_nonblank and _SETEXT.match(line):
            raise ReversingLogError(
                "%s line %d creates a reserved setext heading. Use `####` for "
                "ordinary subheadings and retry." % (field, line_number)
            )
        previous_nonblank = bool(line.strip())
    if fence_character is not None:
        raise ReversingLogError(
            "%s has an unclosed fenced code block. Add the matching closing "
            "fence and retry." % field
        )


def _validate_section(section: str) -> None:
    if section not in CURRENT_STATE_SECTIONS:
        raise ReversingLogError(
            "Unknown current-state section `%s`. Use one of: %s. Example: "
            "update_reversing_log_section(section=\"next_actions\", "
            "content=\"- Inspect the export resolver\", expected_digest=\"...\")."
            % (section, ", ".join(CURRENT_STATE_SECTIONS))
        )


def _validate_title(title: str) -> None:
    if not isinstance(title, str) or not title:
        raise ReversingLogError("Journal title must be a nonempty single line.")
    if title != title.strip() or "\n" in title or "\r" in title:
        raise ReversingLogError(
            "Journal title must be one trimmed line. Put details in `content`."
        )
    if _MARKER_PREFIX in title or title.startswith("#"):
        raise ReversingLogError(
            "Journal title contains reserved Markdown structure. Use plain title "
            "text such as `Rejected full-mapper hypothesis`."
        )
    size = len(title.encode("utf-8"))
    if size > MAX_JOURNAL_TITLE_BYTES:
        raise ReversingLogError(
            "Journal title is %d UTF-8 bytes; the maximum is %d. Shorten the "
            "title and keep detail in `content`." % (size, MAX_JOURNAL_TITLE_BYTES)
        )


@contextlib.contextmanager
def _locked(path: Path) -> Iterator[None]:
    lock_path = path.with_name(".%s.lock" % path.name)
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _atomic_write(path: Path, text: str) -> None:
    temporary = path.with_name(".%s.tmp-%d" % (path.name, os.getpid()))
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def ensure_reversing_log(workspace: str | Path) -> Path:
    """Create the protected notebook for a new project without migrating old runs."""

    root = Path(workspace)
    root.mkdir(parents=True, exist_ok=True)
    path = root / "reversing_log.md"
    with _locked(path):
        if not path.exists():
            _atomic_write(path, REVERSING_LOG_TEMPLATE)
    return path


def _encode_cursor(*, journal_digest: str, end_index: int) -> str:
    payload = json.dumps({
        "schema": NOTEBOOK_CURSOR_SCHEMA,
        "journal_digest": journal_digest,
        "end_index": end_index,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str, *, journal_digest: str, total: int) -> int:
    try:
        padding = "=" * (-len(cursor) % 4)
        payload = json.loads(
            base64.urlsafe_b64decode((cursor + padding).encode("ascii"))
        )
        if payload.get("schema") != NOTEBOOK_CURSOR_SCHEMA:
            raise ValueError("schema")
        if payload.get("journal_digest") != journal_digest:
            raise ReversingLogError(
                "Journal cursor is stale because the journal changed. Re-read "
                "read_reversing_log without a cursor and restart older-entry paging."
            )
        end_index = int(payload["end_index"])
    except ReversingLogError:
        raise
    except Exception:
        raise ReversingLogError(
            "Malformed journal cursor. Re-read read_reversing_log without a cursor."
        ) from None
    if end_index < 0 or end_index > total:
        raise ReversingLogError(
            "Journal cursor position is invalid. Re-read without a cursor."
        )
    return end_index


def read_reversing_log(
    path: str | Path,
    *,
    journal_limit: int = DEFAULT_JOURNAL_LIMIT,
    journal_cursor: str | None = None,
) -> dict[str, Any]:
    """Return all current state and one bounded newest-to-oldest journal page."""

    notebook = Path(path)
    if not 1 <= int(journal_limit) <= MAX_JOURNAL_LIMIT:
        raise ReversingLogError(
            "journal_limit must be between 1 and %d." % MAX_JOURNAL_LIMIT
        )
    with _locked(notebook):
        text = notebook.read_text(encoding="utf-8")
    parsed = _parse_notebook(text)
    sections = parsed["sections"]
    entries = parsed["entries"]
    journal_body = _journal_body(entries)
    journal_digest = _digest(journal_body)
    end_index = (
        _decode_cursor(
            str(journal_cursor),
            journal_digest=journal_digest,
            total=len(entries),
        )
        if journal_cursor
        else len(entries)
    )
    start_index = max(0, end_index - int(journal_limit))
    page_entries = entries[start_index:end_index]
    return {
        "path": str(notebook.resolve()),
        "document_digest": _digest(text),
        "current_state": {
            section: {
                "heading": CURRENT_STATE_SECTIONS[section],
                "content": content,
                "digest": _digest(content),
                "utf8_bytes": len(content.encode("utf-8")),
            }
            for section, content in sections.items()
        },
        "journal": {
            "digest": journal_digest,
            "entries": [
                {
                    **entry,
                    "content_digest": _digest(entry["content"]),
                    "content_utf8_bytes": len(entry["content"].encode("utf-8")),
                }
                for entry in page_entries
            ],
            "page": {
                "order": "chronological_within_reverse_chronological_pages",
                "total": len(entries),
                "returned": len(page_entries),
                "start_index": start_index,
                "end_index": end_index,
                "has_more": start_index > 0,
                "next_cursor": (
                    _encode_cursor(
                        journal_digest=journal_digest,
                        end_index=start_index,
                    )
                    if start_index > 0
                    else None
                ),
            },
        },
        "limits": {
            "section_utf8_bytes": MAX_SECTION_BYTES,
            "journal_entry_utf8_bytes": MAX_JOURNAL_ENTRY_BYTES,
            "journal_page_entries": MAX_JOURNAL_LIMIT,
        },
    }


def update_reversing_log_section(
    path: str | Path,
    *,
    section: str,
    content: str,
    expected_digest: str,
) -> dict[str, Any]:
    """Replace exactly one current-state section under optimistic concurrency."""

    _validate_section(section)
    _validate_content(content, maximum_bytes=MAX_SECTION_BYTES, field="content")
    notebook = Path(path)
    with _locked(notebook):
        before_text = notebook.read_text(encoding="utf-8")
        parsed = _parse_notebook(before_text)
        before_content = parsed["sections"][section]
        before_digest = _digest(before_content)
        if str(expected_digest) != before_digest:
            raise ReversingLogError(
                "Stale digest for section `%s`: expected `%s`, current `%s`. "
                "Re-read read_reversing_log and retry with expected_digest=`%s`."
                % (section, expected_digest, before_digest, before_digest)
            )
        sections = dict(parsed["sections"])
        sections[section] = content
        after_text = _render_notebook(sections, parsed["entries"])
        _atomic_write(notebook, after_text)
    return {
        "status": "updated",
        "action": "section_update",
        "path": str(notebook.resolve()),
        "section": section,
        "heading": CURRENT_STATE_SECTIONS[section],
        "before_digest": before_digest,
        "after_digest": _digest(content),
        "document_before_digest": _digest(before_text),
        "document_after_digest": _digest(after_text),
        "content_utf8_bytes": len(content.encode("utf-8")),
    }


def append_reversing_log_journal(
    path: str | Path,
    *,
    title: str,
    content: str,
    expected_journal_digest: str,
) -> dict[str, Any]:
    """Append one protected chronological journal entry."""

    _validate_title(title)
    _validate_content(
        content,
        maximum_bytes=MAX_JOURNAL_ENTRY_BYTES,
        field="content",
    )
    notebook = Path(path)
    with _locked(notebook):
        before_text = notebook.read_text(encoding="utf-8")
        parsed = _parse_notebook(before_text)
        before_entries = list(parsed["entries"])
        before_body = _journal_body(before_entries)
        before_digest = _digest(before_body)
        if str(expected_journal_digest) != before_digest:
            raise ReversingLogError(
                "Stale journal digest: expected `%s`, current `%s`. Re-read "
                "read_reversing_log and retry with expected_journal_digest=`%s`."
                % (expected_journal_digest, before_digest, before_digest)
            )
        entry_id = hashlib.sha256(
            (before_digest + "\0" + title + "\0" + content).encode("utf-8")
        ).hexdigest()[:24]
        if any(entry["entry_id"] == entry_id for entry in before_entries):
            raise ReversingLogError(
                "This exact journal entry already exists as `%s`. Re-read the log "
                "before appending another material revision." % entry_id
            )
        entries = before_entries + [{
            "entry_id": entry_id,
            "title": title,
            "content": content,
        }]
        after_text = _render_notebook(parsed["sections"], entries)
        after_body = _journal_body(entries)
        _atomic_write(notebook, after_text)
    return {
        "status": "appended",
        "action": "journal_append",
        "path": str(notebook.resolve()),
        "section": "investigation_journal",
        "entry_id": entry_id,
        "title": title,
        "before_digest": before_digest,
        "after_digest": _digest(after_body),
        "document_before_digest": _digest(before_text),
        "document_after_digest": _digest(after_text),
        "content_digest": _digest(content),
        "content_utf8_bytes": len(content.encode("utf-8")),
    }
