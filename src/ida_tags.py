"""
IDA Tag System — Netnode-based function tagging for analysis state tracking.

IDA Pro has no native tag API like Binary Ninja. This module implements
an equivalent using a single netnode that stores JSON metadata per address.

Storage: A netnode named '$harness_tags' stores a JSON blob at each
function address via supval. The blob is a dict mapping tag names to data:
    {"collapsed": "imported", "interesting": "score:42.5"}

Tags persist automatically when the IDB is saved.
"""

import json
from typing import Optional

import ida_netnode

# Tag constants (identical to binja_harness)
TAG_COLLAPSED = "collapsed"
TAG_INTERESTING = "interesting"
TAG_ANALYZED = "analyzed"
TAG_BLOCKED = "blocked"
TAG_NEEDS_CONTEXT = "needs_context"

NETNODE_NAME = "$ harness_tags"  # IDA hidden netnode convention: "$ " prefix


def _get_tag_node() -> ida_netnode.netnode:
    """Get or create the harness tags netnode."""
    node = ida_netnode.netnode()
    if not node.create(NETNODE_NAME):
        # Node already exists, open it
        node = ida_netnode.netnode(NETNODE_NAME)
    return node


def _read_tags(ea: int) -> dict:
    """Read the tag dict for a given address."""
    node = _get_tag_node()
    blob = node.supstr(ea)
    if blob:
        try:
            return json.loads(blob)
        except (json.JSONDecodeError, ValueError):
            return {}
    return {}


def _write_tags(ea: int, tags: dict) -> None:
    """Write the tag dict for a given address."""
    node = _get_tag_node()
    if tags:
        node.supset(ea, json.dumps(tags))
    else:
        node.supdel(ea)


def tag_function(ea: int, tag_name: str, data: str = "") -> bool:
    """Add a tag to a function at the given address.

    Args:
        ea: Function start address
        tag_name: Tag name (use TAG_* constants)
        data: Optional additional data string

    Returns:
        True on success
    """
    try:
        tags = _read_tags(ea)
        tags[tag_name] = data
        _write_tags(ea, tags)
        return True
    except Exception:
        return False


def remove_tag(ea: int, tag_name: str) -> bool:
    """Remove a tag from a function.

    Returns:
        True if tag was removed, False if it didn't exist
    """
    try:
        tags = _read_tags(ea)
        if tag_name in tags:
            del tags[tag_name]
            _write_tags(ea, tags)
            return True
        return False
    except Exception:
        return False


def has_tag(ea: int, tag_name: str) -> bool:
    """Check if a function has a specific tag."""
    tags = _read_tags(ea)
    return tag_name in tags


def get_tag_data(ea: int, tag_name: str) -> Optional[str]:
    """Get the data string for a specific tag, or None if not tagged."""
    tags = _read_tags(ea)
    return tags.get(tag_name)


def get_function_tags(ea: int) -> list[dict]:
    """Get all tags for a function.

    Returns:
        List of dicts: [{"name": tag_name, "data": tag_data}, ...]
    """
    tags = _read_tags(ea)
    return [{"name": name, "data": data} for name, data in tags.items()]


def get_all_tagged(tag_name: str) -> list[int]:
    """Get all addresses that have a specific tag.

    Note: This iterates all supvals in the netnode, which can be slow
    for very large databases. Cache results if calling frequently.

    Returns:
        List of addresses (ints)
    """
    node = _get_tag_node()
    result = []

    ea = node.supfirst()
    while ea != ida_netnode.BADNODE:
        blob = node.supstr(ea)
        if blob:
            try:
                tags = json.loads(blob)
                if tag_name in tags:
                    result.append(ea)
            except (json.JSONDecodeError, ValueError):
                pass
        ea = node.supnext(ea)

    return result
