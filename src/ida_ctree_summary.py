"""Best-effort Hex-Rays ctree/function fact summaries for IDA runs."""

from __future__ import annotations

from typing import Any

import ida_bytes
import ida_funcs
import ida_lines
import idautils
import idc

try:
    import ida_hexrays
    HAS_HEXRAYS = True
except ImportError:
    ida_hexrays = None
    HAS_HEXRAYS = False


def _hex(value: Any) -> str | None:
    try:
        if value is None or value == idc.BADADDR:
            return None
        return hex(int(value))
    except Exception:
        return None


def _clean(text: Any) -> str:
    try:
        return ida_lines.tag_remove(str(text or ""))
    except Exception:
        return str(text or "")


def _op_name(op: int) -> str:
    if not HAS_HEXRAYS:
        return str(op)
    try:
        name = ida_hexrays.get_ctype_name(op)
        if name:
            return str(name)
    except Exception:
        pass
    for key, value in ida_hexrays.__dict__.items():
        if key.startswith("cot_") and value == op:
            return key
    return str(op)


def _op_value(name: str) -> int | None:
    if not HAS_HEXRAYS:
        return None
    value = getattr(ida_hexrays, name, None)
    return int(value) if value is not None else None


def _op_matches(op: int, names: set[str]) -> bool:
    for name in names:
        value = _op_value(name)
        if value is not None and op == value:
            return True
    op_name = _op_name(op)
    short_names = {name[4:] if name.startswith("cot_") else name for name in names}
    return op_name in names or op_name in short_names


ASSIGNMENT_OPS = {
    "cot_asg",
    "cot_asgbor",
    "cot_asgxor",
    "cot_asgband",
    "cot_asgadd",
    "cot_asgsub",
    "cot_asgmul",
    "cot_asgsshr",
    "cot_asgushr",
    "cot_asgshl",
    "cot_asgsdiv",
    "cot_asgudiv",
    "cot_asgsmod",
    "cot_asgumod",
}


def _expr_text(expr: Any) -> str:
    try:
        return _clean(expr.print1(None))
    except Exception:
        return ""


def _num_value(expr: Any) -> int | None:
    try:
        return int(expr.n._value)
    except Exception:
        pass
    try:
        return int(expr.numval())
    except Exception:
        pass
    return None


def _callee_name(expr: Any) -> str:
    text = _expr_text(expr)
    if text:
        return text
    try:
        obj_ea = int(expr.obj_ea)
        if obj_ea and obj_ea != idc.BADADDR:
            return idc.get_func_name(obj_ea) or _hex(obj_ea) or ""
    except Exception:
        pass
    return ""


def _call_args(expr: Any, limit: int) -> list[str]:
    args = []
    try:
        for arg in list(expr.a)[:limit]:
            args.append(_expr_text(arg))
    except Exception:
        pass
    return args


def _record_lvars(cfunc: Any, limit: int) -> list[dict[str, Any]]:
    lvars = []
    try:
        raw_lvars = list(cfunc.lvars)
    except Exception:
        raw_lvars = []
    for index, lvar in enumerate(raw_lvars[:limit]):
        try:
            type_text = lvar.type().dstr()
        except Exception:
            type_text = ""
        is_arg_attr = getattr(lvar, "is_arg_var", False)
        try:
            is_arg = bool(is_arg_attr()) if callable(is_arg_attr) else bool(is_arg_attr)
        except Exception:
            is_arg = False
        has_user_name_value = _call_noarg(lvar, "has_user_name")
        has_user_name = (
            bool(has_user_name_value)
            if has_user_name_value is not None
            else None
        )
        has_user_type_value = _call_noarg(lvar, "has_user_type")
        has_user_type = (
            bool(has_user_type_value)
            if has_user_type_value is not None
            else None
        )
        lvars.append({
            "index": index,
            "name": str(getattr(lvar, "name", "") or ""),
            "type": type_text,
            "is_arg": is_arg,
            "has_user_name": has_user_name,
            "name_provenance": (
                "user"
                if has_user_name is True
                else "not_user_supplied"
                if has_user_name is False
                else "unknown"
            ),
            "is_fake": bool(_call_noarg(lvar, "is_fake_var")),
            "is_overlapped": bool(_call_noarg(lvar, "is_overlapped_var")),
            "has_user_type": has_user_type,
            "type_provenance": (
                "user"
                if has_user_type is True
                else "not_user_supplied"
                if has_user_type is False
                else "unknown"
            ),
            "location": _lvar_location(lvar),
            "use_count": 0,
            "assignment_count": 0,
            "use_sites": [],
        })
    return lvars


def _call_noarg(obj: Any, name: str) -> Any:
    attr = getattr(obj, name, None)
    if attr is None:
        return None
    try:
        return attr() if callable(attr) else attr
    except Exception:
        return None


def _lvar_location(lvar: Any) -> dict[str, Any]:
    location = getattr(lvar, "location", None)
    result = {
        "text": str(location) if location is not None else "",
        "width": _call_noarg(lvar, "width"),
        "defea": _hex(_call_noarg(lvar, "defea")),
        "stack_offset": None,
        "kind": "unknown",
    }
    for source in (lvar, location):
        if source is None:
            continue
        for method in ("get_stkoff", "stkoff"):
            value = _call_noarg(source, method)
            if isinstance(value, int) and value >= 0:
                result["stack_offset"] = value
                result["kind"] = "stack"
                return result
        for predicate, kind in (
            ("is_stkoff", "stack"),
            ("is_reg", "register"),
            ("is_reg1", "register"),
            ("is_scattered", "scattered"),
            ("is_empty", "empty"),
        ):
            value = _call_noarg(source, predicate)
            if value is True:
                result["kind"] = kind
    return result


def _var_index(expr: Any) -> int | None:
    try:
        return int(expr.v.idx)
    except Exception:
        pass
    try:
        return int(expr.v.getv().idx)
    except Exception:
        pass
    return None


def _disassembly_patterns(func_ea: int, limit: int) -> tuple[list[str], list[dict[str, Any]]]:
    constants = []
    suspicious = []
    seen_constants = set()
    seen_patterns = set()
    mnemonic_map = {
        "xor": "xor_transform",
        "shl": "shift",
        "shr": "shift",
        "sar": "shift",
        "rol": "rotate",
        "ror": "rotate",
        "imul": "multiply",
        "mul": "multiply",
    }
    try:
        for head in idautils.FuncItems(func_ea):
            mnemonic = (idc.print_insn_mnem(head) or "").lower()
            pattern = mnemonic_map.get(mnemonic)
            if pattern and pattern not in seen_patterns:
                seen_patterns.add(pattern)
                suspicious.append({
                    "kind": pattern,
                    "source": "disassembly",
                    "address": _hex(head),
                    "text": _clean(idc.generate_disasm_line(head, 0) or ""),
                })
            for op_index in range(6):
                value = idc.get_operand_value(head, op_index)
                if value and value != idc.BADADDR and value not in seen_constants:
                    seen_constants.add(value)
                    constants.append(_hex(value))
                if len(constants) >= limit:
                    break
            if len(constants) >= limit and len(suspicious) >= limit:
                break
    except Exception:
        pass
    return [item for item in constants if item], suspicious[:limit]


def summarize_ctree(func_ea: int, *, limit: int = 80) -> dict[str, Any]:
    """Return compact decompiler facts for one function.

    This intentionally stays conservative. It records facts the host can use
    for prompts/planning, and reports decompiler/API failures as data.
    """
    limit = max(1, min(int(limit or 80), 500))
    func = ida_funcs.get_func(func_ea)
    if not func:
        return {"ok": False, "address": _hex(func_ea), "error": "no function at address"}
    result: dict[str, Any] = {
        "ok": False,
        "address": _hex(func.start_ea),
        "function": {
            "start": _hex(func.start_ea),
            "end": _hex(func.end_ea),
            "name": idc.get_func_name(func.start_ea) or "",
        },
        "calls": [],
        "assignments": [],
        "returns": [],
        "local_variables": [],
        "constants": [],
        "data_refs": [],
        "suspicious_expressions": [],
    }
    if not HAS_HEXRAYS:
        result["error"] = "Hex-Rays module unavailable"
        return result
    try:
        if not ida_hexrays.init_hexrays_plugin():
            result["error"] = "Hex-Rays plugin is not initialized"
            return result
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            result["error"] = "Hex-Rays decompile returned no cfunc"
            return result
    except Exception as exc:
        result["error"] = "decompile failed: %s" % exc
        return result

    result["local_variables"] = _record_lvars(cfunc, limit)
    try:
        return_type = cfunc.type.get_rettype()
        result["function"]["return_type"] = _clean(return_type.dstr())
        result["function"]["return_type_is_void"] = bool(return_type.is_void())
    except Exception:
        result["function"]["return_type"] = ""
        result["function"]["return_type_is_void"] = None
    lvar_usage: dict[int, dict[str, Any]] = {
        item["index"]: {"use_count": 0, "assignment_count": 0, "use_sites": []}
        for item in result["local_variables"]
    }
    constants, suspicious = _disassembly_patterns(func.start_ea, limit)
    result["constants"].extend(constants)
    result["suspicious_expressions"].extend(suspicious)
    seen_constants = set(constants)

    class Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

        def visit_expr(self, expr):
            op_name = _op_name(expr.op)
            try:
                ea = int(expr.ea)
            except Exception:
                ea = None
            if _op_matches(expr.op, {"cot_var"}):
                index = _var_index(expr)
                if index in lvar_usage:
                    usage = lvar_usage[index]
                    usage["use_count"] += 1
                    if len(usage["use_sites"]) < 12:
                        usage["use_sites"].append(_hex(ea))
            if _op_matches(expr.op, {"cot_call"}) and len(result["calls"]) < limit:
                result["calls"].append({
                    "ea": _hex(ea),
                    "callee": _callee_name(expr.x),
                    "args": _call_args(expr, 8),
                    "text": _expr_text(expr),
                })
            elif _op_matches(expr.op, ASSIGNMENT_OPS) and len(result["assignments"]) < limit:
                lhs_index = _var_index(getattr(expr, "x", None))
                if lhs_index in lvar_usage:
                    lvar_usage[lhs_index]["assignment_count"] += 1
                result["assignments"].append({
                    "ea": _hex(ea),
                    "op": op_name,
                    "lhs": _expr_text(getattr(expr, "x", None)),
                    "rhs": _expr_text(getattr(expr, "y", None)),
                    "text": _expr_text(expr),
                })
            elif _op_matches(expr.op, {"cot_num"}):
                value = _num_value(expr)
                if value is not None:
                    value_hex = _hex(value)
                    if value_hex and value_hex not in seen_constants and len(result["constants"]) < limit:
                        seen_constants.add(value_hex)
                        result["constants"].append(value_hex)
            if _op_matches(expr.op, {"cot_xor", "cot_asgxor", "cot_shl", "cot_shr", "cot_idx"}):
                kind = {
                    "cot_xor": "xor_expression",
                    "cot_asgxor": "xor_assignment",
                    "cot_shl": "shift_expression",
                    "cot_shr": "shift_expression",
                    "cot_idx": "table_lookup",
                }.get(op_name, op_name)
                if len(result["suspicious_expressions"]) < limit:
                    result["suspicious_expressions"].append({
                        "kind": kind,
                        "source": "ctree",
                        "ea": _hex(ea),
                        "text": _expr_text(expr),
                    })
            return 0

        def visit_insn(self, insn):
            if not _op_matches(insn.op, {"cit_return"}):
                return 0
            try:
                ea = int(insn.ea)
            except Exception:
                ea = None
            expression = None
            try:
                expression = insn.creturn.expr
            except Exception:
                pass
            text = _expr_text(expression) if expression is not None else ""
            result["returns"].append({
                "ea": _hex(ea),
                "has_value": bool(text),
                "value": text,
            })
            return 0

    try:
        Visitor().apply_to(cfunc.body, None)
        result["ok"] = True
    except Exception as exc:
        result["error"] = "ctree visit failed: %s" % exc

    refs = []
    try:
        for head in idautils.FuncItems(func.start_ea):
            for ref in idautils.DataRefsFrom(head):
                flags = ida_bytes.get_flags(ref)
                refs.append({
                    "from": _hex(head),
                    "to": _hex(ref),
                    "name": idc.get_name(ref) or "",
                    "is_string": bool(ida_bytes.is_strlit(flags)),
                })
                if len(refs) >= limit:
                    break
            if len(refs) >= limit:
                break
    except Exception:
        pass
    result["data_refs"] = refs
    for lvar in result["local_variables"]:
        usage = lvar_usage.get(lvar["index"]) or {}
        lvar["use_count"] = usage.get("use_count", 0)
        lvar["assignment_count"] = usage.get("assignment_count", 0)
        lvar["use_sites"] = [site for site in usage.get("use_sites", []) if site]
    result["counts"] = {
        "calls": len(result["calls"]),
        "assignments": len(result["assignments"]),
        "returns": len(result["returns"]),
        "value_returns": sum(
            bool(row.get("has_value")) for row in result["returns"]
        ),
        "local_variables": len(result["local_variables"]),
        "constants": len(result["constants"]),
        "data_refs": len(result["data_refs"]),
        "suspicious_expressions": len(result["suspicious_expressions"]),
    }
    return result
