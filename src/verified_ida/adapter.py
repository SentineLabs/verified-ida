"""Transport-neutral dispatch for the model-facing Verified IDA tools."""

from __future__ import annotations

from typing import Any, Mapping

from .model_tools import model_tool_declarations
from .errors import OperationError


READ_ONLY_TOOLS = {
    "read_reversing_log", "describe_ida_capabilities", "survey_idb",
    "query_ida_functions", "query_ida_symbols", "query_ida_strings", "query_ida_types",
    "inspect_ida_function", "read_ida_function_code", "inspect_ida", "inspect_ida_local",
    "describe_idapython_capabilities", "run_idapython_readonly", "inspect_ida_relationship",
    "inspect_ida_operation", "review_ida_frontier", "read_ida_call_flow_scope",
    "read_ida_reconciliation", "list_ida_components", "switch_ida_component",
    "review_analysis_closure",
}


class VerifiedIdaToolAdapter:
    """Bind SDK, MCP, or tests to the same small runtime surface."""

    def __init__(self, runtime: Any, *, read_only: bool = False):
        self.runtime = runtime
        self.read_only = bool(read_only)
        self.schemas = {
            row["name"]: row for row in model_tool_declarations()
            if not self.read_only or row["name"] in READ_ONLY_TOOLS
        }

    def invoke(self, name: str, arguments: Mapping[str, Any] | None = None) -> Any:
        result = self._invoke(name, arguments)
        attach = getattr(self.runtime, "attach_pending_analysis_advisories", None)
        return attach(result) if callable(attach) else result

    def _invoke(self, name: str, arguments: Mapping[str, Any] | None = None) -> Any:
        if self.read_only and name not in READ_ONLY_TOOLS:
            raise OperationError(
                "Read-only adapter cannot dispatch IDB edits.", code="read_only",
                recovery="Report the proposed change as a finding for the investigation writer.",
            )
        if name not in self.schemas:
            raise ValueError("Unknown Verified IDA tool: %s" % name)
        request = dict(arguments or {})
        if name == "read_reversing_log":
            return self.runtime.read_reversing_log(**request)
        if name == "update_reversing_log_section":
            return self.runtime.update_reversing_log_section(**request)
        if name == "append_reversing_log_journal":
            return self.runtime.append_reversing_log_journal(**request)
        if name == "describe_ida_capabilities":
            return self.runtime.describe_ida_capabilities()
        if name == "survey_idb":
            return self.runtime.survey_idb(**request)
        if name == "query_ida_functions":
            filters = {
                key: request.get(key)
                for key in (
                    "segment", "name_class", "name_prefix", "address_start",
                    "address_end", "minimum_size", "maximum_size",
                    "minimum_callers", "minimum_callees", "minimum_xrefs",
                    "has_comment", "has_prototype",
                )
                if request.get(key) is not None
            }
            return self.runtime.query_ida_collection(
                family="functions",
                filters=filters,
                order=request.get("order"),
                limit=request.get("limit", 100),
                cursor=request.get("cursor"),
                component_id=request.get("component_id"),
            )
        if name == "query_ida_symbols":
            filters = {
                key: request.get(key)
                for key in ("kind", "name_prefix", "module", "segment")
                if request.get(key) is not None
            }
            return self.runtime.query_ida_collection(
                family="symbols",
                filters=filters,
                order=request.get("order"),
                limit=request.get("limit", 100),
                cursor=request.get("cursor"),
                component_id=request.get("component_id"),
            )
        if name == "query_ida_strings":
            filters = {
                key: request.get(key)
                for key in ("needle", "segment", "minimum_length", "referenced")
                if request.get(key) is not None
            }
            return self.runtime.query_ida_collection(
                family="strings",
                filters=filters,
                order=request.get("order"),
                limit=request.get("limit", 100),
                cursor=request.get("cursor"),
                component_id=request.get("component_id"),
            )
        if name == "query_ida_types":
            filters = {
                key: request.get(key)
                for key in ("kind", "name_prefix")
                if request.get(key) is not None
            }
            return self.runtime.query_ida_collection(
                family="types",
                filters=filters,
                order=request.get("order"),
                limit=request.get("limit", 100),
                cursor=request.get("cursor"),
                component_id=request.get("component_id"),
            )
        if name == "inspect_ida_function":
            return self.runtime.inspect_ida_function(**request)
        if name == "read_ida_function_code":
            return self.runtime.read_ida_function_code(**request)
        if name == "inspect_ida":
            options = dict(request.get("options") or {})
            if "offset" in request:
                options["offset"] = request["offset"]
            return self.runtime.inspect(
                query=request["query"],
                target=request.get("target"),
                component_id=request.get("component_id"),
                limit=request.get("limit", 120),
                options=options,
            )
        if name == "inspect_ida_local":
            return self.runtime.inspect_local(**request)
        if name == "describe_idapython_capabilities":
            return self.runtime.describe_idapython_capabilities(**request)
        if name == "run_idapython_readonly":
            return self.runtime.run_readonly_idapython(
                source=request["source"],
                parameters=request.get("parameters") or {},
                purpose=request["purpose"],
                capability_gap=request["capability_gap"],
            )
        if name == "inspect_ida_relationship":
            return self.runtime.inspect_relationship(**request)
        if name == "edit_ida":
            return self.runtime.apply_edit(
                target_ref=request["target_ref"],
                kind=request["kind"],
                value=request["value"],
                evidence_refs=request.get("evidence_refs") or [],
                reason=request.get("reason"),
            )
        if name == "inspect_ida_operation":
            return self.runtime.inspect_operation(request["operation_id"])
        if name == "review_ida_frontier":
            return self.runtime.frontier_page(**request)
        if name == "disposition_ida_candidate":
            return self.runtime.disposition_candidate(**request)
        if name == "read_ida_reconciliation":
            return self.runtime.read_reconciliation()
        if name == "open_ida_reconciliation_call_flow":
            return self.runtime.open_reconciliation_call_flow(**request)
        if name == "disposition_ida_reconciliation_finding":
            return self.runtime.disposition_reconciliation_finding(**request)
        if name == "read_ida_call_flow_scope":
            return self.runtime.read_call_flow_scope(**request)
        if name == "disposition_ida_call_flow_node":
            return self.runtime.disposition_call_flow_node(**request)
        if name == "revalidate_ida_function_claim":
            return self.runtime.revalidate_function_claim(
                scope_id=request["scope_id"],
                outcome=request["outcome"],
                parent_evidence_ref=request["parent_evidence_id"],
                rationale=request["rationale"],
                operation_ids=request.get("operation_ids") or [],
            )
        if name == "promote_ida_suggestion":
            return self.runtime.promote_candidate(**request)
        if name == "abandon_ida_operation":
            return self.runtime.abandon_operation(**request)
        if name == "list_ida_components":
            return self.runtime.list_components()
        if name == "recover_ida_component":
            return self.runtime.recover_component(request)
        if name == "write_static_extractor":
            return self.runtime.write_static_extractor(**request)
        if name == "decide_ida_component":
            return self.runtime.decide_component(**request)
        if name == "switch_ida_component":
            return self.runtime.switch_component(
                request["component_id"],
                checkpoint_current=not self.read_only,
                remind=not self.read_only,
            )
        if name == "review_analysis_closure":
            return self.runtime.review_analysis_closure()
        if name == "complete_ida_investigation":
            return self.runtime.complete()
        raise AssertionError("unreachable tool dispatch")
