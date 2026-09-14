# Worked example: applying a recovered type

A recovered structure can make a decompiled function much easier to read. In
this ComRAT investigation, Sol identified an object used during process creation,
saved its layout, and applied it to a function parameter. IDA could then show
which fields the code accessed.

The sequence illustrates the feedback Verified IDA provides between edits:
first confirming that the structure was saved, then reporting where it was
used. The code and tool results below come from a recorded static investigation;
the malware was not executed.

## Finding the field

The function at `0x18002c770` creates a process with its primary thread suspended.
In the clean database, IDA gave it an automatic name and represented its single
parameter as a 64-bit integer:

```c
bool __fastcall sub_18002C770(__int64 a1)
```

Inside the function, `a1` was used as the base address of an object. The clearest
clue was this expression, passed as the final argument to `CreateProcessW`:

```c
(LPPROCESS_INFORMATION)(a1 + 48)
```

That argument tells Windows where to write a `PROCESS_INFORMATION` structure,
containing the new process and thread handles and their IDs. The
[API definition](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)
therefore gives the analyst a concrete starting point: this object contains
process information at byte offset 48 (`0x30`). The surrounding code supplies
an executable path and later checks the returned process handle.

## Saving the structure

Sol followed the object through related construction and cleanup code. Those
uses supplied the rest of the proposed layout: diagnostic state, an executable
path, process information, and an event handle. It submitted this declaration:

```c
struct SuspendedProcessContext
{
  void *diagnostic_context;
  union
  {
    WCHAR inline_image_path[8];
    WCHAR *heap_image_path;
  } image_path_storage;
  unsigned __int64 image_path_length;
  unsigned __int64 image_path_capacity;
  unsigned __int64 unknown_28;
  struct _PROCESS_INFORMATION process_info;
  HANDLE completion_event;
};
```

The `process_info` field sits at the expected offset, `0x30`. The path fields
represent string storage, while `unknown_28` marks a field whose role remained
unresolved. The full layout draws on the object's uses across several functions.

Verified IDA applied the declaration to a candidate database, checked the saved
type, and accepted the edit as revision 1. It returned this feedback:

```json
{
  "type_name": "SuspendedProcessContext",
  "status": "declaration_only_currently",
  "measured_use_count": 0
}
```

The structure now existed in IDA's type library. The feedback found no uses
among the interfaces and other locations it measured; the function parameter
still appeared as an integer. This was an advisory about where the new type
could be applied. The type-creation operation itself had succeeded.

## Applying the type to the function

Sol reinspected the function and requested a prototype change, citing the fresh
inspection and the saved type. The prototype tells IDA how to interpret the
function's parameters and return value. After the edit, it read:

```c
bool __fastcall sub_18002C770(struct SuspendedProcessContext *ctx)
```

The parameter was now a pointer to `SuspendedProcessContext`, named `ctx`.
When Sol requested the decompilation again, the final argument to
`CreateProcessW` appeared as:

```c
&ctx->process_info
```

The raw offset had become a named field. A later access to the returned process
handle also became readable as `p_process_info->hProcess`. The recovered layout
now helped explain the function directly in IDA.

The prototype edit produced revision 2, with updated feedback:

```json
{
  "type_name": "SuspendedProcessContext",
  "status": "applied_on_measured_surfaces",
  "measured_use_count": 1
}
```

The count now included one function prototype using `SuspendedProcessContext`.

## Preserving the change and its history

The host saved and reopened the database in a fresh IDA process. Both the edit
result and its persistence checkpoint reported `verified`.

The ledger connects the two edits—creating the structure and applying it—to
their evidence, database revisions, and verification results. A reviewer can
start with `ctx->process_info` in the decompilation, find the operation that
introduced the type, and inspect the evidence Sol supplied for its layout.

The [recorded trace excerpt](../examples/comrat-type-feedback.json) includes the
full before-and-after decompilations and the tool results for this sequence.
It also records which locations the type-use check measured, so the reported
counts can be interpreted in context.

The useful result is both a clearer function and a record of how it changed.
The [interface specification](standard.md) describes how Verified IDA preserves
that connection throughout an investigation.
