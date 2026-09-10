# A verified name is not yet an explained function

This is a small executable example of the **host contract**, not a model run.
It uses the included harmless C source and real IDA. No API key or malware is
needed, and the compiled program is never executed. It requires the supported
Linux/IDA environment and a C compiler.

The function caps an unsigned value at 512. The example:

1. inspects it and applies `ClampRequestedSize` through the runtime;
2. receives a verified rename plus a missing-behavior-comment work item;
3. inspects the new revision and adds the explanation;
4. checks that the missing-comment item is resolved; and
5. verifies persistence in a fresh IDA process while preserving the clean IDB.

The Python driver chooses the actions deterministically. In an investigation,
the model receives these results through its tools and chooses what to inspect
or correct. This example proves the feedback and persistence path, not that a
model necessarily chooses the right action.

## Run from the repository root

Use a new work directory outside the checkout:

```sh
mkdir -p /analysis/verified-edit-demo
cc -O0 -g -fno-pie -no-pie examples/verified-edit/specimen.c \
  -o /analysis/verified-edit-demo/specimen

export IDA_PATH=/opt/ida-pro-9.3
scripts/run_ida_script_no_network.sh \
  --log /analysis/verified-edit-demo/prepare.log \
  /analysis/verified-edit-demo/specimen scripts/prepare_analysis.py \
  --save-as /analysis/verified-edit-demo/clean.i64

nm -n /analysis/verified-edit-demo/specimen
```

Find `specimen_clamp` in the `nm` output, then pass its actual address with a
`0x` prefix. Do not copy an address from another compiler's build:

```sh
python examples/verified-edit/demonstrate.py \
  --sample /analysis/verified-edit-demo/specimen \
  --clean-idb /analysis/verified-edit-demo/clean.i64 \
  --function 0xYOUR_FUNCTION_ADDRESS \
  --project-dir /analysis/verified-edit-demo/project
```

Read `project/example_result.json` for the two real operation IDs and checkpoint.
`project/verified_ida.sqlite` contains their requests, evidence and receipts.
Open the IDB beneath `project/components/root/` to inspect the final annotation.
The original `clean.i64` remains unchanged.

This intentionally does not call analytical completion: demonstrating two
verified edits is not a complete investigation. The ordinary `analyze` and
`review` commands additionally maintain model conversation, notebook content,
observable traces, and analytical closure.
