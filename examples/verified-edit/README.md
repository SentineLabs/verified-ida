# Check your installation

This optional check tests the edit-feedback loop with real IDA and a scripted
driver. It needs the
[supported Linux/IDA environment](../../docs/usage.md#requirements-and-installation)
and a C compiler. No model or API key is required. The harmless test program is
compiled for inspection and never executed. For a model-led example, read
[Applying a recovered type](../../docs/worked-example.md).

`specimen_clamp` caps an unsigned value at 512. The driver:

1. Inspects the function and renames it to `ClampRequestedSize`.
2. Receives a verified rename and a missing-behavior-comment item.
3. Inspects the new revision and adds the explanation.
4. Checks that the item closed, then reopens IDA to verify persistence.

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

Find `specimen_clamp` in the `nm` output and supply its address:

```sh
python examples/verified-edit/demonstrate.py \
  --sample /analysis/verified-edit-demo/specimen \
  --clean-idb /analysis/verified-edit-demo/clean.i64 \
  --function 0xYOUR_FUNCTION_ADDRESS \
  --project-dir /analysis/verified-edit-demo/project
```

## Inspect the result

`project/example_result.json` identifies the two operations and checkpoint.
Their evidence and receipts are in `project/verified_ida.sqlite`. Open the IDB
under `project/components/root/` to see the final annotation; the original
`clean.i64` remains unchanged.

The driver exercises the edit-feedback loop only. Use the
[investigation and review commands](../../docs/usage.md) to run a model-led
analysis with a notebook, conversation history, and completion checks.
