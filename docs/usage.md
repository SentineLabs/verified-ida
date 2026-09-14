# User guide

## Requirements and installation

Read [Security](../SECURITY.md) before supplying samples. It explains where to
run the harness, what reaches the model provider, and how workers are isolated.

The supported environment is Linux with Python 3.10 or later, IDA Pro 9.3 with
Hex-Rays, and working `unshare`, `bwrap`, GNU `timeout`, and `libseccomp.so.2`.
The restricted extraction environment requires Linux. You supply the IDA license
and model API access.

Extract the source package with a tool that preserves Unix executable
permissions, such as `unzip`:

```sh
unzip verified-ida-harness-0.2.0a11-source.zip
cd verified-ida-harness-0.2.0a11
test -x scripts/launch_ida_no_network.sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -c constraints.txt -e .
python -m pip check
verified-ida --help
export IDA_PATH=/opt/ida-pro-9.3
```

Keep the editable source installation intact: workers, prompts, and schemas are
runtime dependencies. Installing a wheel without that source tree is unsupported.
The pinned environment uses Agents SDK 0.20.0 and OpenAI 2.54.0; changed SDK or
IDA versions need new validation.

Supply `OPENAI_API_KEY` through the environment and select an accessible model
with `--model`. [.env.example](../.env.example) documents the variables;
the harness does not load `.env` automatically.

### Check your installation

The [scripted installation check](../examples/verified-edit/README.md) exercises
real IDA edits, feedback, and persistence using a harmless C program. It requires
no model or API key.

## Investigate

Start with a sample and its clean IDB. The host checks that IDA's loader-recorded
input hash matches the sample, then copies the inputs into a new project.

Prepare the IDB with IDA or the included no-network helper:

```sh
scripts/run_ida_script_no_network.sh \
  --log /analysis/output/prepare.log \
  /analysis/input/sample.bin scripts/prepare_analysis.py \
  --save-as /analysis/input/clean.i64
```

Start the investigation:

```sh
verified-ida analyze \
  --sample /analysis/input/sample.bin \
  --clean-idb /analysis/input/clean.i64 \
  --project-dir /analysis/output/investigation \
  --model YOUR_AVAILABLE_MODEL
```

The model receives binary metadata and query capabilities, plans its route,
inspects code, and applies supported findings. The default profile lets it
choose which functions and components to pursue. The notebook tracks that work.

To resume, use the same project and retain its model, reasoning, profile, and
budget settings:

```sh
verified-ida analyze \
  --project-dir /analysis/output/investigation \
  --model YOUR_AVAILABLE_MODEL
```

## Review

Independent review is a separate command:

```sh
verified-ida review \
  --source-project-dir /analysis/output/investigation \
  --run-dir /analysis/output/review \
  --model YOUR_AVAILABLE_MODEL
```

The [review sequence](standard.md#independent-review-and-closure) collects
findings on disposable databases and returns them to the saved investigator.
Reviewed IDBs are under `/analysis/output/review/project/`; the primary project
remains intact. Run review explicitly after investigation; `analyze` does not
automatically run this command.

Resume stopped application without repeating collection:

```sh
verified-ida review \
  --source-project-dir /analysis/output/investigation \
  --run-dir /analysis/output/review \
  --model YOUR_AVAILABLE_MODEL \
  --resume-application
```

The saved findings, prior edits, decisions, notebook, and usage are retained.
If application has resolved the required findings but the final completion
checks were interrupted, retry finalization:

```sh
verified-ida finalize-review \
  --run-dir /analysis/output/review \
  --model YOUR_AVAILABLE_MODEL \
  --stage-name finalization-01
```

Use a new stage name for each retry and retain the campaign's model, reasoning,
and budget settings. Finalization checks persistence and agreement between
accepted review conclusions and the annotations. It can return a reported
conflict for a targeted correction; the [specification](standard.md#independent-review-and-closure)
defines that scope. Use `--resume-application` when findings remain open.

### Optional: enforce a selected investigation scope

Add `--coverage-reconciliation` to `analyze` to run an additional review after
provisional completion. It freezes a set of findings and returns them to the
investigator. A selected call-flow gap can require downstream inspection and
revalidation of the parent function before closure.

This experimental policy is disabled by default and persists across resumption.
Its [scope and limits](standard.md#components-and-enforceable-scope) differ from
independent review; it does not require every function to be annotated.

## Budgets and status

Inspect command-specific `--help` before starting a run. Independent review has
a separate aggregate allowance from the primary investigation: 250M recorded
tokens, 2,500 requests, and four active hours by default, shared across review
collection, application, and finalization.

Limits are checked at model-response boundaries; an in-flight response can
cross a token ceiling. Use an outer job timeout for an exact wall-clock cutoff.
Token totals include cached context and should not be read as a price estimate.
Resumption retains recorded usage.

Read `run_summary.json` for a primary investigation and the review directory's
`summary.json` for independent review. Check completion status, unresolved
findings, mechanical failures, and usage. Exit code 2 can indicate an
analytically incomplete review, including one awaiting an unavailable payload.
It does not necessarily indicate a worker crash.

## Inspect and share results

The investigation project contains:

| Output | Contents |
| --- | --- |
| `components/<id>/` | Input copies and annotated IDBs for each binary |
| `verified_ida.sqlite` | Inspections, operations, receipts, checkpoints, and tracked investigation work |
| `model_session.sqlite` | Saved model conversation used for resumption |
| `reversing_log.md` | Current project state and investigation journal |
| `observable_tool_trace.jsonl` | Observable tool requests, results, and messages |
| `walkthrough.md` | Readable account of the recorded events |

Independent review keeps its working copy under `project/`. Its findings,
decisions, and consistency assessments are in
`review/application/dispositions.json`, relative to the review run directory.
That record links to the operation IDs in the copied project's SQLite ledger.
Stage traces, plans, and previous attempts are retained alongside it.

Share the complete investigation or review directory when its history matters.
An IDB contains the annotations but omits the operation ledger, notebook, and
review decisions. Apply the [same handling precautions](../SECURITY.md) to IDBs
as to their input samples.

### Export annotations

Stop active writers and choose new output paths distinct from the source and
existing project files. The working IDB retains the input IDB's filename
(`clean.i64` in this example):

```sh
python scripts/export_verified_ida_annotations_safely.py \
  --idb /analysis/output/review/project/components/root/clean.i64 \
  --output /analysis/exports/annotations.json \
  --provenance /analysis/exports/export.json
```

This helper exports through disposable snapshots, compares semantic state,
checks source byte identity, and records the result. Failed exports retain
diagnostics while preserving earlier successful output.

### Package the source

```sh
python scripts/package_source.py --output-dir /analysis/packages
```

The builder requires a clean Git checkout and uses the explicit inventory in
`scripts/release_files.json`. It preserves launcher permissions and generates
a per-file manifest and archive checksum. The archive contains source and
documentation; samples, results, credentials, and private research stay outside
it. A checksum detects transfer changes but does not authenticate the publisher.
Commit the reviewed source before building an archive; do not use an older ZIP
as a substitute for uncommitted changes. The archive includes the project's
[MIT license](../LICENSE).
