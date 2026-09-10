# Using Verified IDA

Start with the [README](../README.md). Use a dedicated static-analysis host,
keep samples and results outside the source checkout, and read the
[security boundary](../SECURITY.md). IDA, its license, and API access are external
requirements. The repository does not contain malware or an IDB.

## Install an extracted package

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

Use an extractor that preserves Unix executable permissions. Python ZIP
extraction does not restore them. The supported installation is editable source,
not a wheel detached from its worker scripts, prompts, and schemas. The pinned
reference dependencies include Agents SDK 0.20.0 and OpenAI 2.54.0; changing the
runner or versions requires new validation.

Supply `OPENAI_API_KEY` through the process environment for a model run. The
controller sends code evidence to the configured provider; network-isolated IDA
does not mean an entirely offline investigation. Assess that data transfer before
processing confidential samples. API availability varies; select a model your
account can access with `--model` rather than assuming the reference model is
available to everyone.

## Input and first investigation

Use the sample and its own clean IDB. The host checks IDA's original loader hash;
a mismatched or missing hash blocks startup. The clean input is copied into a
new project and is not the mutable analysis database.

You can prepare an IDB through IDA's normal analysis or the included no-network
helper. For untrusted samples, do this only on the isolated analysis host:

```sh
scripts/run_ida_script_no_network.sh \
  --log /analysis/output/prepare.log \
  /analysis/input/sample.bin scripts/prepare_analysis.py \
  --save-as /analysis/input/clean.i64
```

The host performs static inspection; it does not launch the sample.

```sh
verified-ida analyze \
  --sample /analysis/input/sample.bin \
  --clean-idb /analysis/input/clean.i64 \
  --project-dir /analysis/output/investigation \
  --model YOUR_AVAILABLE_MODEL
```

The initial packet exposes measured binary metadata and query capabilities.
The model plans its investigation, inspects evidence, applies supported changes,
and maintains the notebook. It chooses its route; there is no required root-first
or exhaustive whole-function traversal in the default profile.

## Resume, budgets, and status

```sh
verified-ida analyze \
  --project-dir /analysis/output/investigation \
  --model YOUR_AVAILABLE_MODEL
```

Keep the original model, reasoning, and profile settings when resuming. Do not
reset usage or edit the SQLite ledger to bypass a completion check.

Use command-specific `--help` to inspect current ceilings. Independent review
has its own aggregate budget, separate from primary investigation: defaults are
250M recorded tokens, 2,500 requests, and four active hours. Its collection,
application and finalization share that allowance. Model-response boundaries
enforce these limits, so an in-flight response can cross a token ceiling. Use an
outer process/job timeout if you require an exact wall-clock cutoff.

Token totals include cached context; they are not a direct measure of internal
reasoning or a price estimate. Budget exhaustion is not completion. A nonzero
exit requires examining `summary.json`; an analytically incomplete review can
exit with code 2 without a crashed worker. Check its findings and mechanical
failure fields rather than interpreting every incomplete result as an outage.

## Independent review

```sh
verified-ida review \
  --source-project-dir /analysis/output/investigation \
  --run-dir /analysis/output/review \
  --model YOUR_AVAILABLE_MODEL
```

This command collects findings on disposable databases, then resumes the saved
investigator in a separate review candidate. Application processes one finding
at a time, preserves decisions and journal updates, and checks persistence.
The original primary databases remain intact.

Resume stopped application without repeating collection:

```sh
verified-ida review \
  --source-project-dir /analysis/output/investigation \
  --run-dir /analysis/output/review \
  --model YOUR_AVAILABLE_MODEL \
  --resume-application
```

Earlier attempts, edits, dispositions, and aggregate usage are retained. For a
legacy pre-a10 review, preserve a snapshot before using
`--import-legacy-baseline`; the host checks the original operation prefix and
frozen source identity rather than guessing a missing baseline.

`finalize-review` retries closure after mechanical issues have been resolved.
`replay-review-wave` is a separate, explicitly budgeted replay experiment.
Neither is a substitute for resuming outstanding findings. Use their `--help`
for required project and artifact inputs.

The experimental `--coverage-reconciliation` analysis option adds a separate
pre-completion, fixed-scope review. It is not enabled merely by using the
independent `review` command. See [the standard](standard.md).

## Read the results

| Output | What to inspect |
| --- | --- |
| `components/<id>/` | Canonical sample copies and annotated databases |
| `verified_ida.sqlite` | Exact operations, receipts, inspections, revisions, failures and decisions |
| `reversing_log.md` | Current understanding, component relationships, uncertainty and journal |
| `observable_tool_trace.jsonl` | Tool requests, results and model-visible messages |
| `walkthrough.md` | Readable observable-event overview, not private reasoning |
| `summary.json` | Status, usage, checkpoints and unresolved work |

Review also retains application plans, per-finding outcomes and prior attempts
beneath its run directory. Keep the whole project when transferring provenance;
an IDB alone does not contain the complete operational history.

Inspect the correct component and final review candidate. A successful mutation
receipt does not certify semantic accuracy, and an accepted review finding does
not establish whole-program completeness.

## Export annotations safely

Stop active writers before exporting a completed packed IDB. Use distinct new
output paths, never the source IDB or existing project files:

```sh
python scripts/export_verified_ida_annotations_safely.py \
  --idb /analysis/output/review/project/components/root/sample.i64 \
  --output /analysis/exports/annotations.json \
  --provenance /analysis/exports/export.json
```

This helper measures semantic state from disposable snapshots before and after
export, checks source byte identity, and records provenance. Failed exports
retain diagnostics rather than replacing an earlier successful export. The
standalone semantic worker uses the same exporter as normal checkpoints.
Like any read/export utility, this is not a semantic judgment of the annotations.

## Build a source archive

```sh
python scripts/package_source.py --output-dir /analysis/packages
```

The package inventory is explicit in `scripts/release_files.json`. The builder
requires a clean Git checkout, includes only those files, preserves launcher
permissions, and generates a per-file manifest plus an archive checksum. A
checksum detects transfer changes; it does not authenticate the publisher.
The archive excludes tests, private research, malware, IDBs and credentials.
