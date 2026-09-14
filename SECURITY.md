# Security

## Where to run it

Use a dedicated Linux analysis machine with IDA and Hex-Rays, following the
[user guide](docs/usage.md#requirements-and-installation). Keep samples and
result projects outside the source checkout. IDBs contain sample bytes and
need the same handling precautions as the original binaries.

## What leaves the machine

The controller sends code excerpts, tool results, and investigation context
to the configured model provider. These can include strings and bytes from
the sample. Approve that transfer before analyzing confidential material.

## Isolation provided out of the box

In the supported Linux configuration, IDA workers run with network access
disabled. Model-authored IDAPython runs against disposable database copies.
Byte-extraction scripts use a restricted sandbox that blocks networking,
process creation, and new file opens.

Samples and recovered executables are not launched as programs. Limited
instruction emulation is available for static analysis. The controller retains
its connection to the model provider, and the analysis host still processes
untrusted files.
